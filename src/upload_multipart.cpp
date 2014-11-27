/*
	Mediastorage-proxy is a HTTP proxy for mediastorage based on elliptics
	Copyright (C) 2013-2014 Yandex

	This program is free software; you can redistribute it and/or
	modify it under the terms of the GNU General Public License
	as published by the Free Software Foundation; either version 2
	of the License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include "upload_p.hpp"

namespace elliptics {

/*
	class multipart_context_t {
	public:
		typedef std::vector<char> buffer_t;
		typedef buffer_t::const_iterator const_iterator;

		multipart_context_t()
			: state(multipart_state_tag::init)
			, is_error(false)
			, is_interrupted(false)
		{
			reset();
		}

		const_iterator
		begin() const {
			return iterator;
		}

		const_iterator
		end() const {
			return buffer.end();
		}

		size_t
		size() const {
			return end() - begin();
		}

		void
		append(const char *data, size_t size) {
			buffer.insert(buffer.end(), data, data + size);
			reset();
		}

		void
		skip(size_t size) {
			iterator += size;
		}

		void
		trim() {
			buffer_t buffer_(begin(), end());
			buffer.swap(buffer_);
			reset();
		}

		bool
		interrupt(bool is_error_) {
			is_interrupted = true;
			is_error = is_error_;
		}

		bool
		interrupted() const {
			return is_interrupted;
		}

		bool
		error() const {
			return is_error;
		}

		multipart_state_tag state;

	private:
		void
		reset() {
			iterator = buffer.begin();
			is_interrupted = false;
		}

		buffer_t buffer;
		buffer_t::const_iterator iterator;

		bool need_data;
		bool is_error;
		bool is_stopped;
	} multipart_context;
*/


upload_multipart_t::multipart_context_t::multipart_context_t()
	: state(multipart_state_tag::init)
	, is_error(false)
	, is_interrupted(false)
{
	reset();
}

upload_multipart_t::multipart_context_t::const_iterator
upload_multipart_t::multipart_context_t::begin() const {
	return iterator;
}

upload_multipart_t::multipart_context_t::const_iterator
upload_multipart_t::multipart_context_t::end() const {
	return buffer.end();
}

size_t
upload_multipart_t::multipart_context_t::size() const {
	return end() - begin();
}

void
upload_multipart_t::multipart_context_t::append(const char *data, size_t size) {
	buffer.insert(buffer.end(), data, data + size);
	reset();
}

void
upload_multipart_t::multipart_context_t::skip(size_t size) {
	iterator += size;
}

void
upload_multipart_t::multipart_context_t::trim() {
	buffer_t buffer_(begin(), end());
	buffer.swap(buffer_);
	reset();
}

void
upload_multipart_t::multipart_context_t::interrupt(bool is_error_) {
	is_interrupted = true;
	is_error = is_error_;
}

bool
upload_multipart_t::multipart_context_t::interrupted() const {
	return is_interrupted;
}

bool
upload_multipart_t::multipart_context_t::error() const {
	return is_error;
}

void
upload_multipart_t::multipart_context_t::reset() {
	iterator = buffer.begin();
	is_interrupted = false;
}

upload_multipart_t::upload_multipart_t(namespace_ptr_t ns_, couple_t couple_)
	: ns(std::move(ns_))
	, couple(std::move(couple_))
	, request_is_failed(false)
	, upload_tasks_count(1)
	, is_internal_error(false)
{
}

void
upload_multipart_t::on_headers(ioremap::thevoid::http_request &&http_request_) {
	http_request = std::move(http_request_);

	if (const auto &arg = http_request.headers().content_type()) {
		const auto &type = *arg;
		auto pos = type.find("boundary=");
		if (pos == std::string::npos) {
			MDS_LOG_INFO("boundary is missing");
			send_reply(400);
			return;
		}
		pos += sizeof("boundary=") - 1;
		boundary = std::string("--") + type.substr(pos);
	} else {
		MDS_LOG_INFO("Cannot process request without content-type");
		send_reply(400);
		return;
	}

}

size_t
upload_multipart_t::on_data(const boost::asio::const_buffer &buffer) {
	const char *buffer_data = boost::asio::buffer_cast<const char *>(buffer);
	const size_t buffer_size = boost::asio::buffer_size(buffer);

	multipart_context.append(buffer_data, buffer_size);

	do {
		switch (multipart_context.state) {
		case multipart_state_tag::init:
			sm_init();
			break;
		case multipart_state_tag::headers:
			sm_headers();
			break;
		case multipart_state_tag::body:
			sm_body();
			break;
		case multipart_state_tag::after_body:
			sm_after_body();
			break;
		case multipart_state_tag::end:
			sm_end();
			break;
		}
	} while (!multipart_context.interrupted());

	multipart_context.trim();

	if (multipart_context.error()) {
		on_error();
		return 0;
	}

	return buffer_size;
}

void
upload_multipart_t::sm_init() {
	const std::string BOUNDARY_RN_STRING = boundary + "\r\n";

	if (multipart_context.size() < BOUNDARY_RN_STRING.size()) {
		multipart_context.interrupt(false);
		return;
	}

	if (!std::equal(multipart_context.begin(), multipart_context.begin() + BOUNDARY_RN_STRING.size()
				, BOUNDARY_RN_STRING.begin())) {
		MDS_LOG_INFO("incorrect body: trace 1");
		multipart_context.interrupt(true);
		return;
	}

	multipart_context.state = multipart_state_tag::headers;
	multipart_context.skip(BOUNDARY_RN_STRING.size());
}


void
upload_multipart_t::sm_headers() {
	static const std::string RNRN_STRING = "\r\n\r\n";

	auto headers_end = std::search(multipart_context.begin(), multipart_context.end()
			, RNRN_STRING.begin(), RNRN_STRING.end());

	if (headers_end == multipart_context.end()) {
		multipart_context.interrupt(false);
		return;
	}

	std::string headers(multipart_context.begin(), headers_end);
	multipart_context.skip(headers.size() + RNRN_STRING.size());

	auto CD_pos = headers.find("Content-Disposition");

	if (CD_pos == std::string::npos) {
		MDS_LOG_INFO("incorrect body: trace 2");
		multipart_context.interrupt(true);
		return;
	}

	auto name_pos = headers.find("name=", CD_pos);
	auto return_pos = headers.find("\r\n", CD_pos);

	if (return_pos < name_pos) {
		MDS_LOG_INFO("incorrect body: trace 3");
		multipart_context.interrupt(true);
		return;
	}

	auto name_begin = headers.find('\"', name_pos) + 1;
	auto name_end = headers.find('\"', name_begin + 1);

	if (name_end - name_begin == 1) {
		MDS_LOG_INFO("incorrect body: trace 4");
		multipart_context.interrupt(true);
		return;
	}

	auto name = headers.substr(name_begin, name_end - name_begin);

	{
		auto pos = name.find_first_not_of('/');
		if (pos == std::string::npos) {
			MDS_LOG_INFO("incorrect body: part name consists only of \'/\'");
			multipart_context.interrupt(true);
			return;
		}

		if (pos != 0) {
			MDS_LOG_INFO("cut %d \'/\' from the begin of the name \'%s\'"
					, static_cast<int>(pos), name.c_str());

			name = name.substr(pos);
		}
	}

	current_filename = name;
	upload_buffer = std::make_shared<upload_buffer_t>(
			ioremap::swarm::logger(logger(), blackhole::log::attributes_t())
			, ns->name + '.' + name, server()->m_write_chunk_size
			);

	multipart_context.state = multipart_state_tag::body;
}


void
upload_multipart_t::sm_body() {
	const std::string RN_BOUNDARY_STRING = "\r\n" + boundary;

	if (multipart_context.size() < RN_BOUNDARY_STRING.size() + 1) {
		multipart_context.interrupt(false);
		return;
	}

	bool boundary_found = true;

	auto boundary_it = std::search(multipart_context.begin(), multipart_context.end()
			, RN_BOUNDARY_STRING.begin(), RN_BOUNDARY_STRING.end());

	if (boundary_it == multipart_context.end()) {
		boundary_it = multipart_context.begin() +
			(multipart_context.size() - RN_BOUNDARY_STRING.size());

		boundary_found = false;
	}

	auto size = boundary_it - multipart_context.begin();
	upload_buffer->append(&*multipart_context.begin(), size);
	multipart_context.skip(size);

	if (boundary_found) {
		multipart_context.skip(RN_BOUNDARY_STRING.size());
		multipart_context.state = multipart_state_tag::after_body;

		start_writing();
	} else {
		multipart_context.interrupt(false);
	}
}


void
upload_multipart_t::sm_after_body() {
	static const std::string MINUS_PREFIX_STRING = "--";
	static const std::string RN_STRING = "\r\n";

	if (multipart_context.size() < 2) {
		multipart_context.interrupt(false);
		return;
	}

	if (!std::equal(multipart_context.begin()
			, multipart_context.begin() + MINUS_PREFIX_STRING.size()
			, MINUS_PREFIX_STRING.begin())) {
		if (!std::equal(multipart_context.begin()
				, multipart_context.begin() + RN_STRING.size()
				, RN_STRING.begin())) {
			MDS_LOG_INFO("incorrect body: trace 5");
			multipart_context.interrupt(true);
			return;
		} else {
			multipart_context.state = multipart_state_tag::headers;
			multipart_context.skip(RN_STRING.size());
			return;
		}
	}

	multipart_context.state = multipart_state_tag::end;
}


void
upload_multipart_t::sm_end() {
	multipart_context.interrupt(false);
	send_result();
}

void
upload_multipart_t::start_writing() {
	++upload_tasks_count;

	std::lock_guard<std::mutex> lock(mutex);
	(void) lock;

	if (request_is_failed) {
		multipart_context.interrupt(true);
		return;
	}

	upload_buffers.push_back(std::make_tuple(upload_buffer, current_filename));
	// The method runs in thevoid's io-loop, therefore proxy's dtor cannot run in this moment
	// Hence write_session can be safely used without any check
	upload_buffer->write(*server()->write_session(http_request, couple)
			, server()->timeout_coef.data_flow_rate, ns->success_copies_num
			, std::bind(&upload_multipart_t::on_finished
				, shared_from_this(), std::placeholders::_1)
			, std::bind(&upload_multipart_t::on_internal_error, shared_from_this()));
}

void
upload_multipart_t::on_close(const boost::system::error_code &error) {
	if (error) {
		on_internal_error();
	}
}

void
upload_multipart_t::on_finished(const std::shared_ptr<upload_helper_t> &upload_helper) {
	(void) upload_helper;

	send_result();
}

void
upload_multipart_t::on_internal_error() {
	is_internal_error = true;
	on_error();
}

void
upload_multipart_t::on_error() {
	{
		std::lock_guard<std::mutex> lock(mutex);
		(void) lock;

		if (!request_is_failed) {
			request_is_failed = true;

			MDS_LOG_INFO("request is failed");

			MDS_LOG_INFO("stoping uploads");
			for (auto it = upload_buffers.begin(), end = upload_buffers.end(); it != end; ++it) {
				std::get<0>(*it)->stop();
			}
		}

	}

	send_result();
}

void
upload_multipart_t::send_result() {
	if (--upload_tasks_count != 0) {
		return;
	}

	bool request_is_failed_ = false;

	{
		std::lock_guard<std::mutex> lock(mutex);
		(void) lock;

		request_is_failed_ = request_is_failed;
	}

	if (request_is_failed_) {
		remove_tasks_count = upload_buffers.size() + 1;

		if (auto session = server()->remove_session(http_request, couple)) {
			MDS_LOG_INFO("removing uploaded files");
			for (auto it = upload_buffers.begin(), end = upload_buffers.end(); it != end; ++it) {
				auto key = std::get<0>(*it)->upload_helper->key;

				MDS_LOG_INFO("remove %s", key.remote().c_str());
				auto future = session->clone().remove(key);

				future.connect(std::bind(&upload_multipart_t::on_removed, shared_from_this()
							, key.remote(), std::placeholders::_1, std::placeholders::_2));
			}

			send_error();
		} else {
			MDS_LOG_ERROR("cannot remove files of failed request: remove-session is uninitialized");
		}

		return;
	}

	MDS_LOG_INFO("send result");

	std::ostringstream oss;

	oss << "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";

	oss
		<< "<multipart-post couple_id=\""
		<< *std::min_element(couple.begin(), couple.end()) << "\">\n";

	for (auto it = upload_buffers.begin(), end = upload_buffers.end(); it != end; ++it) {

		const auto &upload_helper = std::get<0>(*it)->upload_helper;
		oss
			<< " <post obj=\"" << upload_helper->key.remote()
			<< "\" id=\"" << upload_helper->key.to_string()
			<< "\" groups=\"" << ns->groups_count
			<< "\" size=\"" << upload_helper->total_size
			<< "\" key=\"";

		if (ns->static_couple.empty()) {
			const auto &groups = upload_helper->session.get_groups();
			auto git = std::min_element(groups.begin(), groups.end());
			oss << *git << '/';
		}

		oss << std::get<1>(*it) << "\">\n";

		const auto &upload_result = upload_helper->upload_result();

		for (auto it = upload_result.begin(), end = upload_result.end(); it != end; ++it) {
			oss
				<< "  <complete"
				<< " addr=\"" << it->address << "\""
				<< " path=\"" << it->path << "\""
				<< " group=\"" << it->group << "\""
				<< " status=\"0\"/>\n";
		}

		oss
			<< "  <written>" << upload_result.size() << "</written>\n"
			<< " </post>\n";
	}

	oss << "</multipart-post>";

	auto res_str = oss.str();

	ioremap::thevoid::http_response reply;
	ioremap::swarm::http_headers headers;

	reply.set_code(200);
	headers.set_content_length(res_str.size());
	headers.set_content_type("text/xml");
	reply.set_headers(headers);

	send_reply(std::move(reply), std::move(res_str));
}

void
upload_multipart_t::on_removed(const std::string &key
		, const ioremap::elliptics::sync_remove_result &result
		, const ioremap::elliptics::error_info &error_info) {
	if (error_info) {
		MDS_LOG_ERROR("cannot remove file \"%s\"", key.c_str());
	} else {
		MDS_LOG_INFO("File \"%s\" was removed", key.c_str());
	}

	send_error();
}

void
upload_multipart_t::send_error() {
	if (--remove_tasks_count != 0) {
		return;
	}

	MDS_LOG_INFO("send error");
	send_reply(is_internal_error ? 500 : 400);
}

} // namespace elliptics

