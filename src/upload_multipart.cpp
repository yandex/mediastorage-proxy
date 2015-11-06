/*
	Mediastorage-proxy is a HTTP proxy for mediastorage based on elliptics
	Copyright (C) 2013-2015 Yandex

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

#include "upload_multipart.hpp"

namespace elliptics {

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

upload_multipart_t::upload_multipart_t(mastermind::namespace_state_t ns_state_, couple_t couple_)
	: interrupt_writers_once([this] { interrupt_writers(); })
	, join_upload_tasks([this] { on_writers_are_finished(); })
	, join_remove_tasks([this] { send_error(); })
	, error_type(error_type_tag::none)
	, ns_state(std::move(ns_state_))
	, couple(std::move(couple_))
	, couple_id(*std::min_element(couple.begin(), couple.end()))
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
			reply()->send_error(ioremap::swarm::http_response::bad_request);
			return;
		}
		pos += sizeof("boundary=") - 1;
		boundary = std::string("--") + type.substr(pos);
	} else {
		MDS_LOG_INFO("Cannot process request without content-type");
		reply()->send_error(ioremap::swarm::http_response::bad_request);
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

	{
		if (multipart_context.error()) {
			interrupt_writers(error_type_tag::multipart);
		}

		// If multipart_context.state is equal to end, the join was already called in this task.
		if (is_error() && multipart_state_tag::end != multipart_context.state) {
			buffered_writer.reset();
			join_upload_tasks();
			return 0;
		}
	}


	multipart_context.trim();

	return buffer_size;
}

void
upload_multipart_t::on_close(const boost::system::error_code &error) {
	if (error) {
		interrupt_writers(error_type_tag::client);
		// Multipart parser is not finished if reading request error is ocurred.
		// That means on_data will not be called anymore and we need to join parser task here.
		join_upload_tasks();
	}
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
	auto name_end = headers.find('\"', name_begin);

	if (name_end - name_begin == 0) {
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

	buffered_writer = std::make_shared<buffered_writer_t>(
			ioremap::swarm::logger(logger(), blackhole::log::attributes_t())
			, ns_state.name() + '.' + name, server()->m_write_chunk_size);

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
	buffered_writer->append(&*multipart_context.begin(), size);
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
	join_upload_tasks();
}

void
upload_multipart_t::start_writing() {
	{
		std::lock_guard<std::mutex> lock(buffered_writers_mutex);
		(void) lock;

		if (is_error()) {
			multipart_context.interrupt(false);
			return;
		}

		join_upload_tasks.defer();

		buffered_writers.insert(std::make_pair(current_filename, buffered_writer));
	}

	auto self = shared_from_this();
	auto next = [this, self] (const std::error_code &error_code) {
		on_writer_is_finished(error_code);
	};

	// The method runs in thevoid's io-loop, therefore proxy's dtor cannot run in this moment
	// Hence write_session can be safely used without any check
	buffered_writer->write(*server()->write_session(http_request, couple)
			, server()->timeout_coef.data_flow_rate
			, ns_settings(ns_state).success_copies_num
			, server()->limit_of_middle_chunk_attempts
			, server()->scale_retry_timeout
			, std::move(next));

	buffered_writer.reset();
}

void
upload_multipart_t::on_writer_is_finished(const std::error_code &error_code) {
	if (error_code) {
		const auto interrupted_error = make_error_code(buffered_writer_errc::interrupted);

		if (error_code != interrupted_error) {
			if (error_code == make_error_code(writer_errc::insufficient_storage)) {
				interrupt_writers(error_type_tag::insufficient_storage);
			} else {
				interrupt_writers(error_type_tag::internal);
			}
		}
	}

	join_upload_tasks();
}

void
upload_multipart_t::set_error(error_type_tag e) {
	if (error_type_tag::none == e) {
		throw std::runtime_error("unexpected error type");
	}

	std::lock_guard<std::mutex> lock_guard(error_type_mutex);
	(void) lock_guard;

	// Errors have priorities:
	// 1. Client error means there is no reason to send response
	// 2. Insufficient Storage error means we should send 507
	// 3. Internal error means we should send 500
	// 4. Multipart error means we should send 400
	switch (error_type) {
	case error_type_tag::none:
		error_type = e;
		break;
	case error_type_tag::insufficient_storage:
		if (error_type_tag::client == e) {
			error_type = e;
		}
		break;
	case error_type_tag::internal:
		if (error_type_tag::client == e || error_type_tag::insufficient_storage == e) {
			error_type = e;
		}
		break;
	case error_type_tag::multipart:
		error_type = e;
		break;
	case error_type_tag::client:
		// nothing to do
		break;
	}
}

bool
upload_multipart_t::is_error() {
	return error_type_tag::none != get_error();
}

upload_multipart_t::error_type_tag
upload_multipart_t::get_error() {
	std::lock_guard<std::mutex> lock_guard(error_type_mutex);
	(void) lock_guard;

	return error_type;
}

void
upload_multipart_t::interrupt_writers(error_type_tag e) {
	set_error(e);
	interrupt_writers_once();
}

void
upload_multipart_t::interrupt_writers() {
	std::lock_guard<std::mutex> lock_guard(buffered_writers_mutex);
	(void) lock_guard;

	MDS_LOG_INFO("interrupt writers");
	for (auto it = buffered_writers.begin(), end = buffered_writers.end(); it != end; ++it) {
		it->second->interrupt();
	}
}

void
upload_multipart_t::on_writers_are_finished() {
	for (auto it = buffered_writers.begin(), end = buffered_writers.end(); it != end; ++it) {
		results.insert(std::make_pair(it->first, it->second->get_result()));
	}

	buffered_writers.clear();

	if (is_error()) {
		remove_files();
		return;
	}

	send_result();
}

void
upload_multipart_t::send_result() {
	MDS_LOG_INFO("send result");

	std::ostringstream oss;

	oss << "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";

	oss
		<< "<multipart-post couple_id=\""
		<< *std::min_element(couple.begin(), couple.end()) << "\">\n";

	for (auto it = results.begin(), end = results.end(); it != end; ++it) {

		oss
			<< " <post obj=\"" << encode_for_xml(it->second.key)
			<< "\" id=\"" << it->second.id
			<< "\" groups=\"" << ns_state.settings().groups_count()
			<< "\" size=\"" << it->second.total_size
			<< "\" key=\"";

		if (ns_settings(ns_state).static_couple.empty()) {
			oss << couple_id << '/';
		}

		oss << encode_for_xml(it->first) << "\">\n";

		const auto &entries_info = it->second.entries_info;

		for (auto it = entries_info.begin(), end = entries_info.end(); it != end; ++it) {
			oss
				<< "  <complete"
				<< " addr=\"" << it->address << "\""
				<< " path=\"" << it->path << "\""
				<< " group=\"" << it->group << "\""
				<< " status=\"0\"/>\n";
		}

		oss
			<< "  <written>" << entries_info.size() << "</written>\n"
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

	send_headers(std::move(reply)
			, std::bind(&upload_multipart_t::headers_are_sent, shared_from_this()
				, res_str, std::placeholders::_1));
}

void
upload_multipart_t::headers_are_sent(const std::string &res_str
		, const boost::system::error_code &error_code) {
	if (error_code) {
		MDS_LOG_ERROR("cannot send headers: %s", error_code.message().c_str());
		set_error(error_type_tag::client);
		remove_files();
		return;
	}

	MDS_LOG_INFO("headers are sent");

	send_data(std::move(res_str)
			, std::bind(&upload_multipart_t::data_is_sent, shared_from_this()
				, std::placeholders::_1));
}

void
upload_multipart_t::data_is_sent(const boost::system::error_code &error_code) {
	if (error_code) {
		MDS_LOG_ERROR("cannot send data: %s", error_code.message().c_str());
		set_error(error_type_tag::client);
		remove_files();
		return;
	}

	MDS_LOG_INFO("data is sent");

	close(boost::system::error_code());
}

void
upload_multipart_t::remove_files() {
	if (auto session = server()->remove_session(http_request, couple)) {
		MDS_LOG_INFO("removing uploaded files");

		auto shared_logger = make_shared_logger(logger());
		auto next = std::bind(&upload_multipart_t::on_removed, shared_from_this()
				, std::placeholders::_1);

		for (auto it = results.begin(), end = results.end(); it != end; ++it) {
			join_remove_tasks.defer();
			elliptics::remove(shared_logger, *session, it->second.key, next);
		}

		join_remove_tasks();
	} else {
		MDS_LOG_ERROR("cannot remove files of failed request: remove-session is uninitialized");
	}
}

void
upload_multipart_t::on_removed(util::expected<remove_result_t> result) {
	// The remove result does not affect handler's flow
	(void) result;

	join_remove_tasks();
}

void
upload_multipart_t::send_error() {
	auto err = get_error();

	MDS_LOG_INFO("send error: %s", static_cast<int>(err));

	switch (get_error()) {
	case error_type_tag::none:
		throw std::runtime_error("unexpected error type: none");
	case error_type_tag::insufficient_storage:
		reply()->send_error(ioremap::swarm::http_response::insufficient_storage);
		break;
	case error_type_tag::internal:
		reply()->send_error(ioremap::swarm::http_response::internal_server_error);
		break;
	case error_type_tag::multipart:
		reply()->send_error(ioremap::swarm::http_response::bad_request);
		break;
	case error_type_tag::client:
		close(boost::system::error_code());
		break;
	default:
		throw std::runtime_error("unexpected error type: "
				+ boost::lexical_cast<std::string>(static_cast<int>(err)));
	}
}

} // namespace elliptics

