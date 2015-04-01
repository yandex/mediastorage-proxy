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

#include "upload_p.hpp"

namespace elliptics {

upload_simple_t::upload_simple_t(mastermind::namespace_state_t ns_state_, couple_t couple_, std::string filename_)
	: ns_state(std::move(ns_state_))
	, couple(std::move(couple_))
	, couple_id(*std::min_element(couple.begin(), couple.end()))
	, filename(std::move(filename_))
	, key(ns_state.name() + '.' + filename)
	, m_single_chunk(false)
	, deferred_fallback([this] { fallback(); })
{
}

void
upload_simple_t::on_request(const ioremap::thevoid::http_request &http_request) {

	set_chunk_size(server()->m_write_chunk_size);

	auto query_list = http_request.url().query();
	auto offset = get_arg<uint64_t>(query_list, "offset", 0);

	auto self = shared_from_this();
	auto on_complete = [this, self] (const std::error_code &error_code) {
		on_write_is_done(error_code);
	};

	// The method runs in thevoid's io-loop, therefore proxy's dtor cannot run in this moment
	// Hence write_session can be safely used without any check
	writer = std::make_shared<writer_t>(
			ioremap::swarm::logger(logger(), blackhole::log::attributes_t())
			, *server()->write_session(http_request, couple), key
			, *http_request.headers().content_length(), offset
			, server()->timeout_coef.data_flow_rate , proxy_settings(ns_state).success_copies_num
			, on_complete, server()->limit_of_middle_chunk_attempts
			, server()->scale_retry_timeout
			);

	// It's required to call try_next_chunk() method to receive first chunk of data
	try_next_chunk();
}

void
upload_simple_t::on_chunk(const boost::asio::const_buffer &buffer, unsigned int flags) {
	const char *buffer_data = boost::asio::buffer_cast<const char *>(buffer);
	const size_t buffer_size = boost::asio::buffer_size(buffer);

	// Fix flags to single_chunk if first chunk == data size 
	if ((flags & last_chunk) && m_single_chunk && (buffer_size == 0)) {
		MDS_LOG_INFO("on_chunk: skipping empty commit");
		return;
	}

	if ((flags == first_chunk) && (buffer_size == writer->get_total_size())) {
		MDS_LOG_INFO("on_chunk: fixing flags to single_chunk");
		flags = single_chunk;
	}

	if (flags == single_chunk) {
		m_single_chunk = true;
	}

	// There are two parallel activities:
	// 1. Reading client request
	// 2. Writing data into elliptics
	// Errors which could happen in second part are handled by writer object (involving removing of
	// needless file). But errors which could happen during reading request should be handled by
	// this object.
	// When such error is ocurred the on_error method will be called. But chunk writing can process
	// in this moment, so we cannot remove file and need to wait until writing is finished.
	// Otherwise if chunk writing does not process we have to initiate file removing in on_error
	// method.
	// To solve this problem deferred call of fallback method is used. The method will be executed
	// only on second call. The method is deferred by one call before each chunk writing, is called
	// after each chunk writing is finished and is called in on_error.
	deferred_fallback.defer();
	writer->write(buffer_data, buffer_size);
}

// The on_error call means an error occurred during working with socket (either read or write).
// The close method is used as a part of send_headers callback.
// That means on_error will not be called if socket write error occurrs.
// Thus, only socket read error should be handled.
void
upload_simple_t::on_error(const boost::system::error_code &error_code) {
	MDS_LOG_ERROR("error during reading request: %s", error_code.message().c_str());
	deferred_fallback();
}

void
upload_simple_t::on_write_is_done(const std::error_code &error_code) {
	if (error_code) {
		MDS_LOG_ERROR("could not write file into storage: %s"
				, error_code.message().c_str());

		if (error_code == make_error_code(writer_errc::insufficient_storage)) {
			send_reply(507);
		} else {
			send_reply(500);
		}

		return;
	}

	// Fallback will be executed if it is called twice: here and in on_error.
	if (deferred_fallback()) {
		return;
	}

	if (!writer->is_committed()) {
		try_next_chunk();
		return;
	}

	send_result();

	// Release writer to break cyclic links
	writer.reset();
}

void
upload_simple_t::send_result() {
	const auto &result = writer->get_result();

	std::ostringstream oss;
	oss 
		<< "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
		<< "<post obj=\"" << encode_for_xml(result.key)
		<< "\" id=\"" << result.id
		<< "\" groups=\"" << ns_state.settings().groups_count()
		<< "\" size=\"" << result.total_size
		<< "\" key=\"";

	if (proxy_settings(ns_state).static_couple.empty()) {
		oss << couple_id << '/';
	}

	oss << encode_for_xml(filename) << "\">\n";

	const auto &entries_info = result.entries_info;

	for (auto it = entries_info.begin(), end = entries_info.end(); it != end; ++it) {
		oss
			<< "<complete"
			<< " addr=\"" << it->address << "\""
			<< " path=\"" << it->path << "\""
			<< " group=\"" << it->group << "\""
			<< " status=\"0\"/>\n";
	}

	oss
		<< "<written>" << entries_info.size() << "</written>\n"
		<< "</post>";

	auto res_str = oss.str();

	ioremap::thevoid::http_response reply;
	ioremap::swarm::http_headers headers;

	reply.set_code(200);
	headers.set_content_length(res_str.size());
	headers.set_content_type("text/xml");
	reply.set_headers(headers);

	send_headers(std::move(reply)
			, std::bind(&upload_simple_t::headers_are_sent, shared_from_this()
				, res_str, std::placeholders::_1));
}

void
upload_simple_t::headers_are_sent(const std::string &res_str
		, const boost::system::error_code &error_code) {
	if (error_code) {
		MDS_LOG_ERROR("cannot send headers: %s", error_code.message().c_str());
		fallback();
		return;
	}

	MDS_LOG_INFO("headers are sent");

	send_data(std::move(res_str)
			, std::bind(&upload_simple_t::data_is_sent, shared_from_this()
				, std::placeholders::_1));
}

void
upload_simple_t::data_is_sent(const boost::system::error_code &error_code) {
	if (error_code) {
		MDS_LOG_ERROR("cannot send data: %s", error_code.message().c_str());
		fallback();
		return;
	}

	MDS_LOG_INFO("data is sent");

	close(boost::system::error_code());
}

void
upload_simple_t::fallback() {
	close(boost::system::error_code());
	remove();
}

void
upload_simple_t::remove() {
	MDS_LOG_INFO("removing key %s", key.c_str());
	if (auto session = server()->remove_session(request(), couple)) {
		auto future = session->remove(key);
		future.connect(std::bind(&upload_simple_t::on_removed, shared_from_this()
					, std::placeholders::_1, std::placeholders::_2));
	} else {
		MDS_LOG_ERROR("cannot remove files of failed request: remove-session is uninitialized");
	}
}

void
upload_simple_t::on_removed(const ioremap::elliptics::sync_remove_result &result
		, const ioremap::elliptics::error_info &error_info) {
	if (error_info) {
		MDS_LOG_ERROR("cannot remove key %s: %s", key.c_str(), error_info.message().c_str());
	} else {
		MDS_LOG_INFO("key %s was removed", key.c_str());
	}
}

} // namespace elliptics

