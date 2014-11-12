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

#include "get.hpp"

#include "ranges.hpp"
#include "data_container.hpp"
#include "utils.hpp"

#include <swarm/url.hpp>

#include <crypto++/md5.h>

#include <boost/asio/buffer.hpp>

#include <functional>
#include <chrono>
#include <ctime>

namespace elliptics {

class get_helper_t
	: public std::enable_shared_from_this<get_helper_t>
{
public:
	enum class chunk_type_tag {
		first, middle, last, single
	};

	typedef std::function<void (const std::shared_ptr<get_helper_t> &)> result_callback_t;
	typedef std::function<void (void)> error_callback_t;

	get_helper_t(ioremap::swarm::logger bh_logger_
			, std::string key_, size_t offset_, size_t size_, size_t chunk_size_)
		: bh_logger(std::move(bh_logger_))
		, key(std::move(key_))
		, offset(offset_)
		, size(size_)
		, chunk_size(chunk_size_)
		, read_size(0)
	{
		std::ostringstream oss;
		oss
			<< "start reading:"
			<< " key=" << key.remote()
			<< " offset=" << offset
			<< " size=" << size
			<< " chunk-size=" << chunk_size;
		auto msg = oss.str();
		MDS_LOG_INFO("%s", msg.c_str());
	}

	void
	read(ioremap::elliptics::session session // We need to pass session in each call
			// to be able to change timeout and ioflags settings to avoid problems with
			// checksum computing
			, result_callback_t result_callback, error_callback_t error_callback) {
		auto current_size = std::min(chunk_size, size);

		{
			std::ostringstream oss;
			oss
				<< "get chunk:"
				<< " key=" << key.remote()
				<< " groups=" << session.get_groups()
				<< " chunk-size=" << current_size
				<< " offset=" << offset
				<< " data-left=" << (size - offset);

			auto msg = oss.str();

			MDS_LOG_INFO("%s", msg.c_str());
		}

		auto future = session.read_data(key, offset, current_size);
		offset += current_size;
		size -= current_size;

		future.connect(std::bind(&get_helper_t::on_read_data, shared_from_this()
					, std::placeholders::_1, std::placeholders::_2
					, std::chrono::system_clock::now()
					, std::move(result_callback), std::move(error_callback)));
	}

	boost::asio::const_buffer
	const_buffer() const {
		return boost::asio::const_buffer(data_pointer.data(), data_pointer.size());
	}

	dnet_time
	timestamp() const {
		return data_timestamp;
	}

	chunk_type_tag
	chunk() const {
		return chunk_type;
	}

private:
	ioremap::swarm::logger &
	logger() {
		return bh_logger;
	}

	void
	on_read_data(const ioremap::elliptics::sync_read_result &result
			, const ioremap::elliptics::error_info &error_info
			, std::chrono::system_clock::time_point start_time_point
			, result_callback_t result_callback, error_callback_t error_callback) {

#define LOG_RESULT(VERBOSITY, STATUS) \
		do { \
			auto spent_time = std::chrono::duration_cast<std::chrono::milliseconds>( \
					std::chrono::system_clock::now() - start_time_point \
					).count(); \
			 \
			std::ostringstream oss; \
			oss \
				<< "get is finished:" \
				<< " key=" << key.remote() \
				<< " spent-time=" << spent_time << "ms" \
				<< " status=" << STATUS \
				<< " chunk-type="; \
			 \
			switch (chunk_type) { \
			case chunk_type_tag::first: \
				oss << "first"; \
				break; \
			case chunk_type_tag::middle: \
				oss << "middle"; \
				break; \
			case chunk_type_tag::last: \
				oss << "last"; \
				break; \
			case chunk_type_tag::single: \
				oss << "single"; \
				break; \
			} \
			 \
			auto msg = oss.str(); \
			MDS_LOG_##VERBOSITY("%s", msg.c_str()); \
		} while (false)

		chunk_type = chunk_type_tag::middle;

		if (read_size == 0) {
			chunk_type = chunk_type_tag::first;
		}

		if (size == 0) {
			if (chunk_type == chunk_type_tag::first) {
				chunk_type = chunk_type_tag::single;
			} else {
				chunk_type = chunk_type_tag::last;
			}
		}

		if (error_info) {
			LOG_RESULT(ERROR, "bad");
			MDS_LOG_ERROR("%s", error_info.message().c_str());
			error_callback();
			return;
		}

		data_pointer = result.front().file();
		data_timestamp = result.front().io_attribute()->timestamp;

		read_size += data_pointer.size();

		LOG_RESULT(INFO, "ok");

#undef LOG_RESULT

		result_callback(shared_from_this());
	}

	ioremap::swarm::logger bh_logger;

	ioremap::elliptics::key key;

	size_t offset;
	size_t size;
	size_t chunk_size;
	size_t read_size;

	ioremap::elliptics::data_pointer data_pointer;
	dnet_time data_timestamp;
	chunk_type_tag chunk_type;
};

void req_get::on_request(const ioremap::thevoid::http_request &http_request
		, const boost::asio::const_buffer &buffer) {
	MDS_LOG_INFO("Get: handle request");

	if (http_request.method() != "HEAD" && http_request.method() != "GET") {
		MDS_LOG_INFO("Unsupported http method\'s type: \"%s\"", http_request.method().c_str());
		send_reply(400);
		return;
	}

	try {
		ns = server()->get_namespace(http_request.url().path(), "/get");
		auto &&prep_session = server()->prepare_session(http_request.url().path(), ns);
		m_session = prep_session.first;
		m_session->set_trace_bit(http_request.trace_bit());
		m_session->set_trace_id(http_request.request_id());
		m_session->set_timeout(server()->timeout.read);
		key = prep_session.second.remote();
	} catch (const std::exception &ex) {
		MDS_LOG_ERROR("Get: \"%s\"", ex.what());
		send_reply(400);
		return;
	}

	if (!server()->check_basic_auth(ns->name, ns->auth_key_for_read
				, http_request.headers().get("Authorization"))) {
		auto token = server()->get_auth_token(http_request.headers().get("Authorization"));
		MDS_LOG_INFO("invalid token \"%s\"", token.empty() ? "<none>" : token.c_str());

		ioremap::thevoid::http_response reply;
		ioremap::swarm::http_headers headers;

		reply.set_code(401);
		headers.add("WWW-Authenticate", std::string("Basic realm=\"") + ns->name + "\"");
		headers.add("Content-Length", "0");
		reply.set_headers(headers);
		send_reply(std::move(reply));

		return;
	}

	if (m_session->get_groups().empty()) {
		MDS_LOG_INFO("Get: cannot find couple of groups for the request");
		send_reply(404);
		return;
	}

	m_first_chunk = true;

	{
		std::ostringstream oss;
		oss << "Get: lookup from groups " << m_session->get_groups();
		auto msg = oss.str();
		MDS_LOG_INFO("%s", msg.c_str());
	}
	{
		auto ioflags = m_session->get_ioflags();
		m_session->set_ioflags(ioflags | DNET_IO_FLAGS_NOCSUM);
		m_session->set_timeout(server()->timeout.lookup);
		m_session->set_filter(ioremap::elliptics::filters::all);
		auto alr = m_session->quorum_lookup(key);
		alr.connect(wrap(std::bind(&req_get::on_lookup, shared_from_this(),
					std::placeholders::_1, std::placeholders::_2)));
		m_session->set_ioflags(ioflags);
	}
}

void req_get::on_lookup(const ioremap::elliptics::sync_lookup_result &slr, const ioremap::elliptics::error_info &error) {
	if (error) {
		if (error.code() == -ENOENT) {
			MDS_LOG_INFO("Get: file not found");
			send_reply(404);
		} else {
			MDS_LOG_ERROR("Get: %s", error.message().c_str());
			send_reply(500);
		}
		return;
	}

	uint64_t tsec = 0;

	{
		std::vector<int> groups;
		for (auto it = slr.begin(), end = slr.end(); it != end; ++it) {
			auto group_id = it->command()->id.group_id;

			switch (it->status())
			{
			case 0:
				groups.push_back(group_id);
				total_size = it->file_info()->size;
				tsec = it->file_info()->mtime.tsec;
				break;
			case -ENOENT:
			case -EBADFD:
			case -EILSEQ:
				bad_groups.push_back(group_id);
			}
		}
		m_session->set_groups(groups);
	}

	auto res = process_precondition_headers(tsec, total_size);

	if (std::get<0>(res)) {
		return;
	}

	if (try_to_redirect_request(slr, total_size, std::get<1>(res))) {
		return;
	}

	start_reading(total_size, std::get<1>(res));
}

std::string generate_etag(uint64_t timestamp, uint64_t size) {
	using namespace CryptoPP;

	MD5 hash;

	hash.Update((const byte *)&timestamp, sizeof(uint64_t));
	hash.Update((const byte *)&size, sizeof(uint64_t));

	std::vector<byte> result(hash.DigestSize());
	hash.Final(result.data());

	std::ostringstream oss;
	oss << std::hex;
	oss << "\"";
	for (auto it = result.begin(), end = result.end(); it != end; ++it) {
		oss << std::setfill('0') << std::setw(2) << static_cast<int>(*it);
	}
	oss << "\"";

	return oss.str();
}

std::string make_content_range_header(size_t offset, size_t size, size_t total_size) {
	std::ostringstream oss;
	oss << "bytes " << offset << '-' << size + offset - 1 << '/' << total_size;
	return oss.str();
}

std::string make_boundary() {
	char boundary_buf[17] = {0};
	for (size_t i = 0; i < 2; ++i) {
		uint32_t tmp = rand();
		sprintf(boundary_buf + i * 8, "%08X", tmp);
	}
	return boundary_buf;
}

std::tuple<bool, bool> req_get::process_precondition_headers(const time_t timestamp, const size_t size) {
	const auto &headers = request().headers();

	bool if_prospect_304 = true;
	bool has_304_headers = false;
	bool if_range = false;

	bool send_whole_file = false;

	struct tm modified_time;
	gmtime_r(&timestamp, &modified_time);

	std::string etag = generate_etag(timestamp, size);

	auto range_header = headers.get("Range");

#define MAKE_TIME_TUPLE(T) std::make_tuple( \
		(T).tm_year, (T).tm_mon, (T).tm_mday, \
		(T).tm_hour, (T).tm_min, (T).tm_sec)

	if (range_header) {
		if (auto if_range_header = headers.get("If-Range")) {
			if ((*if_range_header)[0] == '\"') {
				if (*if_range_header == etag) {
					if_range = true;
				} else {
					send_whole_file = true;
				}
			} else {
				const auto &str = *if_range_header;

				struct tm tm_condition;
				strptime(str.c_str(), "%a, %d %b %Y %H:%M:%S %Z", &tm_condition);

				if (MAKE_TIME_TUPLE(modified_time) == MAKE_TIME_TUPLE(tm_condition)) {
					if_range = true;
				} else {
					send_whole_file = true;
				}
			}
		}
	}

	if (auto if_match_header = headers.get("If-Match")) {
		if (*if_match_header != etag) {
			if (if_range) {
				send_whole_file = true;
			} else {
				send_reply(412);
				return std::make_tuple(true, false);
			}
		}
	}

	if (auto if_none_match_header = headers.get("If-None-Match")) {
		has_304_headers = true;
		if (*if_none_match_header != etag) {
			if_prospect_304 = false;
		}
	}

	if (auto if_unmodified_since_header = headers.get("If-Unmodified-Since")) {
		const auto &str = *if_unmodified_since_header;

		struct tm tm_condition;
		strptime(str.c_str(), "%a, %d %b %Y %H:%M:%S %Z", &tm_condition);

		if (MAKE_TIME_TUPLE(modified_time) > MAKE_TIME_TUPLE(tm_condition)) {
			if (if_range) {
				send_whole_file = true;
			} else {
				send_reply(412);
				return std::make_tuple(true, false);
			}
		}
	}

	if (auto if_modified_since_header = headers.get("If-Modified-Since")) {
		has_304_headers = true;
		const auto &str = *if_modified_since_header;

		struct tm tm_condition;
		strptime(str.c_str(), "%a, %d %b %Y %H:%M:%S %Z", &tm_condition);

		if (MAKE_TIME_TUPLE(modified_time) > MAKE_TIME_TUPLE(tm_condition)) {
			if_prospect_304 = false;
		}
	}

#undef MAKE_TIME_TUPLE

	if (has_304_headers && if_prospect_304) {
		send_reply(304);
		return std::make_tuple(true, false);
	}

	prospect_http_response.set_code(200);
	prospect_http_response.headers().set_last_modified(timestamp);
	prospect_http_response.headers().set("ETag", etag);

	if (request().method() == "HEAD") {
		prospect_http_response.headers().set_content_length(size);
		send_reply(std::move(prospect_http_response));
		return std::make_tuple(true, false);
	}

	return std::make_tuple(false, send_whole_file);
}

bool req_get::try_to_redirect_request(const ioremap::elliptics::sync_lookup_result &slr
		, const size_t size, bool send_whole_file) {

	{
		const auto &headers = request().headers();
		auto range_header = headers.get("Range");

		if (!send_whole_file && range_header) {
			return false;
		}
	}

	if (ns->redirect_content_length_threshold > size) {
		return false;
	}

	const auto &headers = request().headers();

	try {
		if (ns->sign_token.empty()) {
			MDS_LOG_INFO("cannot redirect without signature-token");
			return false;
		}

		auto res = server()->generate_signature_for_elliptics_file(slr
				, headers.get("X-Regional-Host").get_value_or(""), ns);

		std::stringstream oss;
		oss
			<< "//" << std::get<0>(res) << std::get<1>(res) << "?ts="
			<< std::get<2>(res) << "&s=" << std::get<3>(res);

		ioremap::thevoid::http_response http_response;
		http_response.set_code(302);
		http_response.headers().set_content_length(0);
		http_response.headers().set("Location", oss.str());

		send_reply(std::move(http_response));

		return true;
	} catch (const std::exception &ex) {
		MDS_LOG_ERROR("cannot generate signature: %s", ex.what());
		return false;
	}
}

void req_get::start_reading(const size_t size, bool send_whole_file) {
	const auto &headers = request().headers();
	auto range_header = headers.get("Range");

	if (send_whole_file || !range_header) {
		prospect_http_response.headers().set_content_length(size);

		auto get_helper = make_get_helper(0, size);

		callback_t tmp = std::bind(&req_get::on_read_is_done, shared_from_this());
		get_helper->read(get_session(), std::bind(&req_get::on_simple_read, shared_from_this()
					, std::placeholders::_1, std::move(tmp))
				, std::bind(&req_get::on_error, shared_from_this()));
	} else if (auto ranges = parse_range_header(*range_header, size)) {
		prospect_http_response.set_code(206);
		prospect_http_response.headers().set("Accept-Ranges", "bytes");

		if (ranges->size() == 1) {
			const auto &range = ranges->front();

			prospect_http_response.headers().set_content_type("application/octet-stream");
			prospect_http_response.headers().set_content_length(range.size);
			prospect_http_response.headers().set("Content-Range"
					, make_content_range_header(range.offset, range.size, size));

			send_headers(std::move(prospect_http_response)
					, std::function<void (const boost::system::error_code &)>());

			auto get_helper = make_get_helper(range.offset, range.size);

			callback_t tmp = std::bind(&req_get::on_read_is_done, shared_from_this());
			get_helper->read(get_session(), std::bind(&req_get::on_simple_range_read, shared_from_this()
						, std::placeholders::_1, std::move(tmp))
					, std::bind(&req_get::on_error, shared_from_this()));
		} else {
			auto boundary = make_boundary();

			prospect_http_response.headers().set_content_type(
					"multipart/byteranges; boundary=" + boundary);

			size_t content_length = 0;
			std::list<std::string> ranges_headers;

			{
				for (auto begin_it = ranges->begin(), it = begin_it, end_it = ranges->end();
						it != end_it; ++it) {
					std::ostringstream oss;

					if (it != begin_it) {
						oss << "\r\n";
					}

					oss
						<< "--" << boundary << "\r\n"
						<< "Content-Type: application/octet-stream\r\n"
						<< "Content-Range: "
						<< make_content_range_header(it->offset, it->size, size)
						<< "\r\n\r\n";

					auto headers = oss.str();

					content_length += headers.size();
					content_length += it->size;
					ranges_headers.emplace_back(std::move(headers));
				}
				{
					std::ostringstream oss;
					oss << "\r\n--" << boundary << "--\r\n";
					auto last_boundary = oss.str();
					content_length += last_boundary.size();
					ranges_headers.emplace_back(std::move(last_boundary));
				}
			}

			prospect_http_response.headers().set_content_length(content_length);

			send_headers(std::move(prospect_http_response)
					, std::function<void (const boost::system::error_code &)>());

			read_range(std::move(*ranges), std::move(ranges_headers));
		}
	} else {
		prospect_http_response.set_code(416);
		prospect_http_response.headers().set_content_length(0);
		prospect_http_response.headers().set("Content-Range"
				, "bytes */" + boost::lexical_cast<std::string>(size));

		send_headers(std::move(prospect_http_response)
				, std::function<void (const boost::system::error_code &)>());
		return;
	}
}

std::shared_ptr<get_helper_t> req_get::make_get_helper(size_t offset, size_t size) {
	return std::make_shared<get_helper_t>(
				ioremap::swarm::logger(logger(), blackhole::log::attributes_t())
				, key, offset, size
				, server()->m_read_chunk_size);
}

void req_get::on_simple_read(const std::shared_ptr<get_helper_t> &get_helper
		, callback_t read_is_done) {
	auto chunk_type = get_helper->chunk();

	if (chunk_type == get_helper_t::chunk_type_tag::first ||
			chunk_type == get_helper_t::chunk_type_tag::single) {
		if (NULL == server()->m_magic.get()) {
			server()->m_magic.reset(new magic_provider());
		}

		const auto &buffer = get_helper->const_buffer();
		prospect_http_response.headers().set_content_type(server()->m_magic->type(
					boost::asio::buffer_cast<const char *>(buffer)
					, boost::asio::buffer_size(buffer)));

		send_headers(std::move(prospect_http_response)
				, std::function<void (const boost::system::error_code &)>());
	}

	if (chunk_type == get_helper_t::chunk_type_tag::single) {
		if (!bad_groups.empty()) {
			{
				std::ostringstream oss;
				oss << "mds-proxy recovers file! groups=" << bad_groups;
				const auto &msg = oss.str();
				MDS_LOG_INFO("%s", msg.c_str());
			}
			const auto &const_buffer = get_helper->const_buffer();
			auto write_session = server()->write_session(request(), bad_groups);
			write_session.set_timestamp(get_helper->timestamp());
			write_session.write_data(key, ioremap::elliptics::data_pointer::from_raw(
						const_cast<void *>(boost::asio::buffer_cast<const void *>(const_buffer))
						, boost::asio::buffer_size(const_buffer)), 0);
		}
	}

	on_simple_range_read(get_helper, std::move(read_is_done));
}

void req_get::on_simple_range_read(const std::shared_ptr<get_helper_t> &get_helper
		, callback_t read_is_done) {
	send_data(get_helper->const_buffer(), std::bind(&req_get::on_simple_data_sent
				, shared_from_this(), std::placeholders::_1, get_helper, std::move(read_is_done)));
}

void req_get::on_simple_data_sent(const boost::system::error_code &error_code
		, const std::shared_ptr<get_helper_t> &get_helper
		, callback_t read_is_done) {
	auto chunk_type = get_helper->chunk();

	if (error_code) {
		MDS_LOG_ERROR("Get: error during chunk sending: %s", error_code.message().c_str());
		if (chunk_type == get_helper_t::chunk_type_tag::first ||
				chunk_type == get_helper_t::chunk_type_tag::single) {
			send_reply(500);
		}
		return;
	}

	MDS_LOG_INFO("Get: chunk was sent");

	if (chunk_type == get_helper_t::chunk_type_tag::last ||
			chunk_type == get_helper_t::chunk_type_tag::single) {
		read_is_done();
		return;
	}

	get_helper->read(get_session(), std::bind(&req_get::on_simple_range_read, shared_from_this()
				, std::placeholders::_1, std::move(read_is_done))
			, std::bind(&req_get::on_error, shared_from_this()));
}

void req_get::read_range(ranges_t ranges, std::list<std::string> ranges_headers) {
	if (ranges.empty()) {
		send_data(std::move(ranges_headers.front())
				, std::bind(&req_get::on_read_is_done, shared_from_this()));
	} else {
		send_data(std::move(ranges_headers.front())
				, std::function<void (const boost::system::error_code &)>());
		ranges_headers.pop_front();

		auto range = ranges.front();
		ranges.pop_front();

		auto get_helper = make_get_helper(range.offset, range.size);

		callback_t tmp = std::bind(&req_get::read_range, shared_from_this()
				, std::move(ranges), std::move(ranges_headers));
		get_helper->read(get_session(), std::bind(&req_get::on_simple_range_read, shared_from_this()
					, std::placeholders::_1, tmp)
				, std::bind(&req_get::on_error, shared_from_this()));
	}
}

void req_get::on_error() {
	send_reply(500);
}

void req_get::on_read_is_done() {
	reply()->close(boost::system::error_code());
}

ioremap::elliptics::session req_get::get_session() {
	auto session = m_session->clone();

	session.set_timeout(server()->timeout.read);

	if (m_first_chunk) {
		m_first_chunk = false;

		if (server()->timeout_coef.data_flow_rate) {
			session.set_timeout(
					m_session->get_timeout() + total_size / server()->timeout_coef.data_flow_rate);
		}

	} else {
		session.set_ioflags(m_session->get_ioflags() | DNET_IO_FLAGS_NOCSUM);
	}

	return session;
}

}

