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

#include "get.hpp"

#include "utils.hpp"
#include "error.hpp"
#include "timer.hpp"

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <crypto++/md5.h>

#include <mds/error.h>

#include <folly/futures/helpers.h>

#include <chrono>
#include <ctime>
#include <algorithm>

namespace {

std::string generate_etag(uint64_t timestamp, uint64_t size) {
	using namespace CryptoPP;

	Weak::MD5 hash;

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

} // namespace

namespace elliptics {

req_get::req_get()
	: handler<ioremap::thevoid::simple_request_stream>("get")
{
}

void
req_get::on_request(const ioremap::thevoid::http_request &http_request
		, const boost::asio::const_buffer &const_buffer) {
	(void) const_buffer;

	MDS_LOG_INFO("start request processing");
	start_request();

	if (http_request.method() != "HEAD" && http_request.method() != "GET") {
		MDS_LOG_INFO("unsupported http method\'s type: \"%s\"", http_request.method().c_str());
		send_reply(400);
		return;
	}

	try {
		ns_state = server()->get_namespace_state(http_request.url().path(), "/get");
	} catch (const std::exception &ex) {
		MDS_LOG_ERROR("cannot get namespace state: %s", ex.what());
		send_reply(400);
		return;
	}

	try {
		read_controller = server()->make_read_controller(ns_state, http_request);
	} catch (const http_error &ex) {
		MDS_LOG_ERROR("cannot make read controller: %s", ex.what());
		send_reply(ex.http_status());
	} catch (const std::exception &ex) {
		MDS_LOG_ERROR("cannot make read controller: %s", ex.what());
		send_reply(400);
		return;
	}

	if (request().url().query().has_item("expiration-time")) {
		if (!ns_settings(ns_state).custom_expiration_time) {
			MDS_LOG_ERROR("using of expiration-time is prohibited");
			send_reply(403);
			return;
		}

		auto expiration_time_str = *request().url().query().item_value("expiration-time");

		try {
			expiration_time = std::chrono::seconds(
					boost::lexical_cast<size_t>(expiration_time_str));
			MDS_LOG_INFO("user set expiration time to %s seconds", expiration_time->count());
		} catch (const std::exception &ex) {
			MDS_LOG_ERROR("cannot parse expiration-time: %s", ex.what());
			send_reply(400);
			return;
		}
	}

	if (!server()->check_basic_auth(ns_state.name(), ns_settings(ns_state).auth_key_for_read
				, http_request.headers().get("Authorization"))) {
		auto token = server()->get_auth_token(http_request.headers().get("Authorization"));
		MDS_LOG_INFO("invalid token \"%s\"", token.empty() ? "<none>" : token.c_str());

		ioremap::thevoid::http_response reply;
		ioremap::swarm::http_headers headers;

		reply.set_code(401);
		headers.add("WWW-Authenticate", std::string("Basic realm=\"") + ns_state.name() + "\"");
		headers.add("Content-Length", "0");
		reply.set_headers(headers);
		send_reply(std::move(reply));
		return;
	}

	auto self = shared_from_this();

	auto on_get_file_info = [this, self] (mds::FileInfoPtr file_info) {
		return process_request(read_controller, std::move(file_info));
	};

	auto on_processed_request = [this, self] () {
		read_controller->Close();
		close();
	};

	auto send_error = [this] (int code, const std::string &reason) {
		MDS_LOG_ERROR("cannot process request: %s", reason);

		read_controller->Close();

		if (headers_were_sent()) {
			MDS_LOG_ERROR(
					"error occured after headers were sent and cannot be reported to the client");
			close(boost::system::errc::make_error_code(
						boost::system::errc::operation_canceled));
			return;
		}

		send_reply(code);
	};

	auto on_http_error = [this, self, send_error] (const http_error &ex) {
		send_error(ex.http_status(), ex.what());
	};

	auto on_file_not_found_error = [this, self, send_error] (const mds::FileNotFoundError &ex) {
		send_error(404, ex.what());
	};

	auto on_exception = [this, self, send_error] (const std::exception &ex) {
		send_error(500, ex.what());
	};

	read_controller->GetFileInfo()
		.then(std::move(on_get_file_info))
		.then(std::move(on_processed_request))
		.onError(std::move(on_http_error))
		.onError(std::move(on_file_not_found_error))
		.onError(std::move(on_exception));
}

folly::Future<folly::Unit>
req_get::process_request(mds::ReadControllerPtr read_controller
		, mds::FileInfoPtr file_info) {
	auto timestamp = file_info->Timestamp().tv_sec;
	auto size = file_info->Size();
	std::string etag = generate_etag(timestamp, size);
	bool send_whole_file = true;

	{
		auto res = process_precondition_headers(timestamp, etag);
		const auto &opt_http_response = std::get<0>(res);

		if (opt_http_response) {
			return send_headers(std::move(*opt_http_response));
		}

		send_whole_file = std::get<1>(res);
	}

	{
		auto opt_http_response = try_to_redirect_request(file_info);

		if (opt_http_response) {
			return send_headers(std::move(*opt_http_response));
		}
	}

	ioremap::thevoid::http_response http_response;

	http_response.set_code(200);
	http_response.headers().set_last_modified(timestamp);
	http_response.headers().set("ETag", etag);
	http_response.headers().set("Accept-Ranges", "bytes");

	if (request().method() == "HEAD") {
		http_response.headers().set_content_length(size);
		return send_headers(std::move(http_response));
	}

	return process_streaming(std::move(read_controller), std::move(http_response)
			, size, send_whole_file);
}

std::tuple<boost::optional<ioremap::thevoid::http_response>, bool>
req_get::process_precondition_headers(time_t timestamp, const std::string &etag) {
	ioremap::thevoid::http_response http_response;
	http_response.headers().set_content_length(0);

	bool send_whole_file = false;

	const auto &headers = request().headers();

	bool if_prospect_304 = true;
	bool has_304_headers = false;
	bool if_range = false;

	struct tm modified_time;
	gmtime_r(&timestamp, &modified_time);

	auto range_header = headers.get("Range");

#define MAKE_TIME_TUPLE(T) std::make_tuple( \
		(T).tm_year, (T).tm_mon, (T).tm_mday, \
		(T).tm_hour, (T).tm_min, (T).tm_sec)

	if (range_header) {
		if (auto if_range_header = headers.get("If-Range")) {
			if ((*if_range_header)[0] == '\"') {
				MDS_LOG_INFO("If-Range header contains ETag");
				if (*if_range_header == etag) {
					MDS_LOG_INFO("ETag in If-Range is correct");
					if_range = true;
				} else {
					MDS_LOG_INFO("ETag in If-Range is incorrect");
					send_whole_file = true;
				}
			} else {
				MDS_LOG_INFO("If-Range header contains Time");
				const auto &str = *if_range_header;

				struct tm tm_condition;
				strptime(str.c_str(), "%a, %d %b %Y %H:%M:%S %Z", &tm_condition);

				if (MAKE_TIME_TUPLE(modified_time) == MAKE_TIME_TUPLE(tm_condition)) {
					MDS_LOG_INFO("Time in If-Range header is equal to Last-Modified Time");
					if_range = true;
				} else {
					MDS_LOG_INFO("Time in If-Range header is not equal to Last-Modified Time");
					send_whole_file = true;
				}
			}
		}
	}

	if (auto if_match_header = headers.get("If-Match")) {
		if (*if_match_header != etag) {
			MDS_LOG_INFO("If-Match header contains incorrect ETag");
			if (if_range) {
				send_whole_file = true;
			} else {
				http_response.set_code(412);
				return std::make_tuple(std::move(http_response), false);
			}
		}
	}

	if (auto if_none_match_header = headers.get("If-None-Match")) {
		has_304_headers = true;
		if (*if_none_match_header != etag) {
			MDS_LOG_INFO("If-None-Match header contains incorrect ETag");
			if_prospect_304 = false;
		}
	}

	if (auto if_unmodified_since_header = headers.get("If-Unmodified-Since")) {
		const auto &str = *if_unmodified_since_header;

		struct tm tm_condition;
		strptime(str.c_str(), "%a, %d %b %Y %H:%M:%S %Z", &tm_condition);

		if (MAKE_TIME_TUPLE(modified_time) > MAKE_TIME_TUPLE(tm_condition)) {
			MDS_LOG_INFO("If-Unmodified-Since is older than Last-Modified Time");
			if (if_range) {
				send_whole_file = true;
			} else {
				http_response.set_code(412);
				return std::make_tuple(std::move(http_response), false);
			}
		}
	}

	if (auto if_modified_since_header = headers.get("If-Modified-Since")) {
		has_304_headers = true;
		const auto &str = *if_modified_since_header;

		struct tm tm_condition;
		strptime(str.c_str(), "%a, %d %b %Y %H:%M:%S %Z", &tm_condition);

		if (MAKE_TIME_TUPLE(modified_time) > MAKE_TIME_TUPLE(tm_condition)) {
			MDS_LOG_INFO("If-Modified-Since is older than Last-Modified Time");
			if_prospect_304 = false;
		}
	}

#undef MAKE_TIME_TUPLE

	if (has_304_headers && if_prospect_304) {
		http_response.set_code(304);
		return std::make_tuple(std::move(http_response), false);
	}

	return std::make_tuple(boost::none, send_whole_file);
}

req_get::redirect_arg_tag
req_get::get_redirect_arg() {
	auto arg = request().url().query().item_value("redirect");

	if (!arg) {
		return redirect_arg_tag::none;
	}

	auto str = *arg;

	if (str == "yes") {
		return redirect_arg_tag::client_want_redirect;
	}

	return redirect_arg_tag::none;
}

std::vector<std::tuple<std::string, std::string>>
req_get::get_redirect_query_args() {
	std::vector<std::tuple<std::string, std::string>> result;

	if (ns_settings(ns_state).add_orig_path_query_arg) {
		result.emplace_back(std::make_tuple("orig_path"
					, url_encode(request().url().path())));
	}

	const auto &query = request().url().query();
	const auto &redirect_query_args = ns_settings(ns_state).redirect_query_args;

	for (auto it = redirect_query_args.begin(), end = redirect_query_args.end()
			; it != end; ++it) {
		if (auto arg = query.item_value(*it)) {
			result.emplace_back(std::make_tuple(*it, url_encode(*arg)));
		}
	}

	return result;
}

boost::optional<ioremap::thevoid::http_response>
req_get::try_to_redirect_request(const mds::FileInfoPtr &file_info) {
	auto redirect_arg = get_redirect_arg();

	if (redirect_arg != redirect_arg_tag::client_want_redirect) {
		auto redirect_size = ns_settings(ns_state).redirect_content_length_threshold;
		if (redirect_size == -1) {
			MDS_LOG_INFO("cannot redirect: redirect-content-length-threshold is infinity");
			return boost::none;
		}

		if (static_cast<size_t>(redirect_size) > file_info->Size()) {
			std::ostringstream oss;
			oss << "cannot redirect: file is to small;"
				<< " file-size=" << file_info->Size() << ";"
				<< " redirect-content-length-threshold=" << redirect_size;
			auto str = oss.str();
			MDS_LOG_INFO("%s", str.c_str());
			return boost::none;
		}
	}

	const auto &headers = request().headers();

	try {
		if (ns_settings(ns_state).sign_token.empty()) {
			MDS_LOG_INFO("cannot redirect without signature-token");

			if (redirect_arg == redirect_arg_tag::client_want_redirect) {
				throw http_error(403, "redirect=yes is not allowed for this namespace");
			}

			return boost::none;
		}

		auto x_regional_host = headers.get("X-Regional-Host").get_value_or("");
		auto file_location = server()->get_file_location(file_info, ns_state, x_regional_host);
		auto ts = make_signature_ts(expiration_time, ns_state);
		auto args = get_redirect_query_args();

		auto message = make_signature_message(file_location, ts, args);
		auto sign = make_signature(message, ns_settings(ns_state).sign_token);

		std::stringstream oss;
		oss << "//" << file_location.host << file_location.path << "?ts=" << ts;

		for (auto it = args.begin(), end = args.end(); it != end; ++it) {
			oss << '&' << std::get<0>(*it) << '=' << std::get<1>(*it);
		}

		oss << "&sign=" << sign;

		ioremap::thevoid::http_response http_response;
		http_response.set_code(302);
		http_response.headers().set_content_length(0);

		auto location = oss.str();
		http_response.headers().set("Location", location);

		MDS_LOG_INFO("redirect request to \"%s\"", location.c_str());
		return http_response;
	} catch (const std::exception &ex) {
		MDS_LOG_ERROR("cannot generate signature: %s", ex.what());
		return boost::none;
	}
}

folly::Future<folly::Unit>
req_get::process_streaming(mds::ReadControllerPtr read_controller
		, ioremap::thevoid::http_response http_response
		, size_t size, bool send_whole_file) {
	const auto &headers = request().headers();
	auto range_header = headers.get("Range");

	if (send_whole_file || !range_header) {
		MDS_LOG_INFO("send whole file");
		http_response.headers().set_content_length(size);
		return process_whole_file(std::move(read_controller), std::move(http_response));
	}

	if (auto ranges = parse_range_header(*range_header, size)) {
		http_response.set_code(206);

		if (ranges->size() == 1) {
			MDS_LOG_INFO("send a range of file");
			const auto &range = ranges->front();

			http_response.headers().set_content_type("application/octet-stream");
			http_response.headers().set_content_length(range.size);
			http_response.headers().set("Content-Range"
					, make_content_range_header(range.offset, range.size, size));

			return process_range(std::move(read_controller), std::move(http_response)
					, range.offset, range.size);
		}

		MDS_LOG_INFO("send multi-range of file");

		auto boundary = make_boundary();

		http_response.headers().set_content_type(
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

		http_response.headers().set_content_length(content_length);

		return process_ranges(std::move(read_controller), std::move(http_response)
				, std::move(*ranges), std::move(ranges_headers));
	}

	http_response.set_code(416);
	http_response.headers().set_content_length(0);
	http_response.headers().set("Content-Range"
			, "bytes */" + boost::lexical_cast<std::string>(size));

	MDS_REQUEST_REPLY("get", http_response.code(), reinterpret_cast<uint64_t>(this->reply().get()));
	return send_headers(std::move(http_response));
}

folly::Future<folly::Unit>
req_get::process_whole_file(mds::ReadControllerPtr read_controller
		, ioremap::thevoid::http_response http_response) {
	auto self = shared_from_this();

	auto on_get_read_stream = [this, self, read_controller, http_response]
		(mds::ReadStreamPtr read_stream) {
			read_stream->Start();
			return process_whole_file(std::move(read_stream), std::move(http_response));
		};


	return read_controller->GetReadStream()
		.then(std::move(on_get_read_stream));
}

folly::Future<folly::Unit>
req_get::process_whole_file(mds::ReadStreamPtr read_stream
		, ioremap::thevoid::http_response http_response) {
	auto self = shared_from_this();

	auto on_read_chunk = [this, self, http_response] (mds::ReadStreamResult result) mutable {
		http_response.headers().set_content_type(detect_content_type(result));

		auto on_sent_headers = [this, self, result]() mutable {
			return send_data(std::move(result.Data()));
		};

		return send_headers(std::move(http_response)).then(std::move(on_sent_headers));
	};

	auto on_sent_chunk = [this, self, read_stream]() {
		return stream_range(std::move(read_stream));
	};

	return read_stream->ReadChunk()
		.then(std::move(on_read_chunk))
		.then(std::move(on_sent_chunk));
}

std::string
req_get::detect_content_type(const mds::ReadStreamResult &result) {
	util::timer_t timer;

	if (NULL == server()->m_magic.get()) {
		server()->m_magic.reset(new magic_provider());
	}

	// Fisrt 10KB of data should be enough to detect content type.
	static size_t MAGIC_SIZE = 10 * 1024;
	auto content_type = server()->m_magic->type(
			result.Data()->data()
			, std::min(result.Size(), MAGIC_SIZE));

	MDS_LOG_INFO("content-type was detected: type=\"%s\"; spent-time=%s"
			, content_type, timer.str_ms());

	return content_type;
}

folly::Future<folly::Unit>
req_get::process_range(mds::ReadControllerPtr read_controller
		, ioremap::thevoid::http_response http_response, size_t offset, size_t size) {
	auto self = shared_from_this();

	auto on_sent_headers = [this, self, read_controller, offset, size]() {
		return stream_range(std::move(read_controller), offset, size);
	};

	return send_headers(std::move(http_response))
		.then(std::move(on_sent_headers));
}

folly::Future<folly::Unit>
req_get::process_ranges(mds::ReadControllerPtr read_controller
		, ioremap::thevoid::http_response http_response
		, ranges_t ranges, std::list<std::string> boundaries) {
	auto self = shared_from_this();

	auto on_sent_headers = [this, self, read_controller, ranges, boundaries]() {
		return stream_ranges(std::move(read_controller), std::move(ranges), std::move(boundaries));
	};

	return send_headers(std::move(http_response))
		.then(std::move(on_sent_headers));
}

folly::Future<folly::Unit>
req_get::stream_ranges(mds::ReadControllerPtr read_controller, ranges_t ranges
		, std::list<std::string> ranges_headers) {
	auto boundary = std::move(ranges_headers.front());
	ranges_headers.pop_front();

	if (ranges.empty()) {
		return send_data(std::move(boundary));
	}

	auto self = shared_from_this();

	auto range = ranges.front();
	ranges.pop_front();

	auto on_sent_boundary = [this, self, read_controller, range]() {
		return stream_range(read_controller, range.offset, range.size);
	};

	auto on_streamed_range = [this, self, read_controller, ranges, ranges_headers]() {
		return stream_ranges(std::move(read_controller), std::move(ranges)
				, std::move(ranges_headers));
	};

	return send_data(std::move(boundary)).then(std::move(on_sent_boundary))
		.then(std::move(on_streamed_range));
}

folly::Future<folly::Unit>
req_get::stream_range(mds::ReadControllerPtr read_controller, uint64_t offset, uint64_t size) {
	auto self = shared_from_this();
	auto next = [this, self](mds::ReadStreamPtr read_stream) {
		read_stream->Start();
		return stream_range(std::move(read_stream));
	};

	return read_controller->GetReadStream(offset, size).then(std::move(next));
}

folly::Future<folly::Unit>
req_get::stream_range(mds::ReadStreamPtr read_stream) {
	if (!read_stream->CanRead()) {
		read_stream->Close();
		// TODO: return WaitForCleanup
		return folly::makeFuture();
	}

	auto self = shared_from_this();
	auto on_read_chunk = [this, self](mds::ReadStreamResult result) {
		return send_data(std::move(result.Data()));
	};

	auto on_sent_chunk = [this, self, read_stream]() {
		return stream_range(read_stream);
	};

	return read_stream->ReadChunk().then(std::move(on_read_chunk)).then(std::move(on_sent_chunk));
}

} // namespace elliptics

