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

#include "handystats.hpp"

#include "get.hpp"

#include "ranges.hpp"
#include "data_container.hpp"
#include "utils.hpp"
#include "error.hpp"

#include <swarm/url.hpp>

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <crypto++/md5.h>

#include <boost/asio/buffer.hpp>

#include <functional>
#include <chrono>
#include <ctime>
#include <algorithm>

namespace boost {
namespace asio {

boost::asio::const_buffers_1
buffer(const ioremap::elliptics::data_pointer &data_pointer) {
	return {data_pointer.data(), data_pointer.size()};
}

} // namespace asio
} // namespace boost

void
elliptics::req_get::find_first_group(
		std::function<void (const ie::lookup_result_entry &)> on_result
		, std::function<void ()> on_error) {
	if (parallel_lookuper_ptr->results_left()) {
		MDS_LOG_INFO("find next first group");

		auto future = parallel_lookuper_ptr->next_lookup_result();

		auto next = std::bind(&req_get::next_first_group_is_found, shared_from_this()
				, std::placeholders::_1, std::placeholders::_2
				, std::move(on_result), std::move(on_error));

		future.connect(next);
		return;
	}

	all_groups_were_processed(std::move(on_error));
}

void
elliptics::req_get::next_first_group_is_found(const ie::sync_lookup_result &entries
		, const ie::error_info &error_info
		, std::function<void (const ie::lookup_result_entry &)> on_result
		, std::function<void ()> on_error) {
	if (entries.empty()) {
		MDS_LOG_ERROR("lookup result contains no entries: %s", error_info.message().c_str());
		find_first_group(std::move(on_result), std::move(on_error));
		return;
	}

	const auto &entry = entries.front();
	auto group_id = entry.command()->id.group_id;

	std::ostringstream oss;
	oss << "group " << group_id << " was found";

	if (check_lookup_result_entry(entry)) {
		oss << " and will be used for subsequent processing";
		auto msg = oss.str();
		MDS_LOG_INFO("%s", msg.c_str());

		on_result(entry);
		return;
	}

	oss << " and cannot be used: \"" << error_info.message() << "\"";
	auto msg = oss.str();
	MDS_LOG_ERROR("%s", msg.c_str());

	find_first_group(std::move(on_result), std::move(on_error));
}

void
elliptics::req_get::find_other_group(
		std::function<void ()> on_result
		, std::function<void ()> on_error) {
	if (parallel_lookuper_ptr->results_left()) {
		MDS_LOG_INFO("find next group");
		auto future = parallel_lookuper_ptr->next_lookup_result();

		auto next = std::bind(&req_get::next_other_group_is_found, shared_from_this()
				, std::placeholders::_1, std::placeholders::_2
				, std::move(on_result), std::move(on_error));

		future.connect(next);
		return;
	}

	all_groups_were_processed(std::move(on_error));
}

void
elliptics::req_get::next_other_group_is_found(const ie::sync_lookup_result &entries
		, const ie::error_info &error_info
		, std::function<void ()> on_result
		, std::function<void ()> on_error) {
	if (entries.empty()) {
		MDS_LOG_ERROR("lookup result contains no entries: %s", error_info.message().c_str());
		find_other_group(std::move(on_result), std::move(on_error));
		return;
	}

	const auto &entry = entries.front();
	auto group_id = entry.command()->id.group_id;

	std::ostringstream oss;
	oss << "group " << group_id << " was found";

	if (!check_lookup_result_entry(entry)) {
		oss << " and cannot be used: \"" << error_info.message() << "\"";
		auto msg = oss.str();
		MDS_LOG_ERROR("%s", msg.c_str());

		find_other_group(std::move(on_result), std::move(on_error));
		return;
	}

	if (some_data_were_sent && !lookup_result_entries_are_equal(*lookup_result_entry_opt, entry)) {
		oss << " and cannot be used: \"group has different checksums and/or timestamp\"";
		auto msg = oss.str();
		MDS_LOG_ERROR("%s", msg.c_str());

		find_other_group(std::move(on_result), std::move(on_error));
		return;
	}

	oss << " and will be used for subsequent processing";
	auto msg = oss.str();
	MDS_LOG_INFO("%s", msg.c_str());

	m_first_chunk = true;
	m_session->set_groups({static_cast<int>(entry.command()->id.group_id)});
	set_csum_type(entry);

	on_result();
}

void
elliptics::req_get::all_groups_were_processed(std::function<void ()> on_error) {
	if (!has_internal_storage_error) {
		MDS_LOG_INFO("all groups were processed: file not found");
	} else {
		MDS_LOG_ERROR("all groups were processed: cannot read file");
	}

	on_error();
}

bool
elliptics::req_get::check_lookup_result_entry(const ie::lookup_result_entry &entry) {
	auto status = entry.status();

	if (!status) {
		return true;
	}

	switch (status) {
	case -ENOENT:
	case -EBADFD:
	case -EILSEQ: {
			auto group = entry.command()->id.group_id;

			if (std::find(cached_groups.begin(), cached_groups.end(), group)
					== cached_groups.end()) {
				bad_groups.push_back(group);
			}
		}
	}

	if (status != -ENOENT) {
		has_internal_storage_error = true;
	}

	return false;
}

bool
elliptics::req_get::lookup_result_entries_are_equal(const ie::lookup_result_entry &lhs
		, const ie::lookup_result_entry &rhs) {
	const auto *lhs_fi = lhs.file_info();
	const auto *rhs_fi = rhs.file_info();

	const auto &lhs_mtime = lhs_fi->mtime;
	const auto &rhs_mtime = rhs_fi->mtime;

	if (std::make_tuple(lhs_mtime.tsec, lhs_mtime.tnsec)
			!= std::make_tuple(rhs_mtime.tsec, rhs_mtime.tnsec)) {
		return false;
	}

	if (!std::equal(lhs_fi->checksum, lhs_fi->checksum + DNET_CSUM_SIZE, rhs_fi->checksum)) {
		return false;
	}

	return true;
}

void
elliptics::req_get::process_group_info(const ie::lookup_result_entry &entry) {
	try {
		lookup_result_entry_opt.reset(entry);

		m_session->set_groups({static_cast<int>(entry.command()->id.group_id)});
		set_csum_type(entry);

		uint64_t tsec = entry.file_info()->mtime.tsec;

		auto res = process_precondition_headers(tsec, total_size());

		if (std::get<0>(res)) {
			return;
		}

		// TODO: change declaration of try_to_redirect_request
		if (try_to_redirect_request({entry}, total_size())) {
			return;
		}

		start_reading(total_size(), std::get<1>(res));
	} catch (const http_error &ex) {
		MDS_LOG_INFO("http_error: status=\"%s\"; description=\"%s\"", ex.http_status(), ex.what());
		send_reply(ex.http_status());
	}
}

void
elliptics::req_get::set_csum_type(const ie::lookup_result_entry &entry) {
	with_chunked_csum = entry.file_info()->record_flags & DNET_RECORD_FLAGS_CHUNKED_CSUM;

	if (with_chunked_csum) {
		MDS_LOG_INFO("record has chuncked csum, proxy will check csums for every chunk");
	} else {
		MDS_LOG_INFO("record does not have chuncked csum, proxy will check csum only for first chunk");
	}
}

void
elliptics::req_get::read_chunk(size_t offset, size_t size
		, std::function<void (const ie::read_result_entry &)> on_result
		, std::function<void ()> on_error) {
	auto session = get_session();

	{
		std::ostringstream oss;
		oss << "read chunk: offset=" << offset << "; size=" << size
			<< "; groups=" << session.get_groups() << ";";
		auto msg = oss.str();
		MDS_LOG_INFO("%s", msg.c_str());
	}

	auto future = session.read_data(key, offset, size);

	auto callback = std::bind(&req_get::read_chunk_is_finished, shared_from_this()
			, std::placeholders::_1, std::placeholders::_2
			, util::timer_t{}
			, offset, size
			, std::move(on_result), std::move(on_error));

	future.connect(callback);
}

void
elliptics::req_get::read_chunk_is_finished(
		const ie::sync_read_result &entries
		, const ie::error_info &error_info
		, util::timer_t timer
		, size_t offset, size_t size
		, std::function<void (const ie::read_result_entry &)> on_result
		, std::function<void ()> on_error) {
	std::ostringstream oss;
	oss << "chunk reading was finished: spent-time=" << timer.str_ms() << "; status=\""
		<< (error_info ? "bad" : "ok") << "\"; description=\"";

	if (error_info) {
		oss << error_info.message() << "\";";
		auto msg = oss.str();
		MDS_LOG_ERROR("%s", msg.c_str());

		auto next = std::bind(&req_get::read_chunk, shared_from_this()
				, offset, size, std::move(on_result), on_error);

		has_internal_storage_error = true;
		find_other_group(std::move(next), std::move(on_error));
		return;
	}

	oss << "success\";";
	auto msg = oss.str();
	MDS_LOG_INFO("%s", msg.c_str());

	on_result(entries.front());
}

void
elliptics::req_get::send_chunk(ie::data_pointer data_pointer
		, std::function<void ()> on_result
		, std::function<void ()> on_error) {
	MDS_LOG_INFO("send chunk");
	auto callback = std::bind(&req_get::send_chunk_is_finished, shared_from_this()
			, std::placeholders::_1
			, util::timer_t{}
			, std::move(on_result), std::move(on_error));
	send_data(std::move(data_pointer), std::move(callback));
}

void
elliptics::req_get::send_chunk_is_finished(const boost::system::error_code &error_code
		, util::timer_t timer
		, std::function<void ()> on_result
		, std::function<void ()> on_error) {
	some_data_were_sent = true;
	std::ostringstream oss;
	oss << "chink was sent: spent-time=" << timer.str_ms() << "; status=\""
		<< (error_code ? "bad" : "ok") << "\"; description=\"";

	if (error_code) {
		oss << error_code.message() << "\";";
		auto msg = oss.str();
		MDS_LOG_ERROR("%s", msg.c_str());

		on_error();
		return;
	}

	oss << "success\";";
	auto msg = oss.str();
	MDS_LOG_INFO("%s", msg.c_str());

	on_result();
}

void
elliptics::req_get::read_and_send_chunk(size_t offset, size_t size
		, std::function<void ()> on_result
		, std::function<void ()> on_error) {
	auto self = shared_from_this();
	auto next = [this, self, on_result, on_error] (const ie::read_result_entry &entry) {
		send_chunk(std::move(entry.file()), std::move(on_result), std::move(on_error));
	};

	read_chunk(offset, size, std::move(next), std::move(on_error));
}

void
elliptics::req_get::read_and_send_range(size_t offset, size_t size
		, std::function<void ()> on_result
		, std::function<void ()> on_error) {
	// TODO: m_read_chunk_size should be size_t
	auto current_size = std::min(static_cast<size_t>(server()->m_read_chunk_size), size);
	auto next_offset = offset + current_size;
	auto next_size = size - current_size;

	auto self = shared_from_this();
	auto next = [this, self, next_offset, next_size, on_result, on_error] () {
		if (next_size == 0) {
			on_result();
			return;
		}

		read_and_send_range(next_offset, next_size, std::move(on_result), std::move(on_error));
	};

	read_and_send_chunk(offset, current_size, std::move(next), std::move(on_error));
}

void
elliptics::req_get::read_and_send_ranges(ranges_t ranges, std::list<std::string> ranges_headers
		, std::function<void ()> on_result
		, std::function<void ()> on_error) {
	auto self = shared_from_this();
	auto boundary = ranges_headers.front();
	ranges_headers.pop_front();

	if (ranges.empty()) {
		auto next = [self, on_result, on_error] (const boost::system::error_code &error_code) {
			if (error_code) {
				on_error();
				return;
			}

			on_result();
		};

		send_data(std::move(boundary), std::move(next));
		return;
	}

	send_data(std::move(boundary)
			, std::function<void (const boost::system::error_code &)>());

	auto range = ranges.front();
	ranges.pop_front();

	auto next = [this, self, ranges, ranges_headers, on_result, on_error] () {
		read_and_send_ranges(std::move(ranges), std::move(ranges_headers)
				, std::move(on_result), std::move(on_error));
	};

	read_and_send_range(range.offset, range.size, std::move(next), std::move(on_error));
}

void
elliptics::req_get::process_whole_file() {
	auto current_size = std::min(static_cast<size_t>(server()->m_read_chunk_size), total_size());

	auto result_callback = std::bind(&req_get::detect_content_type, shared_from_this()
			, std::placeholders::_1);
	auto error_callback = std::bind(&req_get::on_error, shared_from_this());
	read_chunk(0, current_size, std::move(result_callback), std::move(error_callback));
}

void
elliptics::req_get::process_range(size_t offset, size_t size) {
	MDS_REQUEST_REPLY("get", prospect_http_response.code(), reinterpret_cast<uint64_t>(this->reply().get()));
	headers_were_sent = true;
	send_headers(std::move(prospect_http_response)
			, std::function<void (const boost::system::error_code &)>());

	std::function<void ()> close_callback = std::bind(&req_get::request_is_finished, shared_from_this());
	std::function<void ()> error_callback = std::bind(&req_get::on_error, shared_from_this());

	read_and_send_range(offset, size, std::move(close_callback), std::move(error_callback));
}

void
elliptics::req_get::process_ranges(ranges_t ranges, std::list<std::string> boundaries) {
	MDS_REQUEST_REPLY("get", prospect_http_response.code(), reinterpret_cast<uint64_t>(this->reply().get()));
	headers_were_sent = true;
	send_headers(std::move(prospect_http_response)
			, std::function<void (const boost::system::error_code &)>());

	std::function<void ()> close_callback = std::bind(&req_get::request_is_finished, shared_from_this());
	std::function<void ()> error_callback = std::bind(&req_get::on_error, shared_from_this());

	read_and_send_ranges(std::move(ranges), std::move(boundaries)
			, std::move(close_callback), std::move(error_callback));
}

void
elliptics::req_get::detect_content_type(const ie::read_result_entry &entry) {
	const auto &data_pointer = entry.file();

	{
		util::timer_t timer;
		if (NULL == server()->m_magic.get()) {
			server()->m_magic.reset(new magic_provider());
		}

		// Fisrt 10KB of data should be enough to detect content type
		static size_t MAGIC_SIZE = 10 * 1024;
		auto content_type = server()->m_magic->type(static_cast<const char *>(data_pointer.data())
				, std::min(data_pointer.size(), MAGIC_SIZE));

		prospect_http_response.headers().set_content_type(content_type);

		std::ostringstream oss;
		oss << "content-type was detected: type=\"" << content_type
			<<  "\"; spent-time=" << timer.str_ms();
		auto msg = oss.str();
		MDS_LOG_INFO("%s", msg.c_str());
	}

	MDS_REQUEST_REPLY("get", prospect_http_response.code(), reinterpret_cast<uint64_t>(this->reply().get()));

	headers_were_sent = true;
	send_headers(std::move(prospect_http_response)
			, std::function<void (const boost::system::error_code &)>());

	std::function<void ()> next;
	std::function<void ()> error_callback = std::bind(&req_get::on_error, shared_from_this());

	if (total_size() == data_pointer.size()) {
		if (!bad_groups.empty()) {
			if (auto write_session = server()->write_session(request(), bad_groups)) {
				{
					std::ostringstream oss;
					oss << "mds-proxy recovers file! groups=" << bad_groups;
					const auto &msg = oss.str();
					MDS_LOG_INFO("%s", msg.c_str());
				}

				write_session->set_timestamp(entry.io_attribute()->timestamp);
				write_session->write_data(key, data_pointer, 0);
			} else {
				MDS_LOG_ERROR("oops, file cannot be recovered: write-session is uninitialized");
				return;
			}
		}

		next = std::bind(&req_get::request_is_finished, shared_from_this());
	} else {
		std::function<void ()> close_callback = std::bind(&req_get::request_is_finished, shared_from_this());

		auto offset = data_pointer.size();
		auto size = total_size() - offset;

		next = std::bind(&req_get::read_and_send_range, shared_from_this()
				, offset, size, std::move(close_callback), error_callback);
	}

	send_chunk(std::move(data_pointer), std::move(next), std::move(error_callback));
}

namespace elliptics {

void
req_get::on_request(const ioremap::thevoid::http_request &http_request
		, const boost::asio::const_buffer &const_buffer) {
	(void) const_buffer;

	MDS_REQUEST_START("get", reinterpret_cast<uint64_t>(this->reply().get()));

	MDS_LOG_INFO("Get: handle request");

	if (http_request.method() != "HEAD" && http_request.method() != "GET") {
		MDS_LOG_INFO("Unsupported http method\'s type: \"%s\"", http_request.method().c_str());
		send_reply(400);
		MDS_REQUEST_REPLY("get", 400, reinterpret_cast<uint64_t>(this->reply().get()));
		return;
	}

	try {

		ns_state = server()->get_namespace_state(http_request.url().path(), "/get");
		// The method runs in thevoid's io-loop, therefore proxy's dtor cannot run in this moment
		// Hence session can be safely used without any check
		auto &&prep_session = server()->prepare_session(http_request.url().path(), ns_state);
		m_session = std::get<0>(prep_session);
		m_session->set_trace_bit(http_request.trace_bit());
		m_session->set_trace_id(http_request.request_id());
		m_session->set_timeout(server()->timeout.read);

		if (ns_settings(ns_state).check_for_update) {
			m_session->set_cflags(m_session->get_cflags() | DNET_FLAGS_NOLOCK);
		}

		key = std::get<1>(prep_session).remote();
	} catch (const std::exception &ex) {
		MDS_LOG_ERROR("Get: \"%s\"", ex.what());
		send_reply(400);
		MDS_REQUEST_REPLY("get", 400, reinterpret_cast<uint64_t>(this->reply().get()));
		return;
	}

	try {
		cached_groups = get_cached_groups();

		if (!cached_groups.empty()) {
			std::ostringstream oss;
			oss << "use cached groups for request: " << cached_groups;
			auto msg = oss.str();
			MDS_LOG_INFO("%s", msg.c_str());
		}
	} catch (const std::exception &ex) {
		MDS_LOG_ERROR("cannot get cached groups: %s", ex.what());
	}

	if (request().url().query().has_item("expiration-time")) {
		if (!ns_settings(ns_state).custom_expiration_time) {
			MDS_LOG_ERROR("using of expiration-time is prohibited");
			send_reply(403);
			MDS_REQUEST_REPLY("get", 403, reinterpret_cast<uint64_t>(this->reply().get()));
			return;
		}

		auto expiration_time_str = *request().url().query().item_value("expiration-time");

		try {
			expiration_time = std::chrono::seconds(
					boost::lexical_cast<size_t>(expiration_time_str));
		} catch (const std::exception &ex) {
			MDS_LOG_ERROR("cannot parse expiration-time: %s", ex.what());
			send_reply(400);
			MDS_REQUEST_REPLY("get", 400, reinterpret_cast<uint64_t>(this->reply().get()));
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
		MDS_REQUEST_REPLY("get", 401, reinterpret_cast<uint64_t>(this->reply().get()));

		return;
	}

	if (m_session->get_groups().empty()) {
		MDS_LOG_INFO("Get: cannot find couple of groups for the request");
		send_reply(404);
		MDS_REQUEST_REPLY("get", 404, reinterpret_cast<uint64_t>(this->reply().get()));
		return;
	}

	m_first_chunk = true;
	with_chunked_csum = false;
	headers_were_sent = false;
	some_data_were_sent = false;
	has_internal_storage_error = false;



	{
		auto ioflags = m_session->get_ioflags();
		m_session->set_ioflags(ioflags | DNET_IO_FLAGS_NOCSUM);
		m_session->set_timeout(server()->timeout.lookup);
		m_session->set_filter(ie::filters::all);
		auto session = m_session->clone();
		auto groups = session.get_groups();
		groups.insert(groups.end(), cached_groups.begin(), cached_groups.end());
		session.set_groups(groups);

		{
			std::ostringstream oss;
			oss << "lookup groups: " << groups;
			auto msg = oss.str();
			MDS_LOG_INFO("%s", msg.c_str());
		}

		parallel_lookuper_ptr = make_parallel_lookuper(
				ioremap::swarm::logger(logger(), blackhole::log::attributes_t())
				, session, key);

		m_session->set_ioflags(ioflags);
		m_session->set_filter(ie::filters::positive);

		auto next_callback = std::bind(&req_get::process_group_info
				, shared_from_this(), std::placeholders::_1);
		auto error_callback = std::bind(&req_get::on_error, shared_from_this());

		find_first_group(std::move(next_callback), std::move(error_callback));
	}
}

groups_t
req_get::get_cached_groups() {
	auto ell_key = ioremap::elliptics::key{key};
	m_session->transform(ell_key);
	auto str_ell_id = std::string{dnet_dump_id_str_full(ell_key.id().id)};

	auto groups = m_session->get_groups();
	auto couple_id = *std::min_element(groups.begin(), groups.end());

	return server()->mastermind()->get_cached_groups(str_ell_id, couple_id);
}

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
				MDS_REQUEST_REPLY("get", 412, reinterpret_cast<uint64_t>(this->reply().get()));
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
				MDS_REQUEST_REPLY("get", 412, reinterpret_cast<uint64_t>(this->reply().get()));
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
		MDS_REQUEST_REPLY("get", 304, reinterpret_cast<uint64_t>(this->reply().get()));
		return std::make_tuple(true, false);
	}

	prospect_http_response.set_code(200);
	prospect_http_response.headers().set_last_modified(timestamp);
	prospect_http_response.headers().set("ETag", etag);
	prospect_http_response.headers().set("Accept-Ranges", "bytes");

	if (request().method() == "HEAD") {
		prospect_http_response.headers().set_content_length(size);
		send_reply(std::move(prospect_http_response));
		MDS_REQUEST_REPLY("get", 200, reinterpret_cast<uint64_t>(this->reply().get()));
		MDS_REQUEST_STOP("get", reinterpret_cast<uint64_t>(this->reply().get()));
		return std::make_tuple(true, false);
	}

	return std::make_tuple(false, send_whole_file);
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

bool req_get::try_to_redirect_request(const ie::sync_lookup_result &slr, const size_t size) {

	auto redirect_arg = get_redirect_arg();

	if (redirect_arg != redirect_arg_tag::client_want_redirect) {
		auto redirect_size = ns_settings(ns_state).redirect_content_length_threshold;
		if (redirect_size == -1) {
			MDS_LOG_INFO("cannot redirect: redirect-content-length-threshold is infinity");
			return false;
		}

		if (static_cast<size_t>(redirect_size) > size) {
			std::ostringstream oss;
			oss << "cannot redirect: file is to small;"
				<< " file-size=" << size << ";"
				<< " redirect-content-length-threshold=" << redirect_size;
			auto str = oss.str();
			MDS_LOG_INFO("%s", str.c_str());
			return false;
		}
	}

	const auto &headers = request().headers();

	try {
		if (ns_settings(ns_state).sign_token.empty()) {
			MDS_LOG_INFO("cannot redirect without signature-token");

			if (redirect_arg == redirect_arg_tag::client_want_redirect) {
				throw http_error(403, "redirect=yes is not allowed for this namespace");
			}

			return false;
		}

		auto x_regional_host = headers.get("X-Regional-Host").get_value_or("");
		auto file_location = server()->get_file_location(slr, ns_state, x_regional_host);
		auto ts = make_signature_ts(expiration_time, ns_state);

		auto message = make_signature_message(file_location, ts);
		auto sign = make_signature(message, ns_settings(ns_state).sign_token);

		std::stringstream oss;
		oss << "//" << file_location.host << file_location.path << "?ts=" << ts
			<< "&sign=" << sign;

		ioremap::thevoid::http_response http_response;
		http_response.set_code(302);
		http_response.headers().set_content_length(0);

		auto location = oss.str();
		http_response.headers().set("Location", location);

		MDS_LOG_INFO("redirect request to \"%s\"", location.c_str());
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
		process_whole_file();
		return;
	}

	if (auto ranges = parse_range_header(*range_header, size)) {
		prospect_http_response.set_code(206);

		if (ranges->size() == 1) {
			const auto &range = ranges->front();

			prospect_http_response.headers().set_content_type("application/octet-stream");
			prospect_http_response.headers().set_content_length(range.size);
			prospect_http_response.headers().set("Content-Range"
					, make_content_range_header(range.offset, range.size, size));

			process_range(range.offset, range.size);
			return;
		}

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

		process_ranges(std::move(*ranges), std::move(ranges_headers));

		return;
	}

	prospect_http_response.set_code(416);
	prospect_http_response.headers().set_content_length(0);
	prospect_http_response.headers().set("Content-Range"
			, "bytes */" + boost::lexical_cast<std::string>(size));

	MDS_REQUEST_REPLY("get", prospect_http_response.code(), reinterpret_cast<uint64_t>(this->reply().get()));
	send_reply(std::move(prospect_http_response));
}

size_t
req_get::total_size() {
	if (!lookup_result_entry_opt) {
		return 0;
	}

	return lookup_result_entry_opt->file_info()->size;
}

void req_get::on_error() {
	if (headers_were_sent) {
		MDS_LOG_ERROR("error occured after headers were sent and cannot be reported to the client");
		reply()->close(boost::system::errc::make_error_code(
					boost::system::errc::operation_canceled));
		MDS_REQUEST_STOP("get", reinterpret_cast<uint64_t>(this->reply().get()));
		return;
	}

	if (!has_internal_storage_error) {
		send_reply(404);
		MDS_REQUEST_REPLY("get", 404, reinterpret_cast<uint64_t>(this->reply().get()));
	} else {
		send_reply(500);
		MDS_REQUEST_REPLY("get", 500, reinterpret_cast<uint64_t>(this->reply().get()));
	}
}

void
req_get::request_is_finished() {
	reply()->close(boost::system::error_code());
	MDS_REQUEST_STOP("get", reinterpret_cast<uint64_t>(this->reply().get()));
}

ie::session
req_get::get_session() {
	auto session = m_session->clone();

	session.set_timeout(server()->timeout.read);

	if (!with_chunked_csum) {
		if (m_first_chunk) {
			m_first_chunk = false;

			session.set_ioflags(m_session->get_ioflags() & ~DNET_IO_FLAGS_NOCSUM);
			if (server()->timeout_coef.data_flow_rate) {
				session.set_timeout(
						session.get_timeout() + total_size() / server()->timeout_coef.data_flow_rate);
			}

		} else {
			session.set_ioflags(m_session->get_ioflags() | DNET_IO_FLAGS_NOCSUM);
		}
	}

	return session;
}

}

