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

#include "proxy.hpp"
#include "data_container.hpp"
#include "lookup_result.hpp"

#include "upload.hpp"
#include "upload_p.hpp"

#include <swarm/url.hpp>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include <cstdio>
#include <cstring>

#include <sstream>
#include <fstream>
#include <algorithm>
#include <limits>
#include <string>

namespace elliptics {

void
upload_t::on_headers(ioremap::thevoid::http_request &&http_request) {
	size_t total_size = 0;

	if (const auto &arg = http_request.headers().content_length()) {
		total_size = *arg;
	} else {
		MDS_LOG_INFO("missing Content-Length");
		send_reply(400);
		return;
	}

	if (total_size == 0) {
		MDS_LOG_INFO("Content-Length must be greater than zero");
		send_reply(400);
		return;
	}

	MDS_LOG_INFO("body size: %lu", total_size);

	{
		std::ostringstream oss;
		const auto &headers = http_request.headers().all();
		oss << "Headers:" << std::endl;
		for (auto it = headers.begin(); it != headers.end(); ++it) {
			oss << it->first << ": " << it->second << std::endl;
		}
		MDS_LOG_DEBUG("%s", oss.str().c_str());
	}

	auto file_info = server()->get_file_info(http_request);

	auto ns = file_info.second;

	if (ns->name.empty()) {
		MDS_LOG_INFO("cannot determine a namespace");
		send_reply(400);
		return;
	}

	{
		if (!server()->check_basic_auth(ns->name, ns->auth_key_for_write
					, http_request.headers().get("Authorization"))) {
			auto token = server()->get_auth_token(http_request.headers().get("Authorization"));
			MDS_LOG_INFO("invalid token \"%s\"", token.empty() ? "<none>" : token.c_str());

			ioremap::thevoid::http_response reply;
			ioremap::swarm::http_headers headers;

			reply.set_code(401);
			headers.add("WWW-Authenticate", std::string("Basic realm=\"") + ns->name + "\"");
			headers.set_content_length(0);
			reply.set_headers(headers);
			send_reply(std::move(reply));
			return;
		}
	}

	couple_t couple;

	if (auto arg = http_request.url().query().item_value("couple_id")) {
		if (!ns->can_choose_couple_to_upload) {
			MDS_LOG_INFO("client wants to choose couple by himself, but you forbade that");
			send_reply(403);
			return;
		}

		int couple_id = 0;

		try {
			couple_id = boost::lexical_cast<int>(*arg);
		} catch (...) {
			MDS_LOG_INFO("couple_id is malformed: \"%s\"", arg->c_str());
			send_reply(400);
			return;
		}

		couple = server()->mastermind()->get_couple(couple_id, ns->name);

		if (couple.empty()) {
			MDS_LOG_INFO("cannot obtain couple by couple_id: %d", couple_id);
			send_reply(400);
			return;
		}

		if (couple_id != *std::min_element(couple.begin(), couple.end())) {
			MDS_LOG_INFO("client tried to use no minimum group as couple_id: %d", couple_id);
			send_reply(400);
			return;
		}

		auto space = server()->mastermind()->free_effective_space_in_couple_by_group(couple_id);

		if (space < total_size) {
			MDS_LOG_ERROR("client chose a couple with not enough space: couple_id=%d", couple_id);
			send_reply(507);
			return;
		}

		{
			std::ostringstream oss;
			oss << couple;
			auto couple_str = oss.str();
			MDS_LOG_INFO("use couple chosen by client: %s", couple_str.c_str());
		}

	} else {
		try {
			couple = server()->groups_for_upload(ns, total_size);
		} catch (const mastermind::not_enough_memory_error &e) {
			MDS_LOG_ERROR("cannot obtain any couple size=%d namespace=%s : %s"
				, static_cast<int>(ns->groups_count), ns->name.c_str(), e.code().message().c_str());
			send_reply(507);
			return;
		} catch (const std::system_error &e) {
			MDS_LOG_ERROR("cannot obtain any couple size=%d namespace=%s : %s"
				, static_cast<int>(ns->groups_count), ns->name.c_str(), e.code().message().c_str());
			send_reply(500);
			return;
		}
	}

	if (auto content_type_opt = http_request.headers().content_type()) {
		int res = content_type_opt->compare(0, sizeof("multipart/form-data;") - 1
				, "multipart/form-data;");

		if (!res) {
			auto size = ns->multipart_content_length_threshold;

			if (size != -1 && size < total_size) {
				MDS_LOG_INFO(
						"client tries to upload multipart with total_size=%d"
						", but multipart_content_length_threshold=%d"
						, static_cast<int>(total_size), static_cast<int>(size));
				send_reply(403);
				return;
			}

			request_stream = make_request_stream<upload_multipart_t>(server(), reply()
					, std::move(ns), std::move(couple));
		}
	}

	if (!request_stream) {
		request_stream = make_request_stream<upload_simple_t>(server(), reply()
				, std::move(ns), std::move(couple), std::move(file_info.first));
	}

	request_stream->on_headers(std::move(http_request));
}

size_t
upload_t::on_data(const boost::asio::const_buffer &buffer) {
	return request_stream->on_data(buffer);
}

void
upload_t::on_close(const boost::system::error_code &error) {
	request_stream->on_close(error);
}

upload_helper_t::upload_helper_t(ioremap::swarm::logger bh_logger_
		, const ioremap::elliptics::session &session_, std::string key_
		, size_t total_size_, size_t offset_, size_t commit_coef_, size_t success_copies_num_
		)
	: bh_logger(std::move(bh_logger_))
	, session(session_.clone())
	, key(std::move(key_))
	, total_size(total_size_)
	, written_size(0)
	, offset(offset_)
	, commit_coef(commit_coef_)
	, success_copies_num(success_copies_num_)
	, start_time(std::chrono::system_clock::now())
{
	session.set_filter(ioremap::elliptics::filters::all_with_ack);
	session.set_checker(ioremap::elliptics::checkers::at_least_one);

	key.transform(session);
	key.set_id(key.id());

	{
		std::ostringstream oss;
		oss
			<< "upload start:"
			<< " key=" << key.remote()
			// The only reason to print elliptics key is ioremap::elliptics::key::transform
			// method doesn't log this information
			<< " elliptics-key=" << key.to_string()
			<< " offset=" << offset
			<< " total-size=" << total_size
			<< " groups=" << session.get_groups()
			<< " success-copiens-num=" << success_copies_num;

		auto msg = oss.str();

		MDS_LOG_INFO("%s", msg.c_str());
	}
}

void
upload_helper_t::write(const char *data, size_t size, callback_t on_wrote, callback_t on_error) {
	write(ioremap::elliptics::data_pointer::from_raw(
			reinterpret_cast<void *>(const_cast<char *>(data)), size)
			, std::move(on_wrote), std::move(on_error));
}

void
upload_helper_t::write(const ioremap::elliptics::data_pointer &data_pointer
		, callback_t on_wrote, callback_t on_error) {
	if (written_size == 0 && data_pointer.size() >= total_size) {
		log_chunk_upload("simple", data_pointer.size());
		auto async_result = session.write_data(key, data_pointer, offset);
		written_size = data_pointer.size();

		async_result.connect(std::bind(&upload_helper_t::on_data_wrote
					, shared_from_this(), std::placeholders::_1, std::placeholders::_2
					, std::move(on_wrote), std::move(on_error)));
		return;
	}

	auto async_result = write_impl(data_pointer);
	written_size += data_pointer.size();
	offset += data_pointer.size();

	async_result.connect(std::bind(&upload_helper_t::on_data_wrote
				, shared_from_this(), std::placeholders::_1, std::placeholders::_2
				, std::move(on_wrote), std::move(on_error)));
}

bool
upload_helper_t::is_finished() const {
	return written_size >= total_size;
}

const upload_helper_t::entries_info_t &
upload_helper_t::upload_result() const {
	return entries_info;
}

ioremap::swarm::logger &
upload_helper_t::logger() {
	return bh_logger;
}

ioremap::elliptics::async_write_result
upload_helper_t::write_impl(const ioremap::elliptics::data_pointer &data_pointer) {
	if (written_size == 0) {
		log_chunk_upload("prepare", data_pointer.size());
		return session.write_prepare(key, data_pointer, offset, total_size);
	} else {
		size_t future_size = written_size + data_pointer.size();
		if (future_size >= total_size) {
			session.set_timeout(session.get_timeout() * commit_coef);
			log_chunk_upload("commit", data_pointer.size());
			return session.write_commit(key, data_pointer, offset, future_size);
		} else {
			log_chunk_upload("plain", data_pointer.size());
			return session.write_plain(key, data_pointer, offset);
		}
	}
}

void
upload_helper_t::log_chunk_upload(const std::string &write_type, size_t chunk_size) {
	std::ostringstream oss;
	oss
		<< "upload chunk:"
		<< " key=" << key.remote()
		<< " total-size=" << total_size
		<< " offset=" << offset
		<< " chunk-size=" << chunk_size
		<< " data-left=" << (total_size - offset)
		<< " write-type=" << write_type;

	auto msg = oss.str();

	MDS_LOG_INFO("%s", msg.c_str());
}

void
upload_helper_t::update_groups(const ioremap::elliptics::sync_write_result &entries) {
	std::vector<int> good_groups;

	for (auto it = entries.begin(), end = entries.end(); it != end; ++it) {
		auto &entry = *it;

		int group_id = entry.command()->id.group_id;

		if (entry.status() == 0) {
			good_groups.emplace_back(group_id);
		} else {
			bad_groups.emplace_back(group_id);
		}
	}

	session.set_groups(good_groups);

	{
		std::ostringstream oss;
		oss
			<< "upload of chunk is finished:"
			<< " key=" << key.remote()
			<< " good-groups=" << good_groups
			<< " bad-groups=" << bad_groups;

		auto msg = oss.str();

		MDS_LOG_INFO("%s", msg.c_str());
	}
}

void
upload_helper_t::set_upload_result(const ioremap::elliptics::sync_write_result &entries) {
	for (auto it = entries.begin(), end = entries.end(); it != end; ++it) {
		lookup_result pl(*it, "");
		if (pl.status() != 0) {
			continue;
		}

		entry_info_t entry_info;

		entry_info.address = pl.addr();
		entry_info.path = pl.full_path();
		entry_info.group = pl.group();

		entries_info.emplace_back(std::move(entry_info));
	}
}

bool
upload_helper_t::upload_is_good(const ioremap::elliptics::error_info &error_info) {
	return !error_info && session.get_groups().size() >= success_copies_num;
}

void
upload_helper_t::on_data_wrote(const ioremap::elliptics::sync_write_result &entries
		, const ioremap::elliptics::error_info &error_info
		, callback_t on_wrote, callback_t on_error) {
	update_groups(entries);

#define LOG_RESULT(VERBOSITY, STATUS) \
	do { \
		auto spent_time = std::chrono::duration_cast<std::chrono::milliseconds>( \
				std::chrono::system_clock::now() - start_time).count(); \
		 \
		std::ostringstream oss; \
		oss \
			<< "upload is finished:" \
			<< " key=" << key.remote() \
			<< " spent-time=" << spent_time << "ms" \
			<< " status=" << STATUS \
			<< " wrote into groups " << session.get_groups() \
			<< " failed to write into groups " << bad_groups; \
		 \
		auto msg = oss.str(); \
		MDS_LOG_##VERBOSITY("%s", msg.c_str()); \
	} while (0)


	if (upload_is_good(error_info)) {
		if (written_size >= total_size) {
			LOG_RESULT(INFO, "ok");
			set_upload_result(entries);
		}

		on_wrote();
		return;
	}

	LOG_RESULT(ERROR, "bad");

	on_error();
#undef LOG_RESULT
}

upload_buffer_t::upload_buffer_t(ioremap::swarm::logger bh_logger_, std::string key_
		, size_t chunk_size_)
	: bh_logger(std::move(bh_logger_))
	, key(std::move(key_))
	, chunk_size(chunk_size_)
	, total_size(0)
	, is_stopped(false)
{
}

bool
upload_buffer_t::append(const char *data, size_t size) {
	total_size += size;

	{
		size_t buffers_size = 0;

		if (!buffers.empty()) {
			buffers_size += (buffers.size() - 1) * chunk_size;
			buffers_size += buffers.back().size();
		}
		MDS_LOG_INFO("buffer append: key=%s append-size=%llu buffer-size=%llu total-size=%llu"
				, key.c_str(), size, buffers_size, total_size);
	}

	while (size != 0) {
		if (buffers.empty() || buffers.back().size() >= chunk_size) {
			buffer_t buffer;
			buffer.reserve(chunk_size);

			buffers.emplace_back(std::move(buffer));
		}

		auto &buffer = buffers.back();
		auto buffer_size = buffer.size();

		auto part_size = std::min(size, chunk_size - buffer_size);
		buffer.insert(buffer.end(), data, data + part_size);

		data += part_size;
		size -= part_size;
	}

	return true;
}

void
upload_buffer_t::write(const ioremap::elliptics::session &session, size_t commit_coef
		, size_t success_copies_num
		, on_wrote_callback_t on_wrote_callback, on_error_callback_t on_error_callback) {
	upload_helper = std::make_shared<upload_helper_t>(
			ioremap::swarm::logger(logger(), blackhole::log::attributes_t())
			, session, key, total_size, 0, commit_coef
			, success_copies_num
			);

	write_impl(std::move(on_wrote_callback), std::move(on_error_callback));
}

void
upload_buffer_t::stop() {
	is_stopped = true;
}

const std::string &
upload_buffer_t::get_key() const {
	return key;
}

ioremap::swarm::logger &
upload_buffer_t::logger() {
	return bh_logger;
}

void
upload_buffer_t::write_impl(on_wrote_callback_t on_wrote_callback_
		, const on_error_callback_t &on_error_callback) {
	if (is_stopped) {
		buffers.clear();
		on_wrote_callback_(upload_helper);
		return;
	}

	upload_helper_t::callback_t on_wrote_callback;

	if (buffers.size() == 1) {
		on_wrote_callback = std::bind(on_wrote_callback_, upload_helper);
	} else {
		on_wrote_callback = std::bind(&upload_buffer_t::write_impl, shared_from_this()
				, std::move(on_wrote_callback_), on_error_callback);
	}

	{
		const auto &buffer = buffers.front();
		upload_helper->write(buffer.data(), buffer.size(), std::move(on_wrote_callback)
				, on_error_callback);
		buffers.pop_front();
	}
}

} // elliptics

