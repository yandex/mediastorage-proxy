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

	std::tuple<std::string, mastermind::namespace_state_t> file_info;

	try {
		file_info = server()->get_file_info(http_request);
	} catch (const std::exception &ex) {
		MDS_LOG_ERROR("cannot parse file info: %s", ex.what());
		send_reply(400);
		return;
	}

	auto ns_state = std::get<1>(file_info);

	if (!ns_state) {
		MDS_LOG_INFO("cannot determine a namespace");
		send_reply(400);
		return;
	}

	{
		if (!server()->check_basic_auth(ns_state.name()
					, proxy_settings(ns_state).auth_key_for_write
					, http_request.headers().get("Authorization"))) {
			auto token = server()->get_auth_token(http_request.headers().get("Authorization"));
			MDS_LOG_INFO("invalid token \"%s\"", token.empty() ? "<none>" : token.c_str());

			ioremap::thevoid::http_response reply;
			ioremap::swarm::http_headers headers;

			reply.set_code(401);
			headers.add("WWW-Authenticate", std::string("Basic realm=\"") + ns_state.name() + "\"");
			headers.set_content_length(0);
			reply.set_headers(headers);
			send_reply(std::move(reply));
			return;
		}
	}

	auto couple_iterator = create_couple_iterator(http_request, ns_state, total_size);

	if (!couple_iterator) {
		return;
	}

	if (auto content_type_opt = http_request.headers().content_type()) {
		int res = content_type_opt->compare(0, sizeof("multipart/form-data;") - 1
				, "multipart/form-data;");

		if (!res) {
			auto size = proxy_settings(ns_state).multipart_content_length_threshold;

			if (size != -1 && size < total_size) {
				MDS_LOG_INFO(
						"client tries to upload multipart with total_size=%d"
						", but multipart_content_length_threshold=%d"
						, static_cast<int>(total_size), static_cast<int>(size));
				send_reply(403);
				return;
			}

			request_stream = make_request_stream<upload_multipart_t>(server(), reply()
					, std::move(ns_state), couple_iterator->next().groups);
		}
	}

	if (!request_stream) {
		request_stream = make_request_stream<upload_simple_t>(server(), reply()
				, std::move(ns_state), *couple_iterator
				, std::move(std::get<0>(file_info)));
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

} // elliptics

boost::optional<elliptics::couple_iterator_t>
elliptics::upload_t::create_couple_iterator(const ioremap::thevoid::http_request &http_request
		, const mastermind::namespace_state_t &ns_state, size_t total_size) {
	if (auto arg = http_request.url().query().item_value("couple_id")) {
		if (!proxy_settings(ns_state).can_choose_couple_to_upload) {
			MDS_LOG_INFO("client wants to choose couple by himself, but you forbade that");
			send_reply(403);
			return boost::none;
		}

		int couple_id = 0;

		try {
			couple_id = boost::lexical_cast<int>(*arg);
		} catch (...) {
			MDS_LOG_INFO("couple_id is malformed: \"%s\"", arg->c_str());
			send_reply(400);
			return boost::none;
		}

		auto couple = ns_state.couples().get_couple_groups(couple_id);

		if (couple.empty()) {
			MDS_LOG_INFO("cannot obtain couple by couple_id: %d", couple_id);
			send_reply(400);
			return boost::none;
		}

		if (couple_id != *std::min_element(couple.begin(), couple.end())) {
			MDS_LOG_INFO("client tried to use no minimum group as couple_id: %d", couple_id);
			send_reply(400);
			return boost::none;
		}

		auto space = ns_state.couples().free_effective_space(couple_id);

		if (space < total_size) {
			MDS_LOG_ERROR("client chose a couple with not enough space: couple_id=%d", couple_id);
			send_reply(507);
			return boost::none;
		}

		{
			std::ostringstream oss;
			oss << couple;
			auto couple_str = oss.str();
			MDS_LOG_INFO("use couple chosen by client: %s", couple_str.c_str());
		}

		return couple_iterator_t(couple);
	} else {
		try {
			if (!proxy_settings(ns_state).static_couple.empty()) {
				return couple_iterator_t(proxy_settings(ns_state).static_couple);
			}

			return couple_iterator_t(ns_state.weights().couple_sequence(total_size));
		} catch (const mastermind::not_enough_memory_error &e) {
			MDS_LOG_ERROR("cannot obtain any couple size=%d namespace=%s : %s"
				, static_cast<int>(ns_state.settings().groups_count())
				, ns_state.name().c_str(), e.code().message().c_str());
			send_reply(507);
			return boost::none;
		} catch (const std::system_error &e) {
			MDS_LOG_ERROR("cannot obtain any couple size=%d namespace=%s : %s"
				, static_cast<int>(ns_state.settings().groups_count())
				, ns_state.name().c_str(), e.code().message().c_str());
			send_reply(500);
			return boost::none;
		}
	}
}

