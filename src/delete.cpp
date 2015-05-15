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

#include "delete.hpp"

namespace elliptics {
void req_delete::on_request(const ioremap::thevoid::http_request &req, const boost::asio::const_buffer &buffer) {
	try {
		MDS_LOG_INFO("Delete: handle request: %s", req.url().path().c_str());
		mastermind::namespace_state_t ns_state;
		url_str = req.url().path();
		try {
			ns_state = server()->get_namespace_state(url_str, "/delete");

			// The method runs in thevoid's io-loop, therefore proxy's dtor cannot run in this moment
			// Hence session can be safely used without any check
			auto &&prep_session = server()->prepare_session(url_str, ns_state);
			session = std::get<0>(prep_session);
			session->set_trace_bit(req.trace_bit());
			session->set_trace_id(req.request_id());
			key = std::get<1>(prep_session);
		} catch (const std::exception &ex) {
			MDS_LOG_INFO("Delete: request = \"%s\", err = \"%s\"", url_str.c_str(), ex.what());
			send_reply(400);
			return;
		}

		if (!server()->check_basic_auth(ns_state.name()
					, proxy_settings(ns_state).auth_key_for_write
					, req.headers().get("Authorization"))) {
			auto token = server()->get_auth_token(req.headers().get("Authorization"));
			MDS_LOG_INFO("%s: invalid token \"%s\"", url_str.c_str()
					, token.empty() ? "<none>" : token.c_str());
			ioremap::thevoid::http_response reply;
			ioremap::swarm::http_headers headers;

			reply.set_code(401);
			headers.add("WWW-Authenticate", std::string("Basic realm=\"") + ns_state.name() + "\"");
			headers.add("Content-Length", "0");
			reply.set_headers(headers);
			send_reply(std::move(reply));
			return;
		}

		if (session->state_num() < server()->die_limit()) {
			throw std::runtime_error("Too low number of existing states");
		}

		session->set_timeout(server()->timeout.lookup);
		session->set_filter(ioremap::elliptics::filters::positive);
		auto alr = session->quorum_lookup(key);
		alr.connect(wrap(std::bind(&req_delete::on_lookup,
					shared_from_this(), std::placeholders::_1, std::placeholders::_2)));
	} catch (const std::exception &ex) {
		MDS_LOG_ERROR("Delete request=\"%s\" error: %s"
				, url_str.c_str(), ex.what());
		send_reply(500);
	} catch (...) {
		MDS_LOG_ERROR("Delete request=\"%s\" error: unknown"
				, url_str.c_str());
		send_reply(500);
	}
}

void req_delete::on_lookup(const ioremap::elliptics::sync_lookup_result &slr, const ioremap::elliptics::error_info &error) {

	if (error) {
		MDS_LOG_ERROR("Delete request=\"%s\" lookup error: %s"
				, url_str.c_str(), error.message().c_str());
		send_reply(error.code() == -ENOENT ? 404 : 500);
		return;
	}

	const auto &entry = slr.front();
	total_size = entry.file_info()->size;

	// all_with_ack because all doesn't mean all in some cases e.g. remove act
	session->set_filter(ioremap::elliptics::filters::all_with_ack);
	session->set_timeout(server()->timeout.remove);

	MDS_LOG_DEBUG("Delete %s: data size %d"
			, url_str.c_str(), static_cast<int>(total_size));
	session->remove(key).connect(wrap(std::bind(&req_delete::on_finished, shared_from_this(), std::placeholders::_1, std::placeholders::_2)));
}

void req_delete::on_finished(const ioremap::elliptics::sync_remove_result &srr, const ioremap::elliptics::error_info &error) {
	(void) error;

	bool has_bad_response = false;
	size_t enoent_count = 0;

	for (auto it = srr.begin(), end = srr.end(); it != end; ++it) {
		int status = it->status();
		int group = it->command()->id.group_id;
		const auto &err = it->error();
		if (status != 0) {
			MDS_LOG_INFO("Delete request=\"%s\" group=%d status=%d error=\"%s\""
					, url_str.c_str(), group, status, err.message().c_str());
			if (status != -ENOENT) {
				has_bad_response = true;
			} else {
				enoent_count += 1;
			}
		} else {
			MDS_LOG_INFO("Delete request=\"%s\" group=%d status=0", url_str.c_str(), group);
		}
	}

	// The reason for this check: ELL-250
	if (srr.size() != session->get_groups().size()) {
		MDS_LOG_ERROR("Delete request=\"%s\" unknown client errors"
				, url_str.c_str());
		has_bad_response = true;
	}

	if (has_bad_response) {
		MDS_LOG_ERROR("Delete request=\"%s\" remove is failed"
				, url_str.c_str());
		send_reply(500);
		return;
	}

	if (enoent_count == srr.size()) {
		MDS_LOG_ERROR("Delete request=\"%s\" key not found"
				, url_str.c_str());
		send_reply(404);
		return;
	}

	MDS_LOG_INFO("Delete request=\"%s\" remove is done"
			, url_str.c_str());
	send_reply(200);
	return;
}
} // namespace elliptics

