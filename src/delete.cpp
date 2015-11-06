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
	(void) buffer;

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
					, ns_settings(ns_state).auth_key_for_write
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

		if (ns_settings(ns_state).check_for_update) {
			session->set_cflags(session->get_cflags() | DNET_FLAGS_NOLOCK);
		}

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

	session->set_cflags(session->get_cflags() & ~DNET_FLAGS_NOLOCK);

	const auto &entry = slr.front();
	total_size = entry.file_info()->size;

	session->set_timeout(server()->timeout.remove);

	MDS_LOG_DEBUG("Delete %s: data size %d"
			, url_str.c_str(), static_cast<int>(total_size));

	auto next = std::bind(&req_delete::on_finished, shared_from_this(), std::placeholders::_1);
	elliptics::remove(make_shared_logger(logger()), *session, key.remote(), std::move(next));
}

void req_delete::on_finished(util::expected<remove_result_t> result) {
	try {
		auto remove_result = result.get();

		if (remove_result.is_failed()) {
			send_reply(500);
			return;
		}

		if (remove_result.key_was_not_found()) {
			send_reply(404);
			return;
		}

		send_reply(200);
	} catch (const std::exception &ex) {
		MDS_LOG_ERROR("remove error: %s", ex.what());
		send_reply(500);
	}
}

} // namespace elliptics

