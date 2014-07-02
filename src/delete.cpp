#include "proxy.hpp"

namespace elliptics {
void proxy::req_delete::on_request(const ioremap::swarm::http_request &req, const boost::asio::const_buffer &buffer) {
	try {
		server()->logger().log(ioremap::swarm::SWARM_LOG_INFO, "Delete: handle request: %s", req.url().path().c_str());
		namespace_ptr_t ns;
		url_str = req.url().path();
		try {
			ns = server()->get_namespace(url_str, "/delete");
		} catch (const std::exception &ex) {
			server()->logger().log(
				ioremap::swarm::SWARM_LOG_INFO,
				"Delete: request = \"%s\", err = \"%s\"",
				url_str.c_str(), ex.what()
				);
			send_reply(400);
			return;
		}

		if (!server()->check_basic_auth(ns->name, ns->auth_key_for_write, req.headers().get("Authorization"))) {
			auto token = server()->get_auth_token(req.headers().get("Authorization"));
			server()->logger().log(ioremap::swarm::SWARM_LOG_INFO,
					"%s: invalid token \"%s\""
					, url_str.c_str(), token.empty() ? "<none>" : token.c_str());
			ioremap::swarm::http_response reply;
			ioremap::swarm::http_headers headers;

			reply.set_code(401);
			headers.add("WWW-Authenticate", std::string("Basic realm=\"") + ns->name + "\"");
			headers.add("Content-Length", "0");
			reply.set_headers(headers);
			send_reply(std::move(reply));
			return;
		}

		auto &&prep_session = server()->prepare_session(url_str, ns);
		session.reset(prep_session.first);
		key = prep_session.second;

		if (session->state_num() < server()->die_limit()) {
			throw std::runtime_error("Too low number of existing states");
		}

		session->set_timeout(server()->timeout.lookup);
		auto alr = session->read_data(key, 0, 1);
		alr.connect(std::bind(&proxy::req_delete::on_lookup,
					shared_from_this(), std::placeholders::_1, std::placeholders::_2));
	} catch (const std::exception &ex) {
		server()->logger().log(ioremap::swarm::SWARM_LOG_ERROR, "Delete request error: %s", ex.what());
		send_reply(500);
	} catch (...) {
		server()->logger().log(ioremap::swarm::SWARM_LOG_ERROR, "Delete request error: unknown");
		send_reply(500);
	}
}

void proxy::req_delete::on_lookup(const ioremap::elliptics::sync_read_result &slr, const ioremap::elliptics::error_info &error) {

	if (error) {
		server()->logger().log(ioremap::swarm::SWARM_LOG_ERROR, "%s", error.message().c_str());
		send_reply(error.code() == -ENOENT ? 404 : 500);
		return;
	}

	const auto &entry = slr.front();
	total_size = entry.io_attribute()->total_size;

	session->set_filter(ioremap::elliptics::filters::all);
	session->set_timeout(server()->timeout.remove);

	server()->logger().log(ioremap::swarm::SWARM_LOG_DEBUG, "Delete: removing data");
	session->remove(key).connect(std::bind(&req_delete::on_finished, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
}

void proxy::req_delete::on_finished(const ioremap::elliptics::sync_remove_result &srr, const ioremap::elliptics::error_info &error) {
	(void)srr;
	if (error) {
		server()->logger().log(ioremap::swarm::SWARM_LOG_ERROR, "%s", error.message().c_str());
		send_reply(error.code() == -ENOENT ? 404 : 500);
		return;
	}
	server()->logger().log(ioremap::swarm::SWARM_LOG_INFO,
			"Delete %s: successfully remove %d bytes",
			url_str.c_str(), static_cast<int>(total_size));
	send_reply(200);
}
} // namespace elliptics

