#include "download_info.hpp"

const std::string elliptics::download_info_1_t::handler_name = "downloadinfo";
const std::string elliptics::download_info_2_t::handler_name = "download-info";

elliptics::download_info_1_t::download_info_1_t()
	: download_info_t(handler_name)
{}

elliptics::download_info_2_t::download_info_2_t()
	: download_info_t(handler_name)
{}

elliptics::download_info_t::download_info_t(const std::string &handler_name_)
	: handler_name('/' + handler_name_)
{}

void
elliptics::download_info_t::on_request(const ioremap::thevoid::http_request &req
		, const boost::asio::const_buffer &buffer) {
	try {
		MDS_LOG_INFO("Download info: handle request: %s", req.url().path().c_str());
		const auto &url = req.url().path();
		try {
			ns_state = server()->get_namespace_state(url, handler_name);
		} catch (const std::exception &ex) {
			MDS_LOG_INFO("Download info: request = \"%s\"; err: \"%s\"", url.c_str(), ex.what());
			send_reply(400);
			return;
		}

		if (proxy_settings(ns_state).sign_token.empty()) {
			MDS_LOG_INFO("cannot generate downloadinfo xml without signature-token");
			send_reply(403);
			return;
		}

		{
			const auto &query = request().url().query();

			{
				auto format = get_arg<std::string>(query, "format", "xml");

				if (format != "xml" && format != "json" && format != "jsonp") {
					MDS_LOG_ERROR("unknown format=%s", format.c_str());
					send_reply(400);
					return;
				}
			}

			if (query.has_item("expiration-time")) {
				if (!proxy_settings(ns_state).custom_expiration_time) {
					MDS_LOG_ERROR("using of expiration-time is prohibited");
					send_reply(403);
					return;
				}

				auto expiration_time_str = *query.item_value("expiration-time");

				try {
					expiration_time = std::chrono::seconds(
							boost::lexical_cast<size_t>(expiration_time_str));
				} catch (const std::exception &ex) {
					MDS_LOG_ERROR("cannot parse expiration-time: %s", ex.what());
					send_reply(400);
					return;
				}
			}
		}

		boost::optional<ioremap::elliptics::session> session;
		boost::optional<ioremap::elliptics::key> key;

		try {
			// The method runs in thevoid's io-loop, therefore proxy's dtor cannot run in this moment
			// Hence session can be safely used without any check
			auto &&prep_session = server()->prepare_session(url, ns_state);
			session = std::get<0>(prep_session);
			session->set_trace_bit(req.trace_bit());
			session->set_trace_id(req.request_id());
			key.reset(std::get<1>(prep_session));
		} catch (const std::exception &ex) {
			MDS_LOG_INFO("Download info request error: %s", ex.what());
			send_reply(400);
			return;
		}

		{
			const auto &headers = req.headers();
			if (const auto &xrh = headers.get("X-Regional-Host")) {
				x_regional_host = *xrh;
			}
		}

		if (session->get_groups().empty()) {
			send_reply(404);
			return;
		}

		session->set_filter(ioremap::elliptics::filters::all);
		session->set_timeout(server()->timeout.lookup);

		MDS_LOG_DEBUG("Download info: looking up");
		auto alr = session->quorum_lookup(*key);

		alr.connect(wrap(std::bind(&download_info_t::on_finished, shared_from_this(), std::placeholders::_1, std::placeholders::_2)));
	} catch (const std::exception &ex) {
		MDS_LOG_ERROR("Download info request error: %s", ex.what());
		send_reply(500);
	} catch (...) {
		MDS_LOG_ERROR("Download info request error: unknown");
		send_reply(500);
	}
}

void
elliptics::download_info_t::on_finished(const ioremap::elliptics::sync_lookup_result &slr
		, const ioremap::elliptics::error_info &error) {
	try {
		MDS_LOG_DEBUG("Download info: prepare response");
		if (error) {
			MDS_LOG_ERROR("%s", error.message().c_str());
			send_reply(error.code() == -ENOENT ? 404 : 500);
			return;
		}

		auto res = server()->generate_signature_for_elliptics_file(slr, x_regional_host
				, ns_state, expiration_time);

		ioremap::thevoid::http_response reply;
		ioremap::swarm::http_headers headers;
		reply.set_code(200);
		std::string body;

		auto format = get_arg<std::string>(request().url().query(), "format", "xml");

		if (format == "xml") {
			headers.set_content_type("text/xml");

			std::stringstream oss;
			oss << "<?xml version=\"1.0\" encoding=\"utf-8\"?>";
			oss << "<download-info>";
			oss << "<host>" << std::get<0>(res) << "</host>";
			oss << "<path>" << std::get<1>(res) << "</path>";
			oss << "<ts>" << std::get<2>(res) << "</ts>";
			oss << "<region>-1</region>";
			oss << "<s>" << std::get<3>(res) << "</s>";
			oss << "</download-info>";

			body = oss.str();
		} else if (format == "json" || format == "jsonp") {
			auto dynamic = kora::dynamic_t::empty_object;
			auto &object = dynamic.as_object();
			object["host"] = std::get<0>(res);
			object["path"] = std::get<1>(res);
			object["ts"] = std::get<2>(res);
			object["s"] = std::get<3>(res);

			if (format == "json") {
				headers.set_content_type("application/json");
				body = kora::to_pretty_json(dynamic);
			} else {
				headers.set_content_type("application/javascript");
				std::ostringstream oss;
				oss << get_arg<std::string>(request().url().query(), "callback", "");
				oss << "(" << dynamic << ")";
				body = oss.str();
			}
		}

		headers.set_content_length(body.size());
		reply.set_headers(headers);
		send_reply(std::move(reply), std::move(body));

	} catch (const std::exception &ex) {
		MDS_LOG_ERROR("Download info finish error: %s", ex.what());
		send_reply(500);
	} catch (...) {
		MDS_LOG_ERROR("Download info finish error: unknown");
		send_reply(500);
	}
}

