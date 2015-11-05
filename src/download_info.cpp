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

#include "download_info.hpp"
#include "error.hpp"

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
	(void) buffer;

	MDS_LOG_INFO("Download info: handle request: %s", req.url().path().c_str());

	try {
		ns_state = get_namespace_state(req.url().path(), handler_name);
		check_signature();
		check_query_args();

		boost::optional<ioremap::elliptics::session> session;
		boost::optional<ioremap::elliptics::key> key;

		// The method runs in thevoid's io-loop, therefore proxy's dtor cannot run
		// in this moment. Hence session can be safely used without any check.
		std::tie(session, key) = prepare_session(ns_state);

		if (ns_settings(ns_state).check_for_update) {
			session->set_cflags(session->get_cflags() | DNET_FLAGS_NOLOCK);
		}

		{
			const auto &headers = req.headers();
			if (const auto &xrh = headers.get("X-Regional-Host")) {
				x_regional_host = *xrh;
			}
		}

		if (req.method() == "GET") {
			process_get(*session, *key);
		} else {
			throw http_error(405, "Method " + req.method() + " is not allowed");
		}
	} catch (const http_error &ex) {
		std::ostringstream oss;
		oss
			<< "http_error: http_status = " << ex.http_status()
			<< " ; description = " << ex.what();
		auto msg = oss.str();

		if (ex.is_server_error()) {
			MDS_LOG_ERROR("%s", msg.c_str());
		} else {
			MDS_LOG_INFO("%s", msg.c_str());
		}

		send_reply(ex.http_status());
	} catch (const std::exception &ex) {
		MDS_LOG_ERROR("uncaughted exception: http_status = 500 ; description = %s", ex.what());
		send_reply(500);
	}
}

void
elliptics::download_info_t::on_finished(const ioremap::elliptics::sync_lookup_result &slr
		, const ioremap::elliptics::error_info &error) {
	MDS_LOG_DEBUG("Download info: prepare response");

	try {
		if (error) {
			auto http_status = (error.code() == -ENOENT ? 404 : 500);
			throw http_error(http_status, error.message());
		}

		auto res = server()->generate_signature_for_elliptics_file(slr, x_regional_host
				, ns_state, expiration_time);

		send_response(std::move(res));
	} catch (const http_error &ex) {
		std::ostringstream oss;
		oss
			<< "http_error: http_status = " << ex.http_status()
			<< " ; description = " << ex.what();
		auto msg = oss.str();

		if (ex.is_server_error()) {
			MDS_LOG_ERROR("%s", msg.c_str());
		} else {
			MDS_LOG_INFO("%s", msg.c_str());
		}

		send_reply(ex.http_status());
	} catch (const std::exception &ex) {
		MDS_LOG_ERROR("uncaughted exception: http_status = 500 ; description = %s", ex.what());
		send_reply(500);
	}
}

mastermind::namespace_state_t
elliptics::download_info_t::get_namespace_state(const std::string &path
		, const std::string &handler) {
	try {
		return server()->get_namespace_state(path, handler);
	} catch (const std::exception &ex) {
		throw http_error(400, ex.what());
	}
}

void
elliptics::download_info_t::check_signature() {
	if (ns_settings(ns_state).sign_token.empty()) {
		throw http_error(403, "cannot generate downloadinfo xml without signature-token");
	}
}

void
elliptics::download_info_t::check_query_args() {
	const auto &query = request().url().query();

	{
		auto format = get_arg<std::string>(query, "format", "xml");

		if (format != "xml" && format != "json" && format != "jsonp") {
			throw http_error(400, "unknown format=" + format);
		}
	}

	if (query.has_item("expiration-time")) {
		if (!ns_settings(ns_state).custom_expiration_time) {
			throw http_error(403, "using of expiration-time is prohibited");
		}

		auto expiration_time_str = *query.item_value("expiration-time");

		try {
			expiration_time = std::chrono::seconds(
					boost::lexical_cast<size_t>(expiration_time_str));
		} catch (const std::exception &ex) {
			throw http_error(400, std::string("cannot parse expiration-time: ") + ex.what());
		}
	}
}

std::tuple<boost::optional<ioremap::elliptics::session>, ioremap::elliptics::key>
elliptics::download_info_t::prepare_session(const mastermind::namespace_state_t &ns_state) {
	try {
		auto prep_session = server()->prepare_session(request().url().path(), ns_state);

		if (std::get<0>(prep_session)->get_groups().empty()) {
			throw proxy_error("session was obtained without groups");
		}

		std::get<0>(prep_session)->set_trace_bit(request().trace_bit());
		std::get<0>(prep_session)->set_trace_id(request().request_id());

		std::get<0>(prep_session)->set_filter(ioremap::elliptics::filters::all);
		std::get<0>(prep_session)->set_timeout(server()->timeout.lookup);

		return prep_session;
	} catch (const std::exception &ex) {
		throw http_error(400, ex.what());
	}
}

void
elliptics::download_info_t::process_get(ioremap::elliptics::session session
		, const ioremap::elliptics::key key) {
	MDS_LOG_DEBUG("Download info: looking up");
	auto alr = session.quorum_lookup(key);

	alr.connect(wrap(std::bind(&download_info_t::on_finished, shared_from_this()
					, std::placeholders::_1, std::placeholders::_2)));
}

void
elliptics::download_info_t::send_response(
		std::tuple<std::string, std::string, std::string, std::string> res) {
	ioremap::thevoid::http_response reply;
	ioremap::swarm::http_headers headers;
	reply.set_code(200);
	std::string body;

	auto format = get_arg<std::string>(request().url().query(), "format", "xml");

	if (format == "xml") {
		headers.set_content_type("text/xml");
		body = xml_response(std::move(res));
	} else if (format == "json") {
		headers.set_content_type("application/json");
		body = json_response(std::move(res));
	} else if (format == "jsonp") {
		headers.set_content_type("application/javascript");
		body = jsonp_response(std::move(res));
	}

	headers.set_content_length(body.size());
	reply.set_headers(headers);
	send_reply(std::move(reply), std::move(body));
}

std::string
elliptics::download_info_t::xml_response(
		std::tuple<std::string, std::string, std::string, std::string> res) {
	std::stringstream oss;
	oss << "<?xml version=\"1.0\" encoding=\"utf-8\"?>";
	oss << "<download-info>";
	oss << "<host>" << std::get<0>(res) << "</host>";
	oss << "<path>" << std::get<1>(res) << "</path>";
	oss << "<ts>" << std::get<2>(res) << "</ts>";
	oss << "<region>-1</region>";
	oss << "<s>" << std::get<3>(res) << "</s>";
	oss << "</download-info>";
	return oss.str();
}

kora::dynamic_t
elliptics::download_info_t::json_response_impl(
		std::tuple<std::string, std::string, std::string, std::string> res) {
	auto dynamic = kora::dynamic_t::empty_object;
	auto &object = dynamic.as_object();
	object["host"] = std::get<0>(res);
	object["path"] = std::get<1>(res);
	object["ts"] = std::get<2>(res);
	object["s"] = std::get<3>(res);
	return dynamic;
}

std::string
elliptics::download_info_t::json_response(
		std::tuple<std::string, std::string, std::string, std::string> res) {
	return kora::to_pretty_json(json_response_impl(std::move(res)));
}

std::string
elliptics::download_info_t::jsonp_response(
		std::tuple<std::string, std::string, std::string, std::string> res) {
	std::ostringstream oss;
	oss << get_arg<std::string>(request().url().query(), "callback", "");
	oss << "(" << json_response_impl(std::move(res)) << ")";
	return oss.str();
}

