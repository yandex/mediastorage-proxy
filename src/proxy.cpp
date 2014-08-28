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
#include "lookup_result.hpp"
#include "data_container.hpp"

#include <swarm/url.hpp>
#include <swarm/logger.hpp>

#include <glib.h>

#include <stdexcept>
#include <iterator>
#include <algorithm>
#include <functional>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <utility>
#include <cstring>
#include <cstdio>

#include <boost/lexical_cast.hpp>

#include <iostream>

namespace elliptics {

const std::string proxy::req_download_info_1::handler_name = "downloadinfo";
const std::string proxy::req_download_info_2::handler_name = "download-info";

proxy::req_download_info_1::req_download_info_1()
	: req_download_info(handler_name)
{}

proxy::req_download_info_2::req_download_info_2()
	: req_download_info(handler_name)
{}

} // namespace elliptics

namespace {

int get_int(const rapidjson::Value &config, const char *name, int def_val = 0) {
	return config.HasMember(name) ? config[name].GetInt() : def_val;
}

bool get_bool(const rapidjson::Value &config, const char *name, bool def_val = false) {
	return config.HasMember(name) ? config[name].GetBool() : def_val;
}

std::string get_string(const rapidjson::Value &config, const char *name, const std::string &def_val = std::string()) {
	return config.HasMember(name) ? config[name].GetString() : def_val;
}

ioremap::elliptics::session generate_session(const ioremap::elliptics::node &node) {
	ioremap::elliptics::session session(node);

	session.set_error_handler(ioremap::elliptics::error_handlers::none);

	return session;
}

std::map<std::string, elliptics::namespace_ptr_t> generate_namespaces(std::shared_ptr<mastermind::mastermind_t> &m_mastermind) {
	std::map<std::string, elliptics::namespace_ptr_t> res;
	auto nms = m_mastermind->get_namespaces_settings();

	for (auto it = nms.begin(); it != nms.end(); ++it) {
		elliptics::namespace_t item;

		item.name = it->name();
		item.groups_count = it->groups_count();
		item.auth_key_for_write = it->auth_key_for_write();
		item.auth_key_for_read = it->auth_key_for_read();
		item.static_couple = it->static_couple();
		item.sign_token = it->sign_token();
		item.sign_path_prefix = it->sign_path_prefix();
		item.sign_port = it->sign_port();

		const std::string &scn = it->success_copies_num();

		if (scn == "all") {
			item.result_checker = ioremap::elliptics::checkers::all;
		} else if (scn == "quorum") {
			item.result_checker = ioremap::elliptics::checkers::quorum;
		} else if (scn == "any"){
			item.result_checker = ioremap::elliptics::checkers::at_least_one;
		} else {
			std::ostringstream oss;
			oss << "Unknown type of success-copies-num \'" << scn << "\' in \'" << item.name << "\' namespace. Allowed types: any, quorum, all.";
			throw std::runtime_error(oss.str());
		}

		res.insert(std::map<std::string, elliptics::namespace_ptr_t>::value_type(
			item.name, std::make_shared<elliptics::namespace_t>(item)));
	}

	return res;
}

std::pair<std::string, std::string> get_filename(const ioremap::swarm::http_request &req) {
	auto scriptname = req.url().path();
	auto begin = scriptname.find('/', 1) + 1;
	auto end = scriptname.find('?', begin);
	auto filename = scriptname.substr(begin, end - begin);

	auto namespace_end = begin - 1;
	auto namespace_beg = scriptname.find('-');
	std::string str_namespace;

	if (namespace_beg == std::string::npos) {
		str_namespace = "default";
	} else {
		namespace_beg += 1;
		if (namespace_beg < namespace_end) {
			str_namespace = scriptname.substr(namespace_beg, namespace_end - namespace_beg);
		}
	}
	return std::make_pair(filename, str_namespace);
}

} // namespace

namespace elliptics {

std::string id_str(const ioremap::elliptics::key &key, ioremap::elliptics::session sess) {
	struct dnet_id id;
	memset(&id, 0, sizeof(id));
	if (key.by_id()) {
		id = key.id();
	} else {
		sess.transform(key.remote(), id);
	}
	char str[2 * DNET_ID_SIZE + 1];
	dnet_dump_id_len_raw(id.id, DNET_ID_SIZE, str);
	return std::string(str);
}

ioremap::elliptics::node proxy::generate_node(const rapidjson::Value &config, int &timeout_def) {
	struct dnet_config dnet_conf;
	memset(&dnet_conf, 0, sizeof(dnet_conf));

	if (config.HasMember("timeouts")) {
		const auto &timeouts = config["timeouts"];
		if (timeouts.HasMember("wait"))
			dnet_conf.wait_timeout = timeouts["wait"].GetInt();

		if (timeouts.HasMember("check"))
			dnet_conf.check_timeout = timeouts["check"].GetInt();
	}

	timeout_def = dnet_conf.wait_timeout;

	if (config.HasMember("cfg-flags"))
		dnet_conf.flags = config["cfg-flags"].GetInt();

	if (config.HasMember("elliptics-threads")) {
		const auto &ell_threads = config["elliptics-threads"];
		if (ell_threads.HasMember("io-thread-num"))
			dnet_conf.io_thread_num = ell_threads["io-thread-num"].GetInt();
		if (ell_threads.HasMember("net-thread-num"))
			dnet_conf.net_thread_num = ell_threads["net-thread-num"].GetInt();;
	}

	ioremap::swarm::logger elliptics_logger = ioremap::swarm::logger(logger(),
			blackhole::log::attributes_t({blackhole::attribute::make("component", "elliptics")}));
	ioremap::elliptics::node node(
			ioremap::elliptics::logger(new elliptics_logger_interface_t(std::move(elliptics_logger)), 5), dnet_conf);

	{
		const auto &remotes = mastermind()->get_elliptics_remotes();

		if (remotes.empty()) {
			BH_LOG(logger(), SWARM_LOG_INFO, "Mediastorage-proxy starts: nothing to put add to elliptics remotes");
		} else {
			auto ts_beg = std::chrono::system_clock::now();
			BH_LOG(logger(), SWARM_LOG_INFO, "Mediastorage-proxy starts: add_remotes");
			try {
				node.add_remote(mastermind()->get_elliptics_remotes());
			} catch (const std::exception &ex) {
				std::ostringstream oss;
				oss << "Mediastorage-proxy starts: Can\'t connect to remote nodes: " << ex.what();
				BH_LOG(logger(), SWARM_LOG_INFO, "%s", oss.str().c_str());
			}
			auto ts_end = std::chrono::system_clock::now();
			{
				std::ostringstream oss;
				oss << "Mediastorage-proxy starts: add_remotes is finished in "
					<< std::chrono::duration_cast<std::chrono::microseconds>(ts_end - ts_beg).count()
					<< "us";
				auto msg = oss.str();
				BH_LOG(logger(), SWARM_LOG_INFO, "%s", msg.c_str());
			}
		}
	}

	return node;
}

std::shared_ptr<mastermind::mastermind_t> proxy::generate_mastermind(const rapidjson::Value &config) {
	if (config.HasMember("mastermind") == false) {
		throw std::runtime_error("You should set settings for mastermind");
	}
	
	const auto &mastermind = config["mastermind"];

	if (mastermind.HasMember("nodes") == false) {
		throw std::runtime_error("You should set at least one node to connect to mastermind");
	}

	const auto &nodes = mastermind["nodes"];

	mastermind::mastermind_t::remotes_t remotes;
	ioremap::swarm::logger libmastermind_logger = ioremap::swarm::logger(logger(),
			blackhole::log::attributes_t({blackhole::attribute::make("component", "libmastermind")}));
	auto sp_lg = std::make_shared<cocaine_logger_t>(cocaine_logger_t(std::move(libmastermind_logger)));

	for (auto it = nodes.Begin(); it != nodes.End(); ++it) {
		const auto &node = *it;

		if (node.HasMember("host") == false) {
			//this->logger()->(ioremap::swarm::LOG_INFO, "You should set a host address in each node of mastermind settings");
			COCAINE_LOG_INFO(sp_lg, "You should set a host address in each node of mastermind settings");
			continue;
		}

		auto host = node["host"].GetString();
		auto port = get_int(node, "port", 10053);
		remotes.emplace_back(host, port);
	}

	auto group_info_update_period = get_int(mastermind, "group-info-update-period", 60);
	auto cache_path = get_string(mastermind, "cache-path", "/var/cache/mediastorage-proxy/mastermind");
	auto expired_time = get_int(mastermind, "expired-time", 0);
	auto worker_name = get_string(mastermind, "worker-name", "mastermind");

	return std::make_shared<mastermind::mastermind_t>(remotes, sp_lg,
			group_info_update_period, cache_path, expired_time, worker_name);
}

proxy::~proxy() {
	m_mastermind.reset();
}

bool proxy::initialize(const rapidjson::Value &config) {
	try {
		BH_LOG(logger(), SWARM_LOG_INFO, "Mediastorage-proxy starts");

		BH_LOG(logger(), SWARM_LOG_INFO, "Mediastorage-proxy starts: initialize libmastermind");
		m_mastermind = generate_mastermind(config);
		BH_LOG(logger(), SWARM_LOG_INFO, "Mediastorage-proxy starts: done");

		BH_LOG(logger(), SWARM_LOG_INFO, "Mediastorage-proxy starts: initialize elliptics node");
		m_elliptics_node.reset(generate_node(config, timeout.def));
		BH_LOG(logger(), SWARM_LOG_INFO, "Mediastorage-proxy starts: done");

		if (timeout.def == 0) {
			timeout.def = 10;
		}

		BH_LOG(logger(), SWARM_LOG_INFO, "Mediastorage-proxy starts: initialize elliptics session");
		m_elliptics_session.reset(generate_session(*m_elliptics_node));
		BH_LOG(logger(), SWARM_LOG_INFO, "Mediastorage-proxy starts: done");

		m_die_limit = get_int(config, "die-limit", 1);

		if (config.HasMember("timeouts")) {
			const auto &json_timeout = config["timeouts"];

			timeout.read = get_int(json_timeout, "read", timeout.def);
			timeout.write = get_int(json_timeout, "write", timeout.def);
			timeout.lookup = get_int(json_timeout, "lookup", timeout.def);
			timeout.remove = get_int(json_timeout, "remove", timeout.def);
		}

		if (config.HasMember("header-protector")) {
			const auto &json_hp = config["header-protector"];

			if (json_hp.HasMember("name") == false) {
				BH_LOG(logger(), SWARM_LOG_ERROR,
						"header-protector is set but header-protector/name is missed");
				return false;
			}

			if (json_hp.HasMember("value") == false) {
				BH_LOG(logger(), SWARM_LOG_ERROR,
						"header-protector is set but header-protector/value is missed");
				return false;
			}

			if (json_hp.HasMember("handlers") == false) {
				BH_LOG(logger(), SWARM_LOG_ERROR,
						"header-protector is set but header-protector/handlers are missed");
				return false;
			}

			header_protector.name = get_string(json_hp, "name");
			header_protector.value = get_string(json_hp, "value");

			auto &json_handlers = json_hp["handlers"];
			for (auto it = json_handlers.Begin(); it != json_handlers.End(); ++it) {
				header_protector.handlers.insert(it->GetString());
			}
		}

		if (config.HasMember("timeout-coefs")) {
			const auto &json = config["timeout-coefs"];

			timeout_coef.data_flow_rate = get_int(json, "data-flow-rate", 0);
			timeout_coef.for_commit = get_int(json, "for-commit", 0);
		}

		BH_LOG(logger(), SWARM_LOG_INFO, "Mediastorage-proxy starts: initialize cache updater");
		mastermind()->set_update_cache_callback(std::bind(&proxy::cache_update_callback, this));
		BH_LOG(logger(), SWARM_LOG_INFO, "Mediastorage-proxy starts: done");

		BH_LOG(logger(), SWARM_LOG_INFO, "Mediastorage-proxy starts: initialize namespaces");
		m_namespaces = generate_namespaces(m_mastermind);
		BH_LOG(logger(), SWARM_LOG_INFO, "Mediastorage-proxy starts: done");

		if (config.HasMember("chunk-size") == false) {
			throw std::runtime_error("You should set values for write and read chunk sizes");
		}
		{
			const auto &chunk_size = config["chunk-size"];
			if (chunk_size.HasMember("write") == false || chunk_size.HasMember("read") == false) {
				throw std::runtime_error("You should set both write and read chunk-sizes");
			}
			const size_t MB = 1024 * 1024;
			m_write_chunk_size = chunk_size["write"].GetInt() * MB;
			m_read_chunk_size = chunk_size["read"].GetInt() * MB;
		}

	} catch(const std::exception &ex) {
		BH_LOG(logger(), SWARM_LOG_ERROR, "%s", ex.what());
		return false;
	}
	BH_LOG(logger(), SWARM_LOG_INFO, "Mediastorage-proxy starts: initialize handlers");

	register_handler<req_upload>("upload", false);
	register_handler<req_get>("get", false);
	register_handler<req_delete>("delete", false);
	register_handler<req_download_info_1>(req_download_info_1::handler_name, false);
	register_handler<req_download_info_2>(req_download_info_2::handler_name, false);
	register_handler<req_stat_log>("stat-log", true);
	register_handler<req_stat_log>("stat_log", true);
	register_handler<req_ping>("ping", true);
	register_handler<req_ping>("stat", true);
	register_handler<req_cache>("cache", true);
	register_handler<req_cache_update>("cache-update", true);
	register_handler<req_statistics>("statistics", false);

	BH_LOG(logger(), SWARM_LOG_INFO, "Mediastorage-proxy starts: done");
	BH_LOG(logger(), SWARM_LOG_INFO, "Mediastorage-proxy starts: initialization is done");

	return true;
}

proxy::req_download_info::req_download_info(const std::string &handler_name_)
	: handler_name('/' + handler_name_)
{}

void proxy::req_download_info::on_request(const ioremap::thevoid::http_request &req, const boost::asio::const_buffer &buffer) {
	try {
		BH_LOG(logger(), SWARM_LOG_INFO, "Download info: handle request: %s", req.url().path().c_str());
		const auto &url = req.url().path();
		try {
			ns = server()->get_namespace(url, handler_name);
		} catch (const std::exception &ex) {
			BH_LOG(logger(), SWARM_LOG_INFO,
				"Download info: request = \"%s\"; err: \"%s\"",
				url.c_str(), ex.what());
			send_reply(400);
			return;
		}
		boost::optional<ioremap::elliptics::session> session;
		boost::optional<ioremap::elliptics::key> key;

		try {
			auto &&prep_session = server()->prepare_session(url, ns);
			session.reset(prep_session.first);
			key.reset(prep_session.second);
		} catch (const std::exception &ex) {
			BH_LOG(logger(), SWARM_LOG_INFO, "Download info request error: %s", ex.what());
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

		BH_LOG(logger(), SWARM_LOG_DEBUG, "Download info: looking up");
		auto alr = session->quorum_lookup(*key);

		alr.connect(wrap(std::bind(&req_download_info::on_finished, shared_from_this(), std::placeholders::_1, std::placeholders::_2)));
	} catch (const std::exception &ex) {
		BH_LOG(logger(), SWARM_LOG_ERROR, "Download info request error: %s", ex.what());
		send_reply(500);
	} catch (...) {
		BH_LOG(logger(), SWARM_LOG_ERROR, "Download info request error: unknown");
		send_reply(500);
	}
}

void proxy::req_download_info::on_finished(const ioremap::elliptics::sync_lookup_result &slr, const ioremap::elliptics::error_info &error) {
	try {
		BH_LOG(logger(), SWARM_LOG_DEBUG, "Download info: prepare response");
		if (error) {
			BH_LOG(logger(), SWARM_LOG_ERROR, "%s", error.message().c_str());
			send_reply(error.code() == -ENOENT ? 404 : 500);
			return;
		}

		for (auto it = slr.begin(); it != slr.end(); ++it) {
			if (!it->error()) {
				std::stringstream oss;
				oss << "<?xml version=\"1.0\" encoding=\"utf-8\"?>";
				std::string region = "-1";
				
				auto entry = server()->parse_lookup(*it, ns);
				
				std::string sign;
				long time;
				bool use_sign = !ns->sign_token.empty();
				std::string entry_path = entry.path();

				if (use_sign) {
					{
						const auto &path_prefix = ns->sign_path_prefix;
						if (strncmp(entry_path.c_str(), path_prefix.c_str(), path_prefix.size())) {
							BH_LOG(logger(), SWARM_LOG_INFO,
									"Download-info: path_prefix does not match: prefix=%s path=%s",
									path_prefix.c_str(), entry_path.c_str());
						} else {
							entry_path.substr(path_prefix.size()).swap(entry_path);
							entry_path = '/' + entry_path;
						}
					}
					{
						using namespace std::chrono;
						time = duration_cast<seconds>(
									system_clock::now().time_since_epoch()).count();
					}

					{
						using namespace std::chrono;
						std::ostringstream oss;
						oss << "scheme://";
						if (!x_regional_host.empty()) {
							oss << x_regional_host;
						} else {
							oss << entry.host();
						}
						oss << entry_path << "?time=" << time;
						server()->hmac(oss.str(), ns).swap(sign);
					}
				}

				oss << "<download-info>";
				if (!x_regional_host.empty()) {
					oss << "<regional-host>" << x_regional_host << "</regional-host>";
				}
				oss << "<host>" << entry.host() << "</host>";
				oss << "<path>" << entry_path << "</path>";
				if (use_sign) {
					oss << "<ts>" << time << "</ts>";
				}
				oss << "<region>" << region << "</region>";
				if (use_sign) {
					oss << "<s>" << sign << "</s>";
				}
				oss << "</download-info>";

				const std::string &str = oss.str();

				ioremap::thevoid::http_response reply;
				ioremap::swarm::http_headers headers;
				reply.set_code(200);
				headers.set_content_length(str.size());
				headers.set_content_type("text/xml");
				reply.set_headers(headers);
				send_reply(std::move(reply), std::move(str));
				return;
			}
		}
		BH_LOG(logger(), SWARM_LOG_DEBUG, "Download info: sending response");
		send_reply(503);  
	} catch (const std::exception &ex) {
		BH_LOG(logger(), SWARM_LOG_ERROR, "Download info finish error: %s", ex.what());
		send_reply(500);
	} catch (...) {
		BH_LOG(logger(), SWARM_LOG_ERROR, "Download info finish error: unknown");
		send_reply(500);
	}
}

void proxy::req_ping::on_request(const ioremap::thevoid::http_request &req, const boost::asio::const_buffer &buffer) {
	try {
		auto begin_request = std::chrono::system_clock::now();
		std::ostringstream ts_oss;

		ts_oss << "start: " << std::chrono::duration_cast<std::chrono::microseconds>(
				std::chrono::system_clock::now() - begin_request).count() << "us; ";

		{
			const auto &path = req.url().path();
			ts_oss << "got url path: " << std::chrono::duration_cast<std::chrono::microseconds>(
					std::chrono::system_clock::now() - begin_request).count() << "us; ";
			BH_LOG(logger(), SWARM_LOG_INFO, "Ping: handle request: %s", path.c_str());
		}

		ts_oss << "print greating log: " << std::chrono::duration_cast<std::chrono::microseconds>(
				std::chrono::system_clock::now() - begin_request).count() << "us; ";

		std::ostringstream oss;

		oss << "Stats: done; nodes alive: ";
		int code = 200;

		ts_oss << "init oss and code: " << std::chrono::duration_cast<std::chrono::microseconds>(
				std::chrono::system_clock::now() - begin_request).count() << "us; ";

		auto session = server()->get_session();

		ts_oss << "session is copied: " << std::chrono::duration_cast<std::chrono::microseconds>(
				std::chrono::system_clock::now() - begin_request).count() << "us; ";

		auto state_num = session.state_num();

		ts_oss << "state_num was computed: " << std::chrono::duration_cast<std::chrono::microseconds>(
				std::chrono::system_clock::now() - begin_request).count() << "us; ";

		auto die_limit = server()->die_limit();

		ts_oss << "got a die_limit: " << std::chrono::duration_cast<std::chrono::microseconds>(
				std::chrono::system_clock::now() - begin_request).count() << "us; ";

		oss << state_num;
		oss << "; die-limit: ";

		ts_oss << "check die_limit: " << std::chrono::duration_cast<std::chrono::microseconds>(
				std::chrono::system_clock::now() - begin_request).count() << "us; ";

		if (state_num < die_limit) {
			BH_LOG(logger(), SWARM_LOG_ERROR,
					"Ping request error: state_num too small state_num=%d",
					static_cast<int>(state_num));
			code = 500;
			oss << "Bad";
		} else {
			oss << "Ok";
		}

		ts_oss << "die_limit is checked: " << std::chrono::duration_cast<std::chrono::microseconds>(
				std::chrono::system_clock::now() - begin_request).count() << "us; ";

		send_reply(code);

		ts_oss << "request was send: " << std::chrono::duration_cast<std::chrono::microseconds>(
				std::chrono::system_clock::now() - begin_request).count() << "us; ";

		{
			const auto &msg = ts_oss.str();
			BH_LOG(logger(), SWARM_LOG_DEBUG, "%s", msg.c_str());
		}

		{
			const auto &msg = oss.str();
			BH_LOG(logger(), SWARM_LOG_INFO, "%s", msg.c_str());
		}
	} catch (const std::exception &ex) {
		BH_LOG(logger(), SWARM_LOG_ERROR, "Ping request error: %s", ex.what());
		send_reply(500);
	} catch (...) {
		BH_LOG(logger(), SWARM_LOG_ERROR, "Ping request error: unknown");
		send_reply(500);
	}
}

void proxy::req_cache::on_request(const ioremap::thevoid::http_request &req, const boost::asio::const_buffer &buffer) {
	try {
		BH_LOG(logger(), SWARM_LOG_INFO, "Cache: handle request: %s", req.url().path().c_str());
		auto query_list = req.url().query();

		bool g = false;

		std::ostringstream oss;
		oss << '{' << std::endl;
		if (query_list.has_item("group-weights")) {
			oss << "\"group-weights\" : " << server()->mastermind()->json_group_weights();
			g = true;
		}
		if (query_list.has_item("symmetric-groups")) {
			if (g) oss << ',' << std::endl;
			oss << "\"symmetric-groups\" : " << server()->mastermind()->json_symmetric_groups();
			g = true;
		}
		if (query_list.has_item("bad-groups")) {
			if (g) oss << ',' << std::endl;
			oss << "\"bad-groups\" : " << server()->mastermind()->json_bad_groups();
			g = true;
		}
		if (query_list.has_item("cache-groups")) {
			if (g) oss << ',' << std::endl;
			oss << "\"cache-groups\" : " << server()->mastermind()->json_cache_groups();
			g = true;
		}
		if (query_list.has_item("namespaces-settings")) {
			if (g) oss << ',' << std::endl;
			oss << "\"namespaces-settings\" : " << server()->mastermind()->json_namespaces_settings();
			g = true;
		}
		if (query_list.has_item("metabalancer-info")) {
			if (g) oss << ',' << std::endl;
			oss << "\"metabalancer-info\" : " << server()->mastermind()->json_metabalancer_info();
			g = true;
		}
		if (g) oss << std::endl;
		oss << '}' << std::endl;
		auto res_str = oss.str();
		ioremap::thevoid::http_response reply;
		ioremap::swarm::http_headers headers;
		reply.set_code(200);
		headers.set_content_length(res_str.size());
		headers.set_content_type("text/plain");
		reply.set_headers(headers);
		BH_LOG(logger(), SWARM_LOG_DEBUG, "Cache: sending response");
		send_reply(std::move(reply), std::move(res_str));
	} catch (const std::exception &ex) {
		BH_LOG(logger(), SWARM_LOG_ERROR, "Cache request error: %s", ex.what());
		send_reply(500);
	} catch (...) {
		BH_LOG(logger(), SWARM_LOG_ERROR, "Cache request error: unknown");
		send_reply(500);
	}
}

void proxy::req_cache_update::on_request(const ioremap::thevoid::http_request &req, const boost::asio::const_buffer &buffer) {
	try {
		auto query_list = req.url().query();

		server()->mastermind()->cache_force_update();
		server()->cache_update_callback();
		send_reply(200);
	} catch (const std::exception &ex) {
		BH_LOG(logger(), SWARM_LOG_ERROR, "Cache request error: %s", ex.what());
		send_reply(500);
	} catch (...) {
		BH_LOG(logger(), SWARM_LOG_ERROR, "Cache request error: unknown");
		send_reply(500);
	}
}

void proxy::req_statistics::on_request(const ioremap::thevoid::http_request &req, const boost::asio::const_buffer &buffer) {
	try {
		auto ns = server()->get_namespace(req, "/statistics");
		auto json = server()->mastermind()->json_namespace_statistics(ns->name);

		ioremap::thevoid::http_response reply;
		ioremap::swarm::http_headers headers;

		reply.set_code(200);
		headers.set_content_length(json.size());
		headers.set_content_type("text/json");
		reply.set_headers(headers);

		send_reply(std::move(reply), std::move(json));
	} catch (const std::exception &ex) {
		BH_LOG(logger(), SWARM_LOG_ERROR, "Statistics request error: %s", ex.what());
		send_reply(500);
	} catch (...) {
		BH_LOG(logger(), SWARM_LOG_ERROR, "Statistics request error: unknown");
		send_reply(500);
	}
}

void proxy::req_stat_log::on_request(const ioremap::thevoid::http_request &req, const boost::asio::const_buffer &buffer) {
	try {
		BH_LOG(logger(), SWARM_LOG_INFO, "Stat log: handle request: %s", req.url().path().c_str());
		auto session = server()->get_session();

		BH_LOG(logger(), SWARM_LOG_DEBUG, "Stat log: process \'stat_log\'");
		auto asr = session.stat_log();

		asr.connect(wrap(std::bind(&req_stat_log::on_finished, shared_from_this(), std::placeholders::_1, std::placeholders::_2)));
	} catch (const std::exception &ex) {
		BH_LOG(logger(), SWARM_LOG_ERROR, "Stat log request error: %s", ex.what());
		send_reply(500);
	} catch (...) {
		BH_LOG(logger(), SWARM_LOG_ERROR, "Stat log request error: unknown");
		send_reply(500);
	}
}

void proxy::req_stat_log::on_finished(const ioremap::elliptics::sync_stat_result &ssr, const ioremap::elliptics::error_info &error) {
	try {
		BH_LOG(logger(), SWARM_LOG_DEBUG, "Stat log: prepare response");
		if (error) {
			BH_LOG(logger(), SWARM_LOG_ERROR, "%s", error.message().c_str());
			send_reply(500);
			return;
		}

		char id_str[DNET_ID_SIZE * 2 + 1];
		char addr_str[128];

		std::ostringstream oss;
		oss << "<?xml version=\"1.0\" encoding=\"utf-8\"?>";
		oss << "<data>\n";

		for (auto it = ssr.begin(); it != ssr.end(); ++it) {
			const ioremap::elliptics::stat_result_entry &data = *it;
			struct dnet_addr *addr = data.address();
			struct dnet_cmd *cmd = data.command();
			struct dnet_stat *st = data.statistics();

			dnet_server_convert_dnet_addr_raw(addr, addr_str, sizeof(addr_str));
			dnet_dump_id_len_raw(cmd->id.id, DNET_ID_SIZE, id_str);

			oss << "<stat addr=\"" << addr_str << "\" id=\"" << id_str << "\">";
			oss << "<la>";
			for (size_t i = 0; i != 3; ++i) {
				oss << std::fixed << std::setprecision(2) << static_cast<float>(st->la[i]) / 100.0;
				if (i != 2)
					oss << ' ';
			}
			oss << "</la>";
			oss << "<memtotal>" << st->vm_total << "</memtotal>";
			oss << "<memfree>" << st->vm_free << "</memfree>";
			oss << "<memcached>" << st->vm_cached << "</memcached>";
			oss << "<storage_size>" << st->frsize * st->blocks / 1024 / 1024 << "</storage_size>";
			oss << "<available_size>" << st->bavail * st->bsize / 1024 / 1024 << "</available_size>";
			oss << "<files>" << st->files << "</files>";
			oss << "<fsid>" << std::hex << st->fsid << "</fsid>";
			oss << "</stat>";
		}

		oss << "</data>";

		const std::string &body = oss.str();
		ioremap::thevoid::http_response reply;
		ioremap::swarm::http_headers headers;
		reply.set_code(200);
		headers.set_content_type("text/xml");
		headers.set_content_length(body.size());
		reply.set_headers(headers);
		BH_LOG(logger(), SWARM_LOG_DEBUG, "Stat log: sending response");
		send_reply(std::move(reply), std::move(body));
	} catch (const std::exception &ex) {
		BH_LOG(logger(), SWARM_LOG_ERROR, "Stat log finish error: %s", ex.what());
		send_reply(500);
	} catch (...) {
		BH_LOG(logger(), SWARM_LOG_ERROR, "Stat log finish error: unknown");
		send_reply(500);
	}
}

ioremap::elliptics::session proxy::get_session() {
	return m_elliptics_session->clone();
}

namespace_ptr_t proxy::get_namespace(const ioremap::thevoid::http_request &req, const std::string &handler_name) {
	const auto &url = req.url();
	return get_namespace(url.path(), handler_name);
}

namespace_ptr_t proxy::get_namespace(const std::string &scriptname, const std::string &handler_name) {
	if (strncmp(scriptname.c_str(), handler_name.c_str(), handler_name.size())) {
		throw std::runtime_error("Cannot detect namespace");
	}
	std::string str_namespace;
	if (scriptname[handler_name.size()] == '-') {
		auto namespace_end = scriptname.find('/', 1);
		auto namespace_beg = handler_name.size() + 1;
		if (namespace_beg == namespace_end) {
			throw std::runtime_error("Cannot detect namespace");
		}
		scriptname.substr(namespace_beg, namespace_end - namespace_beg).swap(str_namespace);
	} else if (scriptname[handler_name.size()] == '/'){
		str_namespace = "default";
	} else {
		throw std::runtime_error("Cannot detect namespace");
	}

	std::lock_guard<std::mutex> lock(m_namespaces_mutex);
	auto it = m_namespaces.find(str_namespace);
	if (it == m_namespaces.end()) {
		throw std::runtime_error("Cannot detect namespace");
	}

	return it->second;
}

elliptics::lookup_result proxy::parse_lookup(const ioremap::elliptics::lookup_result_entry &entry, const namespace_ptr_t &ns) {
	return elliptics::lookup_result(entry, ns->sign_port);
}

int proxy::die_limit() const {
	return m_die_limit;
}

std::vector<int> proxy::groups_for_upload(const elliptics::namespace_ptr_t &name_space, uint64_t size) {
	if (!name_space->static_couple.empty())
		return name_space->static_couple;
	return m_mastermind->get_metabalancer_groups(name_space->groups_count, name_space->name, size);
}

std::pair<std::string, namespace_ptr_t> proxy::get_file_info(const ioremap::thevoid::http_request &req) {
	auto p = get_filename(req);
	std::lock_guard<std::mutex> lock(m_namespaces_mutex);
	auto it = m_namespaces.find(p.second);
	auto nm = (it != m_namespaces.end() ? it->second : std::make_shared<elliptics::namespace_t>());
	return std::make_pair(p.first, nm);
}

std::vector<int> proxy::get_groups(int group, const std::string &filename) {
	std::vector<int> res;

	try {
		std::vector<int> vec_groups1;
		std::vector<int> vec_groups2;
		m_mastermind->get_symmetric_groups(group).swap(vec_groups1);
		m_mastermind->get_cache_groups(filename).swap(vec_groups2);
		vec_groups1.reserve(vec_groups2.size());
		vec_groups1.insert(vec_groups1.end(), vec_groups2.begin(), vec_groups2.end());
		res.swap(vec_groups1);
	} catch (...) {
		BH_LOG(logger(), SWARM_LOG_ERROR, "Cannot to determine groups");
	}

	// TODO: if (m_proxy_logger->level() >= ioremap::swarm::SWARM_LOG_INFO)
	{
		std::ostringstream oss;

		auto &groups = res;
		oss << "Fetched groups for request: [";
		for (auto it = groups.begin(); it != groups.end(); ++it) {
			if (it != groups.begin())
				oss << ", ";
			oss << *it;
		}
		oss << "]";

		BH_LOG(logger(), SWARM_LOG_INFO, "%s", oss.str().c_str());
		BH_LOG(logger(), SWARM_LOG_INFO, "filename: %s", filename.c_str());
	}

	return res;
}

std::pair<ioremap::elliptics::session, ioremap::elliptics::key> proxy::prepare_session(
		const ioremap::thevoid::http_request &req,
		const std::string &handler_name) {
	const auto &url = req.url();
	const auto &str_url = url.path();
	const auto &ns = get_namespace(str_url, handler_name);
	return prepare_session(str_url, ns);
}

std::pair<ioremap::elliptics::session, ioremap::elliptics::key> proxy::prepare_session(const std::string &url, const namespace_ptr_t &ns) {
	auto session = get_session();

	std::vector<int> groups;
	std::string filename;

	if (ns->static_couple.empty()) {
		auto bg = url.find('/', 1) + 1;
		auto eg = url.find('/', bg);
		auto bf = eg + 1;
		auto ef = url.find('?', bf);
		auto g = url.substr(bg, eg - bg);
		url.substr(bf, ef - bf).swap(filename);

		try {
			auto group = boost::lexical_cast<int>(g);
			get_groups(group, filename).swap(groups);
		} catch (...) {
			throw std::runtime_error("Cannot to determine groups");
		}
	} else {
		auto bf = url.find('/', 1) + 1;
		auto ef = url.find('?', bf);
		url.substr(bf, ef - bf).swap(filename);
		groups = ns->static_couple;
	}

	session.set_groups(groups);
	return std::make_pair(session, ioremap::elliptics::key(ns->name + '.' + filename));;
}

std::shared_ptr<mastermind::mastermind_t> &proxy::mastermind() {
	return m_mastermind;
}

std::string proxy::get_auth_token(const boost::optional<std::string> &auth_header) {
	if (!auth_header) {
		return "";
	}

	if (auth_header->compare(0, sizeof("Basic ") - 1, "Basic ") == 0) {
		return auth_header->substr(sizeof ("Basic ") - 1);
	}

	return "";
}

bool proxy::check_basic_auth(const std::string &ns, const std::string &auth_key, const boost::optional<std::string> &auth_header) {
	if (auth_key.empty()) {
		return true;
	}

	if (!auth_header) {
		return false;
	}

	if (auth_header->compare(0, sizeof("Basic ") - 1, "Basic ")) {
		return false;
	}

	std::ostringstream oss;
	oss << ns << ':' << auth_key;
	std::string str = oss.str();

	auto base64 = g_base64_encode((const guchar *)str.data(), str.size());

	int result = strcmp((const char *)base64, auth_header->data() + sizeof ("Basic ") - 1);

	g_free(base64);

	return !result;
}

std::string proxy::hmac(const std::string &data, const namespace_ptr_t &ns) {
	using namespace CryptoPP;

	HMAC<SHA512> hmac((const byte *)ns->sign_token.data(), ns->sign_token.size());
	hmac.Update((const byte *)data.data(), data.size());
	std::vector<byte> res(hmac.DigestSize());
	hmac.Final(res.data());

	std::ostringstream oss;
	oss << std::hex;
	for (auto it = res.begin(), end = res.end(); it != end; ++it) {
		oss << std::setfill('0') << std::setw(2) << static_cast<int>(*it);
	}
	return oss.str();
}

void proxy::cache_update_callback() {
	auto &&m = mastermind();
	if (m) {
		BH_LOG(logger(), SWARM_LOG_INFO, "cache updater: starts");
		BH_LOG(logger(), SWARM_LOG_INFO, "cache updater: update namespaces");
		auto namespaces = generate_namespaces(m);
		std::lock_guard<std::mutex> lock(m_namespaces_mutex);
		m_namespaces.swap(namespaces);
		BH_LOG(logger(), SWARM_LOG_INFO, "cache updater: update namespaces is done");

		BH_LOG(logger(), SWARM_LOG_INFO, "cache updater: update elliptics remotes");
		try {
			m_elliptics_node->add_remote(mastermind()->get_elliptics_remotes());
		} catch (const std::exception &ex) {
			std::ostringstream oss;
			oss << "Mediastorage-proxy starts: Can\'t connect to remote nodes: " << ex.what();
			BH_LOG(logger(), SWARM_LOG_INFO, "%s", oss.str().c_str());
		}
		BH_LOG(logger(), SWARM_LOG_INFO, "cache updater: update elliptics remotes is done");
		BH_LOG(logger(), SWARM_LOG_INFO, "cache updater is done");
	}
}

} // namespace elliptics

int main(int argc, char **argv) {
	return ioremap::thevoid::run_server<elliptics::proxy>(argc, argv);
}
