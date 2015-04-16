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

#include <handystats/core.hpp>
#include <handystats/json_dump.hpp>


#include "proxy.hpp"
#include "lookup_result.hpp"
#include "data_container.hpp"

#include "upload.hpp"
#include "get.hpp"
#include "download_info.hpp"

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
#include <limits>

#include <boost/lexical_cast.hpp>

#include <iostream>

namespace {

int get_int(const rapidjson::Value &config, const char *name, int def_val = 0) {
	return config.HasMember(name) ? config[name].GetInt() : def_val;
}

double get_double(const rapidjson::Value &config, const char *name, double def_val = 0) {
	return config.HasMember(name) ? config[name].GetDouble() : def_val;
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

std::pair<std::string, std::string> get_filename(const ioremap::swarm::http_request &req) {
	auto scriptname = req.url().path();
	auto begin = scriptname.find('/', 1) + 1;
	auto filename = scriptname.substr(begin);

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

const settings_t &
proxy_settings(const mastermind::namespace_state_t &ns_state) {
	return static_cast<const settings_t &>(ns_state.settings().user_settings());
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
	ioremap::elliptics::node node(std::move(elliptics_logger), dnet_conf);

	{
		const auto &remotes = mastermind()->get_elliptics_remotes();

		if (remotes.empty()) {
			MDS_LOG_INFO("Mediastorage-proxy starts: nothing to put add to elliptics remotes");
		} else {
			auto ts_beg = std::chrono::system_clock::now();
			MDS_LOG_INFO("Mediastorage-proxy starts: add_remotes");
			try {
				auto remotes = mastermind()->get_elliptics_remotes();
				std::vector<ioremap::elliptics::address> addresses;

				for (auto it = remotes.begin(), end = remotes.end(); it != end; ++it) {
					addresses.emplace_back(*it);
				}

				node.add_remote(addresses);
			} catch (const std::exception &ex) {
				std::ostringstream oss;
				oss << "Mediastorage-proxy starts: Can\'t connect to remote nodes: " << ex.what();
				MDS_LOG_INFO("%s", oss.str().c_str());
			}
			auto ts_end = std::chrono::system_clock::now();
			{
				std::ostringstream oss;
				oss << "Mediastorage-proxy starts: add_remotes is finished in "
					<< std::chrono::duration_cast<std::chrono::microseconds>(ts_end - ts_beg).count()
					<< "us";
				auto msg = oss.str();
				MDS_LOG_INFO("%s", msg.c_str());
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
	auto warning_time = get_int(mastermind, "warning-time", std::numeric_limits<int>::max());
	auto expire_time = get_int(mastermind, "expire-time", std::numeric_limits<int>::max());
	auto worker_name = get_string(mastermind, "worker-name", "mastermind");

	auto enqueue_timeout = get_int(mastermind, "enqueue-timeout", 4000);
	auto reconnect_timeout = get_int(mastermind, "reconnect-timeout", 4000);

	auto factory = std::bind(&proxy::settings_factory, this
			, std::placeholders::_1, std::placeholders::_2);

	auto result = std::make_shared<mastermind::mastermind_t>(remotes, sp_lg,
			group_info_update_period, cache_path, warning_time, expire_time, worker_name,
			enqueue_timeout, reconnect_timeout, false);
	result->set_user_settings_factory(std::move(factory));
	return result;
}

std::shared_ptr<cdn_cache_t> proxy::generate_cdn_cache(const rapidjson::Value &config) {
	cdn_cache_t::config_t cdn_config;

	if (config.HasMember("cdn-cache")) {
		const auto &cdn_hosts = config["cdn-cache"];

		cdn_config.url = get_string(cdn_hosts, "url", "");
		cdn_config.timeout = get_int(cdn_hosts, "timeout", 10);
		cdn_config.update_period = get_int(cdn_hosts, "update-period", 60);
		cdn_config.cache_path = get_string(cdn_hosts, "cache-path", "");
	}

	auto logger_ = ioremap::swarm::logger(logger(), blackhole::log::attributes_t({
				blackhole::attribute::make("component", "cdn-cache")}));

	return std::make_shared<cdn_cache_t>(std::move(logger_), std::move(cdn_config));
}

proxy::~proxy() {
	MDS_LOG_INFO("Mediastorage-proxy stops");

	MDS_LOG_INFO("Mediastorage-proxy stops: mastermind");
	mastermind()->stop();
	MDS_LOG_INFO("Mediastorage-proxy stops: done");

	MDS_LOG_INFO("Mediastorage-proxy stops: elliptics node");
	{
		std::lock_guard<std::mutex> lock_node(elliptics_node_mutex);
		(void) lock_node;

		std::lock_guard<std::mutex> lock_session(elliptics_session_mutex);
		(void) lock_session;

		m_elliptics_session.reset();
		elliptics_read_session.reset();
		elliptics_write_session.reset();
		elliptics_remove_session.reset();
		elliptics_lookup_session.reset();

		m_elliptics_node.reset();
	}
	MDS_LOG_INFO("Mediastorage-proxy stops: done");

	MDS_LOG_INFO("Mediastorage-proxy stops: handystats");
	HANDY_FINALIZE();
	MDS_LOG_INFO("Mediastorage-proxy stops: done");
}

bool proxy::initialize(const rapidjson::Value &config) {
	try {
		MDS_LOG_INFO("Mediastorage-proxy starts");

		cache_is_expired = false;

		MDS_LOG_INFO("Mediastorage-proxy starts: initialize libmastermind");
		m_mastermind = generate_mastermind(config);
		MDS_LOG_INFO("Mediastorage-proxy starts: done");

		MDS_LOG_INFO("Mediastorage-proxy starts: initialize elliptics node");
		m_elliptics_node.reset(generate_node(config, timeout.def));
		MDS_LOG_INFO("Mediastorage-proxy starts: done");

		if (timeout.def == 0) {
			timeout.def = 10;
		}

		if (config.HasMember("timeouts")) {
			const auto &json_timeout = config["timeouts"];

			timeout.read = get_int(json_timeout, "read", timeout.def);
			timeout.write = get_int(json_timeout, "write", timeout.def);
			timeout.lookup = get_int(json_timeout, "lookup", timeout.def);
			timeout.remove = get_int(json_timeout, "remove", timeout.def);
		}

		MDS_LOG_INFO("Mediastorage-proxy starts: initialize elliptics session");
		m_elliptics_session.reset(generate_session(*m_elliptics_node));

		elliptics_read_session.reset(m_elliptics_session->clone());
		elliptics_read_session->set_timeout(timeout.read);
		elliptics_read_session->set_filter(ioremap::elliptics::filters::positive);

		elliptics_write_session.reset(m_elliptics_session->clone());
		elliptics_write_session->set_timeout(timeout.write);
		elliptics_write_session->set_error_handler(
				ioremap::elliptics::error_handlers::remove_on_fail(
					elliptics_write_session->clone()));

		elliptics_remove_session.reset(m_elliptics_session->clone());
		elliptics_remove_session->set_timeout(timeout.remove);
		elliptics_remove_session->set_checker(ioremap::elliptics::checkers::all);
		elliptics_remove_session->set_filter(ioremap::elliptics::filters::all_with_ack);

		elliptics_lookup_session.reset(m_elliptics_session->clone());
		elliptics_lookup_session->set_timeout(timeout.lookup);
		elliptics_lookup_session->set_filter(ioremap::elliptics::filters::positive);

		MDS_LOG_INFO("Mediastorage-proxy starts: done");

		MDS_LOG_INFO("Mediastorage-proxy starts: initialize cdn cache");
		cdn_cache = generate_cdn_cache(config);
		MDS_LOG_INFO("Mediastorage-proxy starts: done");

		m_die_limit = get_int(config, "die-limit", 1);

		if (config.HasMember("header-protector")) {
			const auto &json_hp = config["header-protector"];

			if (json_hp.HasMember("name") == false) {
				MDS_LOG_ERROR("header-protector is set but header-protector/name is missed");
				return false;
			}

			if (json_hp.HasMember("value") == false) {
				MDS_LOG_ERROR("header-protector is set but header-protector/value is missed");
				return false;
			}

			if (json_hp.HasMember("handlers") == false) {
				MDS_LOG_ERROR("header-protector is set but header-protector/handlers are missed");
				return false;
			}

			header_protector.name = get_string(json_hp, "name");
			header_protector.value = get_string(json_hp, "value");

			auto &json_handlers = json_hp["handlers"];
			for (auto it = json_handlers.Begin(); it != json_handlers.End(); ++it) {
				header_protector.handlers.insert(it->GetString());
			}
		}

		if (config.HasMember("retries")) {
			const auto &json_rt = config["retries"];

			limit_of_middle_chunk_attempts = get_int(json_rt, "limit-of-middle-chunk-attempts", 1);
			scale_retry_timeout = get_double(json_rt, "scale-retry-timeout", 1);
		} else {
			limit_of_middle_chunk_attempts = 1;
			scale_retry_timeout = 1;
		}

		if (config.HasMember("timeout-coefs")) {
			const auto &json = config["timeout-coefs"];

			timeout_coef.data_flow_rate = get_int(json, "data-flow-rate", 0);
		}

		MDS_LOG_INFO("Mediastorage-proxy starts: initialize cache updater");
		mastermind()->set_update_cache_ext1_callback(std::bind(&proxy::cache_update_callback, this,
					std::placeholders::_1));
		mastermind()->start();
		MDS_LOG_INFO("Mediastorage-proxy starts: done");

		update_elliptics_remotes();

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

		if (config.HasMember("handystats")) {
			HANDY_CONFIG_JSON(config["handystats"]);

			if (config["handystats"].HasMember("core") &&
					config["handystats"]["core"].HasMember("enable") &&
					config["handystats"]["core"]["enable"].IsBool() &&
					config["handystats"]["core"]["enable"].GetBool()
				)
			{
				HANDY_INIT();
			}
		}

	} catch(const std::exception &ex) {
		MDS_LOG_ERROR("%s", ex.what());
		return false;
	}

	MDS_LOG_INFO("Mediastorage-proxy starts: initialize handlers");

	register_handler<upload_t>("upload", false);
	register_handler<req_get>("get", false);
	register_handler<req_delete>("delete", false);
	register_handler<download_info_1_t>(download_info_1_t::handler_name, false);
	register_handler<download_info_2_t>(download_info_2_t::handler_name, false);
	register_handler<req_ping>("ping", true);
	register_handler<req_ping>("stat", true);
	register_handler<req_cache>("cache", true);
	register_handler<req_cache_update>("cache-update", false);
	register_handler<req_statistics>("statistics", false);
	register_handler<req_stats>("stats", false);

	MDS_LOG_INFO("Mediastorage-proxy starts: done");
	MDS_LOG_INFO("Mediastorage-proxy starts: initialization is done");

	return true;
}

void proxy::req_ping::on_request(const ioremap::thevoid::http_request &req, const boost::asio::const_buffer &buffer) {
	try {
		if (server()->cache_is_expired) {
			MDS_LOG_ERROR("Ping: libmastermind cache is expired");
			send_reply(500);
			return;
		}

		auto begin_request = std::chrono::system_clock::now();
		std::ostringstream ts_oss;

		ts_oss << "start: " << std::chrono::duration_cast<std::chrono::microseconds>(
				std::chrono::system_clock::now() - begin_request).count() << "us; ";

		{
			const auto &path = req.url().path();
			ts_oss << "got url path: " << std::chrono::duration_cast<std::chrono::microseconds>(
					std::chrono::system_clock::now() - begin_request).count() << "us; ";
			MDS_LOG_INFO("Ping: handle request: %s", path.c_str());
		}

		ts_oss << "print greating log: " << std::chrono::duration_cast<std::chrono::microseconds>(
				std::chrono::system_clock::now() - begin_request).count() << "us; ";

		std::ostringstream oss;

		oss << "Stats: done; nodes alive: ";
		int code = 200;

		ts_oss << "init oss and code: " << std::chrono::duration_cast<std::chrono::microseconds>(
				std::chrono::system_clock::now() - begin_request).count() << "us; ";

		auto session = server()->get_session();

		if (!session) {
			MDS_LOG_ERROR("cannot process ping request: session is uninitialized");
			return;
		}

		session->set_trace_bit(req.trace_bit());
		session->set_trace_id(req.request_id());

		ts_oss << "session is copied: " << std::chrono::duration_cast<std::chrono::microseconds>(
				std::chrono::system_clock::now() - begin_request).count() << "us; ";

		auto state_num = session->state_num();

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
			MDS_LOG_ERROR("Ping request error: state_num too small state_num=%d"
					, static_cast<int>(state_num));
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
			MDS_LOG_INFO("%s", msg.c_str());
		}

		{
			const auto &msg = oss.str();
			MDS_LOG_INFO("%s", msg.c_str());
		}
	} catch (const std::exception &ex) {
		MDS_LOG_ERROR("Ping request error: %s", ex.what());
		send_reply(500);
	} catch (...) {
		MDS_LOG_ERROR("Ping request error: unknown");
		send_reply(500);
	}
}

void proxy::req_cache::on_request(const ioremap::thevoid::http_request &req, const boost::asio::const_buffer &buffer) {
	try {
		MDS_LOG_INFO("Cache: handle request: %s", req.url().path().c_str());
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
		MDS_LOG_DEBUG("Cache: sending response");
		send_reply(std::move(reply), std::move(res_str));
	} catch (const std::exception &ex) {
		MDS_LOG_ERROR("Cache request error: %s", ex.what());
		send_reply(500);
	} catch (...) {
		MDS_LOG_ERROR("Cache request error: unknown");
		send_reply(500);
	}
}

void proxy::req_cache_update::on_request(const ioremap::thevoid::http_request &req, const boost::asio::const_buffer &buffer) {
	try {
		auto query_list = req.url().query();
		auto cache = req.url().path().substr(sizeof("/cache-update") - 1);

		if (cache == "/mastermind") {
			MDS_LOG_INFO("update mastermind cache");
			server()->mastermind()->cache_force_update();
		} else if (cache == "/conductor") {
			MDS_LOG_INFO("update conductor cache");
			server()->cdn_cache->cache_force_update();
		} else if (cache.empty()) {
			MDS_LOG_INFO("update mastermind cache");
			server()->mastermind()->cache_force_update();
			MDS_LOG_INFO("update conductor cache");
			server()->cdn_cache->cache_force_update();
		} else {
			send_reply(404);
			return;
		}
		send_reply(200);
	} catch (const std::exception &ex) {
		MDS_LOG_ERROR("Cache request error: %s", ex.what());
		send_reply(500);
	} catch (...) {
		MDS_LOG_ERROR("Cache request error: unknown");
		send_reply(500);
	}
}

void proxy::req_statistics::on_request(const ioremap::thevoid::http_request &req, const boost::asio::const_buffer &buffer) {
	try {
		mastermind::namespace_state_t ns_state;
		try {
			ns_state = server()->get_namespace_state(req.url().path(), "/statistics");
		} catch (const std::exception &ex) {
			MDS_LOG_INFO("Statistics: Cannot find namespace: %s", ex.what());
			send_reply(404);
			return;
		}

		auto json = server()->mastermind()->json_namespace_statistics(ns_state.name());

		ioremap::thevoid::http_response reply;
		ioremap::swarm::http_headers headers;

		reply.set_code(200);
		headers.set_content_length(json.size());
		headers.set_content_type("text/json");
		reply.set_headers(headers);

		send_reply(std::move(reply), std::move(json));
	} catch (const std::exception &ex) {
		MDS_LOG_ERROR("Statistics request error: %s", ex.what());
		send_reply(500);
	} catch (...) {
		MDS_LOG_ERROR("Statistics request error: unknown");
		send_reply(500);
	}
}

void proxy::req_stats::on_request(const ioremap::thevoid::http_request &req, const boost::asio::const_buffer &buffer) {
	std::string json = HANDY_JSON_DUMP();

	ioremap::thevoid::http_response reply;
	ioremap::swarm::http_headers headers;

	reply.set_code(200);
	headers.set_content_length(json.size());
	headers.set_content_type("application/json");
	reply.set_headers(headers);

	send_reply(std::move(reply), std::move(json));
}

boost::optional<ioremap::elliptics::session>
proxy::get_session() {
	std::lock_guard<std::mutex> lock(elliptics_session_mutex);
	(void) lock;

	if (!m_elliptics_session) {
		return boost::none;
	}

	return m_elliptics_session->clone();
}

boost::optional<ioremap::elliptics::session>
proxy::read_session(const ioremap::thevoid::http_request &http_request, const couple_t &couple) {
	std::lock_guard<std::mutex> lock(elliptics_session_mutex);
	(void) lock;

	if (!elliptics_read_session) {
		return boost::none;
	}

	return setup_session(elliptics_read_session->clone(), http_request, couple);
}

boost::optional<ioremap::elliptics::session>
proxy::write_session(const ioremap::thevoid::http_request &http_request, const couple_t &couple) {
	std::lock_guard<std::mutex> lock(elliptics_session_mutex);
	(void) lock;

	if (!elliptics_write_session) {
		return boost::none;
	}

	return setup_session(elliptics_write_session->clone(), http_request, couple);
}

boost::optional<ioremap::elliptics::session>
proxy::remove_session(const ioremap::thevoid::http_request &http_request, const couple_t &couple) {
	std::lock_guard<std::mutex> lock(elliptics_session_mutex);
	(void) lock;

	if (!elliptics_remove_session) {
		return boost::none;
	}

	return setup_session(elliptics_remove_session->clone(), http_request, couple);
}

boost::optional<ioremap::elliptics::session>
proxy::lookup_session(const ioremap::thevoid::http_request &http_request, const couple_t &couple) {
	std::lock_guard<std::mutex> lock(elliptics_session_mutex);
	(void) lock;

	if (!elliptics_lookup_session) {
		return boost::none;
	}

	return setup_session(elliptics_lookup_session->clone(), http_request, couple);
}

ioremap::elliptics::session
proxy::setup_session(ioremap::elliptics::session session
		, const ioremap::thevoid::http_request &http_request, const couple_t &couple) {
	session.set_trace_id(http_request.request_id());
	session.set_trace_bit(http_request.trace_bit());
	session.set_groups(couple);
	return session;
}

mastermind::namespace_state_t
proxy::get_namespace_state(const std::string &script, const std::string &handler) {
	if (strncmp(script.c_str(), handler.c_str(), handler.size())) {
		throw std::runtime_error("Cannot detect namespace");
	}
	std::string str_namespace;
	if (script[handler.size()] == '-') {
		auto namespace_end = script.find('/', 1);
		auto namespace_beg = handler.size() + 1;
		if (namespace_beg == namespace_end) {
			throw std::runtime_error("Cannot detect namespace");
		}
		script.substr(namespace_beg, namespace_end - namespace_beg).swap(str_namespace);
	} else if (script[handler.size()] == '/'){
		str_namespace = "default";
	} else {
		throw std::runtime_error("Cannot detect namespace");
	}

	return get_namespace_state(str_namespace);
}

mastermind::namespace_state_t
proxy::get_namespace_state(const std::string &name) {
	auto ns_state = mastermind()->get_namespace_state(name);

	if (!ns_state) {
		throw std::runtime_error("Cannot detect namespace");
	}

	return ns_state;
}

int proxy::die_limit() const {
	return m_die_limit;
}

std::vector<int> proxy::groups_for_upload(const mastermind::namespace_state_t &ns_state, uint64_t size) {
	if (!proxy_settings(ns_state).static_couple.empty())
		return proxy_settings(ns_state).static_couple;
	return ns_state.weights().groups(size);
}

std::tuple<std::string, mastermind::namespace_state_t>
proxy::get_file_info(const ioremap::thevoid::http_request &req) {
	auto p = get_filename(req);
	return std::make_tuple(p.first, get_namespace_state(p.second));
}

std::tuple<boost::optional<ioremap::elliptics::session>, ioremap::elliptics::key>
proxy::prepare_session(const std::string &url, const mastermind::namespace_state_t &ns_state) {
	auto session = get_session();

	std::vector<int> groups;
	std::string filename;

	if (session) {
		if (proxy_settings(ns_state).static_couple.empty()) {
			auto bg = url.find('/', 1) + 1;
			auto eg = url.find('/', bg);
			auto bf = eg + 1;
			auto ef = url.find('?', bf);
			auto g = url.substr(bg, eg - bg);
			url.substr(bf, ef - bf).swap(filename);

			try {
				auto group = boost::lexical_cast<int>(g);

				if (group <= 0) {
					throw std::runtime_error("group must be greater than zero");
				}

				groups = ns_state.couples().get_groups(group);
				auto cached_groups = mastermind()->get_cache_groups(filename);
				groups.insert(groups.begin(), cached_groups.begin(), cached_groups.end());
			} catch (...) {
				throw std::runtime_error("Cannot to determine groups");
			}
		} else {
			auto bf = url.find('/', 1) + 1;
			auto ef = url.find('?', bf);
			url.substr(bf, ef - bf).swap(filename);
			groups = proxy_settings(ns_state).static_couple;
		}

		session->set_groups(groups);
	}

	return std::make_pair(session, ioremap::elliptics::key(ns_state.name() + '.' + filename));;
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

std::string
proxy::hmac(const std::string &data, const std::string &token) {
	using namespace CryptoPP;

	HMAC<SHA256> hmac((const byte *)token.data(), token.size());
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

std::tuple<std::string, std::string, std::string, std::string>
proxy::generate_signature_for_elliptics_file(const ioremap::elliptics::sync_lookup_result &slr
	, std::string x_regional_host, const mastermind::namespace_state_t &ns_state) {
	return generate_signature_for_elliptics_file(slr, std::move(x_regional_host), ns_state
			, boost::none);
}
std::tuple<std::string, std::string, std::string, std::string>
proxy::generate_signature_for_elliptics_file(const ioremap::elliptics::sync_lookup_result &slr
	, std::string x_regional_host, const mastermind::namespace_state_t &ns_state
	, boost::optional<std::chrono::seconds> optional_expiration_time) {

	bool use_regional_host = !x_regional_host.empty() && cdn_cache->check_host(x_regional_host);
	if (proxy_settings(ns_state).sign_token.empty()) {
		throw std::runtime_error(
				"cannot generate signature for elliptics file without signature-token");
	}

	std::string error_message;

	for (auto it = slr.begin(); it != slr.end(); ++it) {
		if (it->error()) {
			error_message = it->error().message();
			continue;
		}

		lookup_result entry(*it, proxy_settings(ns_state).sign_port);

		std::string host;
		std::string path = entry.path();
		std::string ts;
		std::string sign;

		{
			{
				const auto &path_prefix = proxy_settings(ns_state).sign_path_prefix;
				if (strncmp(path.c_str(), path_prefix.c_str(), path_prefix.size())) {
					std::ostringstream oss;
					oss
						<< "path_prefix does not match: prefix=" << path_prefix << "path=" << path;
					throw std::runtime_error(oss.str());
				}

				path = '/' + ns_state.name() + '/' + path.substr(path_prefix.size());

				if (use_regional_host) {
					host = x_regional_host;
					path = '/' + entry.host() + path;
				} else {
					host = entry.host();
				}
			}

			{
				using namespace std::chrono;

				auto now = system_clock::now().time_since_epoch();
				auto expiration_time = optional_expiration_time.get_value_or(
						proxy_settings(ns_state).redirect_expire_time);

				std::ostringstream ts_oss;
				ts_oss
					<< std::hex
					<< duration_cast<microseconds>(now + expiration_time).count();
				ts = ts_oss.str();
			}

			{
				std::ostringstream oss;
				oss << host << path << '/' << ts;
				sign = hmac(oss.str(), proxy_settings(ns_state).sign_token);
			}
		}

		return std::make_tuple(host, path, ts, sign);
	}

	throw std::runtime_error("cannot make signature, there are no goot lookup result entry: "
			+ error_message);
}

void
proxy::update_elliptics_remotes() {
	MDS_LOG_INFO("update elliptics remotes");

	try {
		auto remotes = mastermind()->get_elliptics_remotes();
		std::vector<ioremap::elliptics::address> addresses;

		for (auto it = remotes.begin(), end = remotes.end(); it != end; ++it) {
			addresses.emplace_back(*it);
		}

		std::lock_guard<std::mutex> lock_guard(elliptics_node_mutex);

		if (m_elliptics_node) {
			m_elliptics_node->add_remote(addresses);
		}
	} catch (const std::exception &ex) {
		std::ostringstream oss;
		oss << "Mediastorage-proxy starts: Can\'t connect to remote nodes: " << ex.what();
		MDS_LOG_INFO("%s", oss.str().c_str());
	}

	MDS_LOG_INFO("update elliptics remotes is done");
}

void proxy::cache_update_callback(bool cache_is_expired_) {
	auto &&m = mastermind();

	cache_is_expired = cache_is_expired_;

	if (m) {
		MDS_LOG_INFO("cache updater: starts");

		update_elliptics_remotes();

		MDS_LOG_INFO("cache updater is done");
	}
}

mastermind::namespace_state_t::user_settings_ptr_t
proxy::settings_factory(const std::string &name, const kora::config_t &config) {
	std::unique_ptr<settings_t> settings(new settings_t);

	settings->name = name;

	{
		auto scn = config.at<std::string>("success-copies-num");

		if (scn == "all") {
			settings->result_checker = ioremap::elliptics::checkers::all;
			settings->success_copies_num = config.at<int>("groups-count");
		} else if (scn == "quorum") {
			settings->result_checker = ioremap::elliptics::checkers::quorum;
			settings->success_copies_num = config.at<int>("groups-count") / 2 + 1;
		} else if (scn == "any"){
			settings->result_checker = ioremap::elliptics::checkers::at_least_one;
			settings->success_copies_num = 1;
		} else {
			std::ostringstream oss;
			oss
				<< "Unknown type of success-copies-num \'" << scn << "\' in \'"
				<< name << "\' namespace. Allowed types: any, quorum, all.";
			throw std::runtime_error(oss.str());
		}
	}

	settings->auth_key_for_write = config.at<std::string>("auth-key", "");

	if (config.has("auth-keys")) {
		const auto &auth_keys_config = config.at("auth-keys");
		settings->auth_key_for_write = auth_keys_config.at<std::string>("write", "");
		settings->auth_key_for_read = auth_keys_config.at<std::string>("read", "");
	}

	if (config.has("static-couple")) {
		const auto &static_couple_config = config.at("static-couple");

		for (size_t index = 0, size = static_couple_config.size(); index != size; ++index) {
			settings->static_couple.emplace_back(static_couple_config.at<int>(index));
		}
	}

	if (config.has("signature")) {
		const auto &signature_config = config.at("signature");
		settings->sign_token = signature_config.at<std::string>("token", "");
		settings->sign_path_prefix = signature_config.at<std::string>("path_prefix", "");
		settings->sign_port = signature_config.at<std::string>("port", "");
	}

	if (config.has("redirect")) {
		const auto &redirect_config = config.at("redirect");
		settings->redirect_expire_time = std::chrono::seconds(
				redirect_config.at<int>("expire-time", 0));
		settings->redirect_content_length_threshold
			= redirect_config.at<int>("content-length-threshold", -1);
	}

	if (config.has("features")) {
		const auto &features_config = config.at("features");

		settings->can_choose_couple_to_upload
			= features_config.at<bool>("select-couple-to-upload", false);

		if (features_config.has("multipart")) {
			const auto &multipart_features_config = features_config.at("multipart");

			settings->multipart_content_length_threshold
				= multipart_features_config.at<int64_t>("content-length-threshold", 0);
		}

		settings->custom_expiration_time
			= features_config.at<bool>("custom-expiration-time", false);
	}

	settings->check_for_update = config.at<bool>("check-for-update", true);

	return mastermind::namespace_state_t::user_settings_ptr_t(std::move(settings));
}

} // namespace elliptics

int main(int argc, char **argv) {
	return ioremap::thevoid::run_server<elliptics::proxy>(argc, argv);
}
