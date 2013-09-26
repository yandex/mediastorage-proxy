#include "proxy.hpp"
#include "lookup_result.hpp"
#include "data_container.hpp"
#include "loggers.hpp"

#include <swarm/network_url.h>
#include <swarm/logger.h>

#include <stdexcept>
#include <iterator>
#include <algorithm>
#include <functional>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <utility>

#include <boost/lexical_cast.hpp>

#include <iostream>

namespace {

enum tag_user_flags {
	UF_EMBEDS = 1
};

template <typename T>
T get_arg(const ioremap::swarm::network_query_list &query_list, const std::string &name, const T &default_value = T()) {
	auto &&arg = query_list.try_item(name);
	return arg ? boost::lexical_cast<T>(*arg) : default_value;
}

int get_int(const rapidjson::Value &config, const char *name, int def_val = 0) {
	return config.HasMember(name) ? config[name].GetInt() : def_val;
}

bool get_bool(const rapidjson::Value &config, const char *name, bool def_val = false) {
	return config.HasMember(name) ? config[name].GetBool() : def_val;
}

std::string get_string(const rapidjson::Value &config, const char *name, const std::string &def_val = std::string()) {
	return config.HasMember(name) ? config[name].GetString() : def_val;
}

ioremap::swarm::logger generate_logger(const rapidjson::Value &config) {
	std::string log_path("/dev/stderr");
	int log_mask(DNET_LOG_INFO | DNET_LOG_ERROR);

	if (config.HasMember("log")) {
		const auto &log = config["log"];

		if (log.HasMember("path"))
			log_path = log["path"].GetString();
		if (log.HasMember("level"))
			log_mask = log["level"].GetInt();
	}

	return ioremap::swarm::logger(log_path.c_str(), log_mask);
}

ioremap::elliptics::node generate_node(const rapidjson::Value &config, const ioremap::elliptics::logger &logger) {
	struct dnet_config dnet_conf;
	memset(&dnet_conf, 0, sizeof(dnet_conf));

	if (config.HasMember("timeouts")) {
		const auto &timeouts = config["timeouts"];
		if (timeouts.HasMember("wait"))
			dnet_conf.wait_timeout = timeouts["wait"].GetInt();
		if (timeouts.HasMember("check"))
			dnet_conf.check_timeout = timeouts["check"].GetInt();
	}

	if (config.HasMember("cfg-flags"))
		dnet_conf.flags = config["cfg-flags"].GetInt();

	return ioremap::elliptics::node(logger, dnet_conf);
}

ioremap::elliptics::session generate_session(const rapidjson::Value &config, ioremap::swarm::logger &logger) {
	auto node = generate_node(config, elliptics_logger_t(logger));

	if (config.HasMember("remotes") == false) {
		const char *err = "You should set a list of remote addresses";
		throw std::runtime_error(err);
	}

	{
		auto &conf_remotes = config["remotes"];
		for (auto it = conf_remotes.Begin(); it != conf_remotes.End(); ++it) {
			const std::string &host = it->GetString();
			try {
				node.add_remote(host.c_str());
			} catch (const std::exception &ex) {
				std::ostringstream oss;
				oss << "Can\'t connect to remote node " << host << " : " << ex.what();
				logger.log(DNET_LOG_INFO, "%s", oss.str().c_str());
			}
		}
	}

	ioremap::elliptics::session session(node);

	{
		const std::string &scn = get_string(config, "success-copies-num", "quorum");

		if (scn == "all") {
			session.set_checker(ioremap::elliptics::checkers::all);
		} else if (scn == "quorum") {
			session.set_checker(ioremap::elliptics::checkers::quorum);
		} else if (scn == "any"){
			session.set_checker(ioremap::elliptics::checkers::at_least_one);
		} else {
			std::ostringstream oss;
			oss << "Unknown type of success-copies-num \'" << scn << "\'. Allowed types: any, quorum, all.";
			const std::string &str = oss.str();
			throw std::runtime_error(str);
		}
	}

	session.set_error_handler(ioremap::elliptics::error_handlers::none);

	return session;
}

std::shared_ptr<elliptics::mastermind_t> generate_mastermind(const rapidjson::Value &config, const cocaine_logger_t &logger) {
	if (config.HasMember("mastermind") == false) {
		const char *err = "You should set settings for mastermind";
		throw std::runtime_error(err);
	}
	
	const auto &mastermind = config["mastermind"];

	if (mastermind.HasMember("host") == false) {
		const char *err = "You should set an ip address in mastermind settings";
		throw std::runtime_error(err);
	}

	auto ip = mastermind["host"].GetString();
	auto port = get_int(mastermind, "port", 10053);
	auto group_info_update_period = get_int(mastermind, "group-info-update-period", 60);

	return std::make_shared<elliptics::mastermind_t>(ip, port, std::make_shared<cocaine_logger_t>(logger), group_info_update_period);
}

std::pair<std::string, std::string> get_filename(const ioremap::swarm::network_request &req) {
	auto scriptname = req.get_url();
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

std::pair<ioremap::elliptics::key, std::string> get_file_info(const ioremap::swarm::network_request &req) {
	auto p = get_filename(req);
	return std::make_pair(ioremap::elliptics::key(p.first), p.second);
}

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

ioremap::elliptics::async_write_result write(
	  ioremap::elliptics::session &session
	, const ioremap::elliptics::key &key
	, const ioremap::elliptics::data_pointer &data
	, const ioremap::swarm::network_query_list &query_list
	) {
	session.set_error_handler(ioremap::elliptics::error_handlers::remove_on_fail(session));
	auto offset = get_arg<uint64_t>(query_list, "offset", 0);
    if (auto &&arg = query_list.try_item("prepare")) {
        size_t size = boost::lexical_cast<uint64_t>(*arg);
        return session.write_prepare(key, data, offset, size);
    } else if (auto &&arg = query_list.try_item("commit")) {
        size_t size = boost::lexical_cast<uint64_t>(*arg);
        return session.write_commit(key, data, offset, size);
    } else if (query_list.has_item("plain_write") || query_list.has_item("plain-write")) {
        return session.write_plain(key, data, offset);
    } else {
		// TODO: add chunk write
        return session.write_data(key, data, offset, 0 /*m_data->m_chunk_size*/);
    }
}

} // namespace

namespace elliptics {

bool proxy::initialize(const rapidjson::Value &config) {
	try {
		m_logger.reset(generate_logger(config));
		m_elliptics_session.reset(generate_session(config, *m_logger));
		m_mastermind = generate_mastermind(config, cocaine_logger_t(*m_logger));

		m_die_limit = get_int(config, "die-limit", 1);
		m_eblob_style_path = get_bool(config, "eblob_style_path", true);
		m_direction_bit_num = get_int(config, "direction_bit_num", 16);
		m_base_port = get_int(config, "base_port", 1024);

		if (config.HasMember("groups-count") == false) {
			const char *err = "You should set a groups count in application settings";
			throw std::runtime_error(err);
		}
		m_groups_count = config[ "groups-count"].GetInt();
	} catch(const std::exception &ex) {
		if (m_logger) {
			m_logger->log(ioremap::swarm::LOG_ERROR, "%s", ex.what());
		} else {
			std::cerr << ex.what() << std::endl;
		}
	}

	on_prefix<req_upload>("/upload");
	on_prefix<req_get>("/get/");
	on_prefix<req_delete>("/delete/");
	on_prefix<req_download_info>("/download_info/");
	on_prefix<req_download_info>("/download-info/");
	on<req_stat_log>("/stat-log");
	on<req_stat_log>("/stat_log");
	on<req_ping>("/ping");
	on<req_ping>("/stat");

	return true;
}

void proxy::req_upload::on_request(const ioremap::swarm::network_request &req, const boost::asio::const_buffer &buffer) {
	try {
		get_server()->logger().log(ioremap::swarm::LOG_DEBUG, "Upload: prepare to handle request");
		m_session = get_server()->get_session();
		auto file_info = get_file_info(req);
		m_key = file_info.first;
		if (file_info.second.empty()) {
			get_server()->logger().log(ioremap::swarm::LOG_INFO, "Upload: Cannot determine a namespace");
			send_reply(400);
			return;
		}

		m_session->set_groups(get_server()->groups_for_upload(file_info.second));
		ioremap::swarm::network_query_list query_list(ioremap::swarm::network_url(req.get_url()).query());

		if (m_session->state_num() < get_server()->die_limit()) {
			throw std::runtime_error("Too low number of existing states");
		}

		auto data = std::string(
			boost::asio::buffer_cast<const char *>(buffer)
			, boost::asio::buffer_size(buffer)
			);
		elliptics::data_container_t dc(data);

		if (query_list.has_item("embed") || query_list.has_item("embed_timestamp")) {
			timespec timestamp;
			timestamp.tv_sec = get_arg<uint64_t>(query_list, "timestamp", 0);
			timestamp.tv_nsec = 0;
			dc.set<elliptics::DNET_FCGI_EMBED_TIMESTAMP>(timestamp);
		}

		if (dc.embeds_count() != 0) {
			m_session->set_user_flags(m_session->get_user_flags() | UF_EMBEDS);
		}

		m_content = elliptics::data_container_t::pack(dc);

		get_server()->logger().log(ioremap::swarm::LOG_DEBUG, "Upload: writing content");
		auto awr = write(*m_session, m_key, m_content, query_list);

		awr.connect(std::bind(&req_upload::on_finished, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
	
	} catch (std::exception &ex) {
		get_server()->logger().log(ioremap::swarm::LOG_ERROR, "Upload request error: %s", ex.what());
		send_reply(500);
	} catch (...) {
		get_server()->logger().log(ioremap::swarm::LOG_ERROR, "Upload request error: unknown");
		send_reply(500);
	}
}

void proxy::req_upload::on_finished(const ioremap::elliptics::sync_write_result &swr, const ioremap::elliptics::error_info &error) {
	try {
		get_server()->logger().log(ioremap::swarm::LOG_DEBUG, "Upload: prepare response");
		if (error) {
			get_server()->logger().log(ioremap::swarm::LOG_ERROR, "%s", error.message().c_str());
			send_reply(500);
			return;
		}
		std::ostringstream oss;

		oss 
			<< "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
			<< "<post obj=\"" << m_key.remote() << "\" id=\""
			<< id_str(m_key, *m_session)
			<< "\" groups=\"" << swr.size()
			<< "\" size=\"" << m_content.size()
			<< "\" key=\"/";
		{
			auto groups = m_session->get_groups();
			auto git = std::min_element(groups.begin(), groups.end());
			oss << *git;
		}
		oss << '/' << m_key.remote() << "\">\n";

		size_t written = 0;
		for (auto it = swr.begin(); it != swr.end(); ++it) {
			auto pl = get_server()->parse_lookup(*it);
			if (pl.status() == 0)
				written += 1;
			oss << "<complete addr=\"" << pl.addr() << "\" path=\"" <<
				pl.full_path() << "\" group=\"" << pl.group() <<
				"\" status=\"" << pl.status() << "\"/>\n";
		}

		oss
			<< "<written>" << written << "</written>\n"
			<< "</post>";

		auto res_str = oss.str();
		ioremap::swarm::network_reply reply;
		reply.set_code(200);
		reply.set_content_length(res_str.size());
		reply.set_content_type("text/plain");
		get_server()->logger().log(ioremap::swarm::LOG_DEBUG, "Upload: sending response");
		send_reply(reply, res_str);

	} catch (std::exception &ex) {
		get_server()->logger().log(ioremap::swarm::LOG_ERROR, "Upload finish error: %s", ex.what());
		send_reply(500);
	} catch (...) {
		get_server()->logger().log(ioremap::swarm::LOG_ERROR, "Upload finish error: unknown");
		send_reply(500);
	}
}

void proxy::req_get::on_request(const ioremap::swarm::network_request &req, const boost::asio::const_buffer &buffer) {
	try {
		get_server()->logger().log(ioremap::swarm::LOG_DEBUG, "Get: prepare to handle request");
		auto &&prep_session = get_server()->prepare_session(req);
		auto &&session = prep_session.first;

		if (session.get_groups().empty()) {
			send_reply(404);
			return;
		}

		m_query_list.set_query(ioremap::swarm::network_url(req.get_url()).query());

		auto &&key = prep_session.second;
		auto offset = get_arg<uint64_t>(m_query_list, "offset", 0);
		auto size = get_arg<uint64_t>(m_query_list, "size", 0);
		get_server()->logger().log(ioremap::swarm::LOG_DEBUG, "Get: reading data");
		auto arr = session.read_data(key, offset, size);

		arr.connect(std::bind(&req_get::on_finished, shared_from_this(), std::placeholders::_1, std::placeholders::_2, req.try_header("If-Modified-Since")));
	} catch (const std::exception &ex) {
		get_server()->logger().log(ioremap::swarm::LOG_ERROR, "Get request error: %s", ex.what());
		send_reply(500);
	} catch (...) {
		get_server()->logger().log(ioremap::swarm::LOG_ERROR, "Get request error: unknown");
		send_reply(500);
	}
}

void proxy::req_get::on_finished(const ioremap::elliptics::sync_read_result &srr, const ioremap::elliptics::error_info &error, const boost::optional<std::string> &if_modified_since) {
	try {
		get_server()->logger().log(ioremap::swarm::LOG_DEBUG, "Get: prepare response");
		if (error) {
			get_server()->logger().log(ioremap::swarm::LOG_ERROR, "%s", error.message().c_str());
			send_reply(error.code() == -ENOENT ? 404 : 500);
			return;
		}
		auto &&rr = srr.front();
		bool embeded = m_query_list.has_item("embed") || m_query_list.has_item("embed_timestamp");
		if (rr.io_attribute()->user_flags & UF_EMBEDS) {
			embeded = true;
		}

		auto dc = elliptics::data_container_t::unpack(rr.file(), embeded);
		
		auto ts = dc.get<elliptics::DNET_FCGI_EMBED_TIMESTAMP>();

		ioremap::swarm::network_reply reply;
		if (ts) {
			char ts_str[128] = {0};
			time_t timestamp = (time_t)(ts->tv_sec);
			struct tm tmp;
			strftime(ts_str, sizeof (ts_str), "%a, %d %b %Y %T %Z", gmtime_r(&timestamp, &tmp));
			
			if (if_modified_since) {
				if (*if_modified_since == ts_str) {
					send_reply(304);
					return;
				}
			}
			reply.set_header("Last-Modified", ts_str);
		}

		auto res_str = dc.data.to_string();
		reply.set_code(200);
		reply.set_content_length(res_str.size());
		reply.set_content_type("text/plain");
		get_server()->logger().log(ioremap::swarm::LOG_DEBUG, "Get: sending response");
		send_reply(reply, res_str);
	} catch (const std::exception &ex) {
		get_server()->logger().log(ioremap::swarm::LOG_ERROR, "Get finish error: %s", ex.what());
		send_reply(500);
	} catch (...) {
		get_server()->logger().log(ioremap::swarm::LOG_ERROR, "Get finish error: unknown");
		send_reply(500);
	}
}

void proxy::req_delete::on_request(const ioremap::swarm::network_request &req, const boost::asio::const_buffer &buffer) {
	try {
		get_server()->logger().log(ioremap::swarm::LOG_DEBUG, "Delete: prepare to handle request");
		auto &&prep_session = get_server()->prepare_session(req);
		auto &&session = prep_session.first;

		if (session.get_groups().empty()) {
			send_reply(404);
			return;
		}

		if (session.state_num() < get_server()->die_limit()) {
			throw std::runtime_error("Too low number of existing states");
		}

		session.set_filter(ioremap::elliptics::filters::all);

		auto &&key = prep_session.second;
		get_server()->logger().log(ioremap::swarm::LOG_DEBUG, "Delete: removing data");
		session.remove(key).connect(std::bind(&req_delete::on_finished, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
	} catch (const std::exception &ex) {
		get_server()->logger().log(ioremap::swarm::LOG_ERROR, "Delete request error: %s", ex.what());
		send_reply(500);
	} catch (...) {
		get_server()->logger().log(ioremap::swarm::LOG_ERROR, "Delete request error: unknown");
		send_reply(500);
	}
}

void proxy::req_delete::on_finished(const ioremap::elliptics::sync_remove_result &srr, const ioremap::elliptics::error_info &error) {
	(void)srr;
	if (error) {
		get_server()->logger().log(ioremap::swarm::LOG_ERROR, "%s", error.message().c_str());
		send_reply(error.code() == -ENOENT ? 404 : 500);
		return;
	}
	get_server()->logger().log(ioremap::swarm::LOG_DEBUG, "Delete: sending reply");
	send_reply(200);
}

void proxy::req_download_info::on_request(const ioremap::swarm::network_request &req, const boost::asio::const_buffer &buffer) {
	try {
		get_server()->logger().log(ioremap::swarm::LOG_DEBUG, "Download info: prepare to handle request");
		auto &&prep_session = get_server()->prepare_session(req);
		auto &&session = prep_session.first;

		if (session.get_groups().empty()) {
			send_reply(404);
			return;
		}

		session.set_filter(ioremap::elliptics::filters::all);

		auto &&key = prep_session.second;
		get_server()->logger().log(ioremap::swarm::LOG_DEBUG, "Download info: looking up");
		auto alr = session.lookup(key);

		alr.connect(std::bind(&req_download_info::on_finished, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
	} catch (const std::exception &ex) {
		get_server()->logger().log(ioremap::swarm::LOG_ERROR, "Download info request error: %s", ex.what());
		send_reply(500);
	} catch (...) {
		get_server()->logger().log(ioremap::swarm::LOG_ERROR, "Download info request error: unknown");
		send_reply(500);
	}
}

void proxy::req_download_info::on_finished(const ioremap::elliptics::sync_lookup_result &slr, const ioremap::elliptics::error_info &error) {
	try {
		get_server()->logger().log(ioremap::swarm::LOG_DEBUG, "Download info: prepare response");
		if (error) {
			get_server()->logger().log(ioremap::swarm::LOG_ERROR, "%s", error.message().c_str());
			send_reply(error.code() == -ENOENT ? 404 : 500);
			return;
		}

		for (auto it = slr.begin(); it != slr.end(); ++it) {
			if (!it->error()) {
				std::stringstream oss;
				oss << "<?xml version=\"1.0\" encoding=\"utf-8\"?>";
				std::string region = "-1";
				
				auto entry = get_server()->parse_lookup(*it);
				
				long time;
				{
					using namespace std::chrono;
					time = duration_cast<microseconds>(
						system_clock::now().time_since_epoch()
						).count();
				}

				oss << "<download-info>";
				oss << "<host>" << entry.host() << "</host>";
				oss << "<path>" << entry.path() << "</path>";
				oss << "<region>" << region << "</region>";
				oss << "</download-info>";

				const std::string &str = oss.str();

				ioremap::swarm::network_reply reply;
				reply.set_code(200);
				reply.set_content_length(str.size());
				reply.set_content_type("text/xml");
				send_reply(reply, str);
				return;
			}
		}
		get_server()->logger().log(ioremap::swarm::LOG_DEBUG, "Download info: sending response");
		send_reply(503);  
	} catch (const std::exception &ex) {
		get_server()->logger().log(ioremap::swarm::LOG_ERROR, "Download info finish error: %s", ex.what());
		send_reply(500);
	} catch (...) {
		get_server()->logger().log(ioremap::swarm::LOG_ERROR, "Download info finish error: unknown");
		send_reply(500);
	}
}

void proxy::req_ping::on_request(const ioremap::swarm::network_request &req, const boost::asio::const_buffer &buffer) {
	try {
		get_server()->logger().log(ioremap::swarm::LOG_DEBUG, "Ping: handle request");
		int code = 200;
		auto session = get_server()->get_session();
		if (session.state_num() < get_server()->die_limit()) {
			code = 500;
		}
		send_reply(code);
	} catch (const std::exception &ex) {
		get_server()->logger().log(ioremap::swarm::LOG_ERROR, "Ping request error: %s", ex.what());
		send_reply(500);
	} catch (...) {
		get_server()->logger().log(ioremap::swarm::LOG_ERROR, "Ping request error: unknown");
		send_reply(500);
	}
}

void proxy::req_stat_log::on_request(const ioremap::swarm::network_request &req, const boost::asio::const_buffer &buffer) {
	try {
		get_server()->logger().log(ioremap::swarm::LOG_DEBUG, "Stat log: prepare to handle request");
		auto session = get_server()->get_session();

		get_server()->logger().log(ioremap::swarm::LOG_DEBUG, "Stat log: process \'stat_log\'");
		auto asr = session.stat_log();

		asr.connect(std::bind(&req_stat_log::on_finished, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
	} catch (const std::exception &ex) {
		get_server()->logger().log(ioremap::swarm::LOG_ERROR, "Stat log request error: %s", ex.what());
		send_reply(500);
	} catch (...) {
		get_server()->logger().log(ioremap::swarm::LOG_ERROR, "Stat log request error: unknown");
		send_reply(500);
	}
}

void proxy::req_stat_log::on_finished(const ioremap::elliptics::sync_stat_result &ssr, const ioremap::elliptics::error_info &error) {
	try {
		get_server()->logger().log(ioremap::swarm::LOG_DEBUG, "Stat log: prepare response");
		if (error) {
			get_server()->logger().log(ioremap::swarm::LOG_ERROR, "%s", error.message().c_str());
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
		ioremap::swarm::network_reply reply;
		reply.set_code(200);
		reply.set_content_type("text/xml");
		reply.set_content_length(body.size());
		get_server()->logger().log(ioremap::swarm::LOG_DEBUG, "Stat log: sending response");
		send_reply(reply, body);
	} catch (const std::exception &ex) {
		get_server()->logger().log(ioremap::swarm::LOG_ERROR, "Stat log finish error: %s", ex.what());
		send_reply(500);
	} catch (...) {
		get_server()->logger().log(ioremap::swarm::LOG_ERROR, "Stat log finish error: unknown");
		send_reply(500);
	}
}

ioremap::elliptics::session proxy::get_session() {
	return m_elliptics_session->clone();
}

elliptics::lookup_result proxy::parse_lookup(const ioremap::elliptics::lookup_result_entry &entry) {
	return elliptics::lookup_result(entry, m_eblob_style_path, m_base_port, m_direction_bit_num);
}

int proxy::die_limit() const {
	return m_die_limit;
}

std::vector<int> proxy::groups_for_upload(const std::string &name_space) {
	return m_mastermind->get_metabalancer_groups(m_groups_count, name_space);
}

std::pair<ioremap::elliptics::session, ioremap::elliptics::key> proxy::prepare_session(const ioremap::swarm::network_request &req) {
	auto session = get_session();

	auto url = req.get_url();
	auto bg = url.find('/', 1) + 1;
	auto eg = url.find('/', bg);
	auto bf = eg + 1;
	auto ef = url.find('?', bf);
	auto g = url.substr(bg, eg - bg);
	auto filename = url.substr(bf, ef - bf);



	try {
		auto group = boost::lexical_cast<int>(g);
		std::vector<int> vec_groups1;
		std::vector<int> vec_groups2;
		vec_groups1.swap(m_mastermind->get_symmetric_groups(group));
		vec_groups2.swap(m_mastermind->get_cache_groups(filename));
		vec_groups1.reserve(vec_groups2.size());
		vec_groups1.insert(vec_groups1.end(), vec_groups2.begin(), vec_groups2.end());
		session.set_groups(vec_groups1);
	} catch (...) {
		logger().log(ioremap::swarm::LOG_ERROR, "Cannot to determine groups");
	}

	if (m_logger->get_level() >= ioremap::swarm::LOG_INFO) {
		std::ostringstream oss;

		auto groups = session.get_groups();
		oss << "Fetched groups for request: [";
		for (auto it = groups.begin(); it != groups.end(); ++it) {
			if (it != groups.begin())
				oss << ", ";
			oss << *it;
		}
		oss << "]";

		m_logger->log(ioremap::swarm::LOG_INFO, "%s", oss.str().c_str());
		m_logger->log(ioremap::swarm::LOG_INFO, "filename: %s", filename.c_str());
	}

	return std::make_pair(session, ioremap::elliptics::key(filename));;
}

ioremap::swarm::logger &proxy::logger() {
	return *m_logger;
}

} // namespace elliptics

int main(int argc, char **argv) {
	return ioremap::thevoid::run_server<elliptics::proxy>(argc, argv);
}
