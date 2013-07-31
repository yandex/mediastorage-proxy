#include "proxy.hpp"
#include "lookup_result.hpp"
#include "data_container.hpp"

#include <swarm/network_url.h>

#include <stdexcept>
#include <iterator>
#include <algorithm>
#include <functional>
#include <chrono>
#include <sstream>
#include <iomanip>

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

ioremap::elliptics::file_logger generate_logger(const rapidjson::Value &config) {
	std::string log_path("/dev/stderr");
	int log_mask(DNET_LOG_INFO | DNET_LOG_ERROR);

	if (config.HasMember("log")) {
		const auto &log = config["log"];

		if (log.HasMember("path"))
			log_path = log["path"].GetString();
		if (log.HasMember("mask"))
			log_mask = log["mask"].GetInt();
	}

	return ioremap::elliptics::file_logger(log_path.c_str(), log_mask);
}

ioremap::elliptics::node generate_node(const rapidjson::Value &config, const ioremap::elliptics::file_logger &logger) {
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

ioremap::elliptics::session generate_session(const rapidjson::Value &config) {
	const auto &logger = generate_logger(config);
	auto node = generate_node(config, logger);

	int base_port = get_int(config, "base-port", 1024);
	int addresses_family = get_int(config, "addresses_family", 2);

	if (config.HasMember("remotes") == false) {
		const char *err = "You should set a list of remote addresses";
		std::clog << err << std::endl;
		throw std::runtime_error(err);
	}

	{
		auto &conf_remotes = config["remotes"];
		for (auto it = conf_remotes.Begin(); it != conf_remotes.End(); ++it) {
			const std::string &host = it->GetString();
			try {
				node.add_remote(host.c_str(), base_port, addresses_family);
			} catch (const std::exception &ex) {
				std::ostringstream oss;
				oss
					<< "Can\'t connect to remote node " << host << ':'
					<< base_port << ':' << addresses_family << " : "
					<< ex.what();
				std::clog << oss.str() << std::endl;
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
			std::clog << str.c_str() << std::endl;
			throw std::runtime_error(str);
		}
	}

	session.set_error_handler(ioremap::elliptics::error_handlers::remove_on_fail(session));

	return session;
}

std::shared_ptr<elliptics::mastermind_t> generate_mastermind(const rapidjson::Value &config) {
	if (config.HasMember("mastermind") == false) {
		const char *err = "You should set settings for mastermind";
		std::clog << err << std::endl;
		throw std::runtime_error(err);
	}
	
	const auto &mastermind = config["mastermind"];

	if (mastermind.HasMember("ip") == false) {
		const char *err = "You should set an ip address in mastermind settings";
		std::clog << err << std::endl;
		throw std::runtime_error(err);
	}

	if (mastermind.HasMember("port") == false) {
		const char *err = "You should set a port in mastermind settings";
		std::clog << err << std::endl;
		throw std::runtime_error(err);
	}

	auto ip = mastermind["ip"].GetString();
	auto port = mastermind["port"].GetInt();

	return std::make_shared<elliptics::mastermind_t>(ip, port);
}

std::string get_filename(const ioremap::swarm::network_request &req) {
	auto scriptname = req.get_url();
	auto begin = scriptname.find('/', 1) + 1;
	auto end = scriptname.find('?', begin);
	return scriptname.substr(begin, end - begin);
}

ioremap::elliptics::key get_key(const ioremap::swarm::network_request &req) {
	return ioremap::elliptics::key(get_filename(req));
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
	auto offset = get_arg<uint64_t>(query_list, "offset", 0);
    if (auto &&arg = query_list.try_item("prepare")) {
        size_t size = boost::lexical_cast<uint64_t>(*arg);
		std::clog << "write prepare: offset=" << offset << "; size=" << size << "; data-size=" << data.size() << std::endl;
        return session.write_prepare(key, data, offset, size);
    } else if (auto &&arg = query_list.try_item("commit")) {
        size_t size = boost::lexical_cast<uint64_t>(*arg);
		std::clog << "write commit: offset=" << offset << "; size=" << size << "; data-size=" << data.size() << std::endl;
        return session.write_commit(key, data, offset, size);
    } else if (query_list.has_item("plain_write") || query_list.has_item("plain-write")) {
		std::clog << "write plain: offset=" << offset << "; data-size=" << data.size() << std::endl;
        return session.write_plain(key, data, offset);
    } else {
		// TODO: add chunk write
		std::clog << "write simple: offset=" << offset << "; chunk=" << 0 << std::endl;
        return session.write_data(key, data, offset, 0 /*m_data->m_chunk_size*/);
    }
}

} // namespace

namespace elliptics {

bool proxy::initialize(const rapidjson::Value &config) {
	m_elliptics_session.reset(generate_session(config));
	m_mastermind = generate_mastermind(config);

	m_die_limit = get_int(config, "die-limit", 1);
	m_eblob_style_path = get_bool(config, "eblob_style_path", true);
	m_base_port = get_int(config, "base_port", 1024);
	m_groups_count = get_int(config, "groups_count", 3);

	on_prefix<req_upload>("/upload/");
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
		std::clog << "Upload request" << std::endl;

		m_session = get_server()->get_session();
		m_session->set_groups(get_server()->groups_for_upload());
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

		m_key = get_key(req);
		auto awr = write(*m_session, m_key, m_content, query_list);

		awr.connect(std::bind(&req_upload::on_finished, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
	
	} catch (std::exception &ex) {
		std::clog << "Upload request error: " << ex.what() << std::endl;
		send_reply(500);
	} catch (...) {
		std::clog << "Upload request error: unknown" << std::endl;
		send_reply(500);
	}
}

void proxy::req_upload::on_finished(const ioremap::elliptics::sync_write_result &swr, const ioremap::elliptics::error_info &error) {
	try {
		if (error) {
			std::clog << error.message() << std::endl;
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
		send_reply(reply, res_str);

	} catch (std::exception &ex) {
		std::clog << "Upload request error: " << ex.what() << std::endl;
		send_reply(500);
	} catch (...) {
		std::clog << "Upload request error: unknown" << std::endl;
		send_reply(500);
	}
}

void proxy::req_get::on_request(const ioremap::swarm::network_request &req, const boost::asio::const_buffer &buffer) {
	try {
		std::clog << "Get request" << std::endl;
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
		auto arr = session.read_data(key, offset, size);

		arr.connect(std::bind(&req_get::on_finished, shared_from_this(), std::placeholders::_1, std::placeholders::_2, req.try_header("If-Modified-Since")));
	} catch (const std::exception &ex) {
		std::clog << "Get request error: " << ex.what() << std::endl;
		send_reply(500);
	} catch (...) {
		std::clog << "Get request error: unknown" << std::endl;
		send_reply(500);
	}
}

void proxy::req_get::on_finished(const ioremap::elliptics::sync_read_result &srr, const ioremap::elliptics::error_info &error, const boost::optional<std::string> &if_modified_since) {
	try {
		if (error) {
			std::clog << error.message() << std::endl;
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
		send_reply(reply, res_str);
	} catch (const std::exception &ex) {
		std::clog << "Get request error: " << ex.what() << std::endl;
		send_reply(500);
	} catch (...) {
		std::clog << "Get request error: unknown" << std::endl;
		send_reply(500);
	}
}

void proxy::req_delete::on_request(const ioremap::swarm::network_request &req, const boost::asio::const_buffer &buffer) {
	try {
		std::clog << "Delete request" << std::endl;
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
		session.remove(key).connect(std::bind(&req_delete::on_finished, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
	} catch (const std::exception &ex) {
		std::clog << "Delete request error: " << ex.what() << std::endl;
		send_reply(500);
	} catch (...) {
		std::clog << "Delete request error: unknown" << std::endl;
		send_reply(500);
	}
}

void proxy::req_delete::on_finished(const ioremap::elliptics::sync_remove_result &srr, const ioremap::elliptics::error_info &error) {
	(void)srr;
	if (error) {
		std::clog << error.message() << std::endl;
		send_reply(error.code() == -ENOENT ? 404 : 500);
		return;
	}
	send_reply(200);
}

void proxy::req_download_info::on_request(const ioremap::swarm::network_request &req, const boost::asio::const_buffer &buffer) {
	try {
		std::clog << "Download info request" << std::endl;
		auto &&prep_session = get_server()->prepare_session(req);
		auto &&session = prep_session.first;

		if (session.get_groups().empty()) {
			send_reply(404);
			return;
		}

		session.set_filter(ioremap::elliptics::filters::all);

		auto &&key = prep_session.second;
		auto alr = session.lookup(key);

		alr.connect(std::bind(&req_download_info::on_finished, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
	} catch (const std::exception &ex) {
		std::clog << "Download info request error: " << ex.what() << std::endl;
		send_reply(500);
	} catch (...) {
		std::clog << "Download info request error: unknown" << std::endl;
		send_reply(500);
	}
}

void proxy::req_download_info::on_finished(const ioremap::elliptics::sync_lookup_result &slr, const ioremap::elliptics::error_info &error) {
	try {
		if (error) {
			std::clog << error.message() << std::endl;
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
		send_reply(503);  
	} catch (const std::exception &ex) {
		std::clog << "Download info request error: " << ex.what() << std::endl;
		send_reply(500);
	} catch (...) {
		std::clog << "Download info request error: unknown" << std::endl;
		send_reply(500);
	}
}

void proxy::req_ping::on_request(const ioremap::swarm::network_request &req, const boost::asio::const_buffer &buffer) {
	try {
		std::clog << "Ping request" << std::endl;
		int code = 200;
		auto session = get_server()->get_session();
		if (session.state_num() < get_server()->die_limit()) {
			code = 500;
		}
		send_reply(code);
	} catch (const std::exception &ex) {
		std::clog << "Ping request error: " << ex.what() << std::endl;
		send_reply(500);
	} catch (...) {
		std::clog << "Ping request error: unknown" << std::endl;
		send_reply(500);
	}
}

void proxy::req_stat_log::on_request(const ioremap::swarm::network_request &req, const boost::asio::const_buffer &buffer) {
	try {
		std::clog << "Stat log request" << std::endl;
		auto session = get_server()->get_session();

		auto asr = session.stat_log();

		asr.connect(std::bind(&req_stat_log::on_finished, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
	} catch (const std::exception &ex) {
		std::clog << "Stat log request error: " << ex.what() << std::endl;
		send_reply(500);
	} catch (...) {
		std::clog << "Stat log request error: unknown" << std::endl;
		send_reply(500);
	}
}

void proxy::req_stat_log::on_finished(const ioremap::elliptics::sync_stat_result &ssr, const ioremap::elliptics::error_info &error) {
	try {
		if (error) {
			std::clog << error.message() << std::endl;
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
		send_reply(reply, body);
	} catch (const std::exception &ex) {
		std::clog << "Stat log request error: " << ex.what() << std::endl;
		send_reply(500);
	} catch (...) {
		std::clog << "Stat log request error: unknown" << std::endl;
		send_reply(500);
	}
}

ioremap::elliptics::session proxy::get_session() {
	return m_elliptics_session->clone();
}

elliptics::lookup_result proxy::parse_lookup(const ioremap::elliptics::lookup_result_entry &entry) {
	return elliptics::lookup_result(entry, m_eblob_style_path, m_base_port);
}

int proxy::die_limit() const {
	return m_die_limit;
}

std::vector<int> proxy::groups_for_upload() {
	return m_mastermind->get_metabalancer_groups(m_groups_count);
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
		session.set_groups(m_mastermind->get_symmetric_groups(group));
	} catch (...) {
		std::clog << "Cannot to determine groups" << std::endl;
	}

	return std::make_pair(session, ioremap::elliptics::key(filename));;
}

} // namespace elliptics

int main(int argc, char **argv) {
	return ioremap::thevoid::run_server<elliptics::proxy>(argc, argv);
}
