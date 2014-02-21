#include "proxy.hpp"
#include "data_container.hpp"

#include <swarm/url.hpp>

#include <functional>

namespace elliptics {

void proxy::req_get::on_request(const ioremap::swarm::http_request &req, const boost::asio::const_buffer &buffer) {
	m_beg_time = std::chrono::system_clock::now();
	server()->logger().log(ioremap::swarm::SWARM_LOG_INFO, "Get: handle request: %s", req.url().to_string().c_str());
	try {
		auto &&prep_session = server()->prepare_session(req);
		m_session = prep_session.first;
		m_key = prep_session.second;
	} catch (const std::exception &ex) {
		server()->logger().log(
			ioremap::swarm::SWARM_LOG_INFO,
			"Get: request = \"%s\"; err: \"%s\"",
			req.url().to_string().c_str(), ex.what());
		send_reply(400);
		return;
	}

	if (m_session->get_groups().empty()) {
		server()->logger().log(ioremap::swarm::SWARM_LOG_INFO, "Get: on_request: cannot find couple of groups for the request");
		send_reply(404);
		return;
	}

	auto query_list = req.url().query();
	m_offset = get_arg<uint64_t>(query_list, "offset", 0);
	m_size = get_arg<uint64_t>(query_list, "size", 0);
	m_embed = query_list.has_item("embed") || query_list.has_item("embed_timestamp");
	m_if_modified_since = req.headers().get("If-Modified-Since");
	m_first_chunk = true;
	m_chunk_size = server()->m_read_chunk_size;

	if (m_size == 0) {
		auto alr = m_session->lookup(m_key);
		alr.connect(std::bind(&proxy::req_get::on_lookup, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
	} else {
		read_chunk();
	}
}

void proxy::req_get::on_lookup(const ioremap::elliptics::sync_lookup_result &slr, const ioremap::elliptics::error_info &error) {
	if (error) {
		if (error.code() == -ENOENT) {
			server()->logger().log(ioremap::swarm::SWARM_LOG_INFO, "Get: on_lookup: file %s not found", m_key.remote().c_str());
			send_reply(404);
		} else {
			server()->logger().log(ioremap::swarm::SWARM_LOG_ERROR, "Get: on_lookup: %s", error.message().c_str());
			send_reply(500);
		}
		return;
	}
	const auto &entry = slr.front();
	m_size = entry.file_info()->size;

	std::vector<int> groups;
	groups.push_back(entry.command()->id.group_id);
	m_session->set_groups(groups);

	read_chunk();
}

void proxy::req_get::read_chunk() {
	if (server()->logger().level() >= ioremap::swarm::SWARM_LOG_INFO){
		std::ostringstream oss;
		oss
			<< "Get: read_chunk: chunk_size=" << m_chunk_size
			<< " file_size=" << m_size << " offset=" << m_offset
			<< " data_left=" << (m_size - m_offset)
			<< " groups: [";
		auto groups = m_session->get_groups();
		for (auto itb = groups.begin(), it = itb; it != groups.end(); ++it) {
			if (it != itb) oss << ", ";
			oss << *it;
		}
		oss << ']';

		server()->logger().log(ioremap::swarm::SWARM_LOG_INFO, "%s", oss.str().c_str());
	}

	server()->logger().log(ioremap::swarm::SWARM_LOG_DEBUG, "Get: read_chunk: reading of chunks is starting");
	auto arr = m_session->read_data(m_key, m_offset, m_chunk_size);
	arr.connect(std::bind(&proxy::req_get::on_read_chunk, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
}

void proxy::req_get::on_read_chunk(const ioremap::elliptics::sync_read_result &srr, const ioremap::elliptics::error_info &error) {
	if (error) {
		server()->logger().log(ioremap::swarm::SWARM_LOG_ERROR, "Get: on_read_chunk: %s", error.message().c_str());
		send_reply(500);
		return;
	}

	server()->logger().log(ioremap::swarm::SWARM_LOG_DEBUG, "Get: on_read_chunk: got a chunk");

	const auto &rr = srr.front();

	if (rr.io_attribute()->user_flags & UF_EMBEDS) {
		m_embed = true;
	}

	std::string data;

	if (m_first_chunk) {
		m_first_chunk = false;

		auto dc = elliptics::data_container_t::unpack(rr.file(), m_embed);
		auto ts = dc.get<elliptics::DNET_FCGI_EMBED_TIMESTAMP>();

		ioremap::swarm::http_response reply;
		reply.set_code(200);
		reply.headers().set_content_length(m_size);
		// TODO: detect Content-Type
		reply.headers().set_content_type("text/plain");

		if (ts) {
			char ts_str[128] = {0};
			time_t timestamp = (time_t)(ts->tv_sec);
			struct tm tmp;
			strftime(ts_str, sizeof (ts_str), "%a, %d %b %Y %T %Z", gmtime_r(&timestamp, &tmp));
			
			if (m_if_modified_since) {
				if (*m_if_modified_since == ts_str) {
					send_reply(304);
					return;
				}
			}

			reply.headers().set_last_modified(ts_str);
		}

		send_headers(std::move(reply), std::function<void (const boost::system::error_code &)>());

		dc.data.to_string().swap(data);
	} else {
		rr.file().to_string().swap(data);
	}

	send_data(std::move(data), std::bind(&proxy::req_get::on_sent_chunk, shared_from_this(), std::placeholders::_1));
	m_offset += data.size();
}

void proxy::req_get::on_sent_chunk(const boost::system::error_code &error) {
	if (error) {
		server()->logger().log(ioremap::swarm::SWARM_LOG_ERROR, "get: on_sent_chunk: %s", error.message().c_str());
		get_reply()->close(error);
		return;
	}

	if (m_offset < m_size) {
		read_chunk();
		return;
	}

	if (server()->logger().level() >= ioremap::swarm::SWARM_LOG_INFO) {
		auto end_time = std::chrono::system_clock::now();
		auto spent_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - m_beg_time).count();

		std::ostringstream oss;
		oss
			<< "Get: on_finished: request=" << request().url().to_string() << " spent_time=" << spent_time
			<< " file_size=" << m_size;

		server()->logger().log(ioremap::swarm::SWARM_LOG_INFO, "%s", oss.str().c_str());
	}
}

}

