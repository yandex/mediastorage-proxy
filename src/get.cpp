#include "proxy.hpp"
#include "data_container.hpp"

#include <swarm/url.hpp>

#include <functional>

namespace elliptics {

void proxy::req_get::on_request(const ioremap::swarm::http_request &req, const boost::asio::const_buffer &buffer) {
	m_beg_time = std::chrono::system_clock::now();
	url_str = req.url().to_string();
	server()->logger().log(ioremap::swarm::SWARM_LOG_INFO, "Get: handle request: %s", url_str.c_str());
	namespace_ptr_t ns;
	try {
		ns = server()->get_namespace(url_str, "/get");
		auto &&prep_session = server()->prepare_session(url_str, ns);
		m_session = prep_session.first;
		m_session->set_timeout(server()->timeout.read);
		m_key = prep_session.second;
		m_key.transform(*m_session);
		m_key.set_id(m_key.id());
	} catch (const std::exception &ex) {
		server()->logger().log(
			ioremap::swarm::SWARM_LOG_INFO,
			"Get: request = \"%s\"; err: \"%s\"",
			req.url().to_string().c_str(), ex.what());
		send_reply(400);
		return;
	}

	if (!server()->check_basic_auth(ns->name, ns->auth_key_for_read, req.headers().get("Authorization"))) {
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

	if (m_session->get_groups().empty()) {
		server()->logger().log(ioremap::swarm::SWARM_LOG_INFO
				, "Get %s: on_request: cannot find couple of groups for the request"
				, url_str.c_str());
		send_reply(404);
		return;
	}

	auto query_list = req.url().query();
	m_offset = get_arg<uint64_t>(query_list, "offset", 0);
	m_size = get_arg<uint64_t>(query_list, "size", 0);
	m_if_modified_since = req.headers().get("If-Modified-Since");
	m_first_chunk = true;
	m_chunk_size = server()->m_read_chunk_size;

	// Read 1 byte to get total_size of file cause lookup doesn't look up into cache
	{
		std::ostringstream oss;
		oss << "Get " << m_key.remote() << " " << m_key.to_string()
			<< ": lookup(read 1 byte) from groups [";
		const auto &groups = m_session->get_groups();
		for (auto bit = groups.begin(), it = bit, end = groups.end(); it != end; ++it) {
			if (it != bit) oss << ", ";
			oss << *it;
		}
		oss << ']';
		auto msg = oss.str();
		server()->logger().log(ioremap::swarm::SWARM_LOG_INFO, "%s", msg.c_str());
	}
	{
		auto ioflags = m_session->get_ioflags();
		m_session->set_ioflags(ioflags | DNET_IO_FLAGS_NOCSUM);
		auto alr = m_session->read_data(m_key, 0, 1);
		alr.connect(std::bind(&proxy::req_get::on_lookup, shared_from_this(),
					std::placeholders::_1, std::placeholders::_2));
		m_session->set_ioflags(ioflags);
	}
}

void proxy::req_get::on_lookup(const ioremap::elliptics::sync_read_result &slr, const ioremap::elliptics::error_info &error) {
	if (error) {
		if (error.code() == -ENOENT) {
			server()->logger().log(ioremap::swarm::SWARM_LOG_INFO
					, "Get %s %s: on_lookup: file not found"
					, m_key.remote().c_str(), m_key.to_string().c_str());
			send_reply(404);
		} else {
			server()->logger().log(ioremap::swarm::SWARM_LOG_ERROR
					, "Get %s %s: on_lookup: %s"
					, m_key.remote().c_str(), m_key.to_string().c_str(), error.message().c_str());
			send_reply(500);
		}
		return;
	}
	const auto &entry = slr.front();
	auto total_size = entry.io_attribute()->total_size;

	if (m_offset >= total_size) {
		server()->logger().log(ioremap::swarm::SWARM_LOG_INFO
				, "Get %s %s: offset greater than total_size"
				, m_key.remote().c_str()
				, m_key.to_string().c_str());
		send_reply(400);
		return;
	}

	total_size -= m_offset;

	if (m_size == 0 || m_size > total_size) {
		m_size = total_size;
	}

	std::vector<int> groups;
	groups.push_back(entry.command()->id.group_id);
	m_session->set_groups(groups);

	read_chunk();
}

void proxy::req_get::read_chunk() {
	if (server()->logger().level() >= ioremap::swarm::SWARM_LOG_INFO){
		std::ostringstream oss;
		oss
			<< "Get " << m_key.remote() << " " << m_key.to_string()
			<< ": read_chunk: chunk_size=" << m_chunk_size
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

	if (m_first_chunk) {
		if (server()->timeout_coef.data_flow_rate) {
			m_session->set_timeout(
					m_session->get_timeout() + m_size / server()->timeout_coef.data_flow_rate);
		}
	} else {
		m_session->set_timeout(server()->timeout.read);
		m_session->set_ioflags(m_session->get_ioflags() | DNET_IO_FLAGS_NOCSUM);
	}
	auto arr = m_session->read_data(m_key, m_offset, m_chunk_size);
	arr.connect(std::bind(&proxy::req_get::on_read_chunk, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
}

void proxy::req_get::on_read_chunk(const ioremap::elliptics::sync_read_result &srr, const ioremap::elliptics::error_info &error) {
	if (error) {
		server()->logger().log(ioremap::swarm::SWARM_LOG_ERROR
				, "Get %s %s: on_read_chunk: %s"
				, m_key.remote().c_str(), m_key.to_string().c_str(), error.message().c_str());
		send_reply(500);
		return;
	}

	server()->logger().log(ioremap::swarm::SWARM_LOG_INFO
			, "Get %s %s: on_read_chunk: chunk was read"
			, m_key.remote().c_str(), m_key.to_string().c_str());

	const auto &rr = srr.front();
	auto file = rr.file();

	std::string data = file.to_string();

	if (m_first_chunk) {
		m_first_chunk = false;

		ioremap::swarm::http_response reply;
		reply.set_code(200);
		reply.headers().set_content_length(m_size);

		if (NULL == server()->m_magic.get()) {
			server()->m_magic.reset(new magic_provider());
		}

		reply.headers().set_content_type(server()->m_magic->type(data));

		{
			time_t timestamp = (time_t)(rr.io_attribute()->timestamp.tsec);

			char ts_str[128] = {0};
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
	}

	send_data(std::move(data), std::bind(&proxy::req_get::on_sent_chunk, shared_from_this(), std::placeholders::_1));
	m_offset += file.size();
}

void proxy::req_get::on_sent_chunk(const boost::system::error_code &error) {
	if (error) {
		server()->logger().log(ioremap::swarm::SWARM_LOG_ERROR
				, "Get %s %s: on_sent_chunk: %s"
				, m_key.remote().c_str(), m_key.to_string().c_str(), error.message().c_str());
		get_reply()->close(error);
		return;
	}

	server()->logger().log(ioremap::swarm::SWARM_LOG_INFO
			, "Get %s %s: chunk was sent"
			, m_key.remote().c_str(), m_key.to_string().c_str());

	if (m_offset < m_size) {
		read_chunk();
		return;
	}

	if (server()->logger().level() >= ioremap::swarm::SWARM_LOG_INFO) {
		auto end_time = std::chrono::system_clock::now();
		auto spent_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - m_beg_time).count();

		std::ostringstream oss;
		oss
			<< "Get " << m_key.remote() << " " << m_key.to_string()
			<< ": on_finished: request=" << request().url().to_string() << " spent_time=" << spent_time
			<< " file_size=" << m_size;

		server()->logger().log(ioremap::swarm::SWARM_LOG_INFO, "%s", oss.str().c_str());
	}

	get_reply()->close(error);
}

}

