#include "proxy.hpp"
#include "data_container.hpp"
#include "lookup_result.hpp"

#include <swarm/url.hpp>

#include <sstream>

namespace elliptics {

void proxy::req_upload::on_request(const ioremap::swarm::http_request &req) {
	m_beg_time = std::chrono::system_clock::now();

	if (const auto &arg = req.headers().content_length()) {
		m_size = *arg;
	} else {
		server()->logger().log(ioremap::swarm::SWARM_LOG_INFO, "Upload: missing Content-Length");
		send_reply(400);
		return;
	}

	// TODO: check %lu prints size_t like %d prints int
	server()->logger().log(ioremap::swarm::SWARM_LOG_INFO, "Upload: handle request: %s; body size: %lu",
		req.url().to_string().c_str(), m_size);

	if (server()->logger().level() >= ioremap::swarm::SWARM_LOG_DEBUG) {
		std::ostringstream oss;
		const auto &headers = req.headers().all();
		oss << "Headers:" << std::endl;
		for (auto it = headers.begin(); it != headers.end(); ++it) {
			oss << it->first << ": " << it->second << std::endl;
		}
		server()->logger().log(ioremap::swarm::SWARM_LOG_DEBUG, "%s", oss.str().c_str());
	}

	// TODO: set chunk size according to config
	set_chunk_size(10 * 1024 * 1024);

	m_session = server()->get_session();

	if (m_session->state_num() < server()->die_limit()) {
		server()->logger().log(ioremap::swarm::SWARM_LOG_ERROR, "Upload: too low number of existing states");
		send_reply(503);
		return;
	}

	auto file_info = server()->get_file_info(req);

	if (file_info.second.name.empty()) {
		server()->logger().log(ioremap::swarm::SWARM_LOG_INFO, "Upload: cannot determine a namespace");
		send_reply(400);
		return;
	}

	m_key = ioremap::elliptics::key(file_info.second.name + '.' + file_info.first);
	m_filename = file_info.first;
	m_session->set_checker(file_info.second.result_checker);
	m_session->set_error_handler(ioremap::elliptics::error_handlers::remove_on_fail(*m_session));
	m_session->set_groups(server()->groups_for_upload(file_info.second));
	m_session->set_filter(ioremap::elliptics::filters::all);

	auto query_list = req.url().query();
	m_offset = get_arg<uint64_t>(query_list, "offset", 0);
	m_embed = query_list.has_item("embed") || query_list.has_item("embed_timestamp");
	if (m_embed) {
		m_timestamp.tv_sec = get_arg<uint64_t>(query_list, "timestamp", 0);
		m_timestamp.tv_nsec = 0;
	}
}

void proxy::req_upload::on_chunk(const boost::asio::const_buffer &buffer, unsigned int flags) {
	if (flags & first_chunk) {
		auto data = std::string(
			boost::asio::buffer_cast<const char *>(buffer)
			, boost::asio::buffer_size(buffer)
			);
		elliptics::data_container_t dc(data);

		if (m_embed) {
			dc.set<elliptics::DNET_FCGI_EMBED_TIMESTAMP>(m_timestamp);
		}

		if (dc.embeds_count() != 0) {
			m_session->set_user_flags(m_session->get_user_flags() | UF_EMBEDS);
		}

		m_content = elliptics::data_container_t::pack(dc);
	} else {
		m_content = ioremap::elliptics::data_pointer::from_raw(
			const_cast<char *>(boost::asio::buffer_cast<const char *>(buffer))
			, boost::asio::buffer_size(buffer)
			);
	}

	if (server()->logger().level() >= ioremap::swarm::SWARM_LOG_INFO) {
		std::ostringstream oss;

		auto groups = m_session->get_groups();
		oss << "Upload: writing content by key=" << m_key.to_string() << " into groups=[";

		for (auto it = groups.begin(); it != groups.end(); ++it) {
			if (it != groups.begin())
				oss << ", ";
			oss << *it;
		}

		oss << ']';

		server()->logger().log(ioremap::swarm::SWARM_LOG_INFO, "%s", oss.str().c_str());
	}

	auto awr = write(flags);
	m_offset += m_content.size();

	{
		using namespace std::placeholders;

		if (flags & last_chunk) {
			awr.connect(std::bind(&req_upload::on_finished, shared_from_this(), _1, _2));
		} else {
			awr.connect(std::bind(&req_upload::on_wrote, shared_from_this(), _1, _2));
		}
	}
}

void proxy::req_upload::on_error(const boost::system::error_code &err) {
	server()->logger().log(ioremap::swarm::SWARM_LOG_ERROR, "Upload on_error: %s", err.message().c_str());
	send_reply(500);
}

void proxy::req_upload::on_wrote(const ioremap::elliptics::sync_write_result &swr, const ioremap::elliptics::error_info &error) {
	// TODO: add logs
	if (error) {
		on_finished(swr, error);
		return;
	}

	std::vector<int> groups;

	for (auto it = swr.begin(); it != swr.end(); ++it) {
		if (!it->error()) {
			groups.push_back(it->command()->id.group_id);
		}
	}

	m_session->set_groups(groups);

	try_next_chunk();
}

void proxy::req_upload::on_finished(const ioremap::elliptics::sync_write_result &swr, const ioremap::elliptics::error_info &error) {
	// TODO: add logs
	if (error) {
		std::vector<int> good_groups;
		std::vector<int> bad_groups;

		for (auto it = swr.begin(); it != swr.end(); ++it) {
			int group = it->command()->id.group_id;
			if (!it->error()) {
				good_groups.push_back(group);
			} else {
				bad_groups.push_back(group);
			}
		}

		std::ostringstream oss;
		oss << "Upload: on_wrote: " << error.message().c_str();
		oss << "; wrote into groups: [";
		for (auto itb = good_groups.begin(), it = itb; it != good_groups.end(); ++it) {
			if (it != itb) oss << ", ";
			oss << *it;
		}
		oss << "]; cannot write into: [";
		for (auto itb = bad_groups.begin(), it = itb; it != bad_groups.end(); ++it) {
			if (it != itb) oss << ", ";
			oss << *it;
		}
		oss << ']';

		server()->logger().log(ioremap::swarm::SWARM_LOG_ERROR, "%s", oss.str().c_str());

		send_reply(500);
		return;
	}

	std::ostringstream oss;

	oss 
		<< "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
		<< "<post obj=\"" << m_key.remote() << "\" id=\""
		<< id_str(m_key, *m_session)
		<< "\" groups=\"" << swr.size()
		<< "\" size=\"" << m_size
		<< "\" key=\"/";
	{
		auto groups = m_session->get_groups();
		auto git = std::min_element(groups.begin(), groups.end());
		oss << *git;
	}
	oss << '/' << m_filename << "\">\n";

	size_t written = 0;
	std::vector<int> wrote_into_groups;
	for (auto it = swr.begin(); it != swr.end(); ++it) {
		auto pl = server()->parse_lookup(*it);
		if (pl.status() == 0)
			written += 1;
		oss << "<complete addr=\"" << pl.addr() << "\" path=\"" <<
			pl.full_path() << "\" group=\"" << pl.group() <<
			"\" status=\"" << pl.status() << "\"/>\n";
		wrote_into_groups.push_back(pl.group());
	}

	oss
		<< "<written>" << written << "</written>\n"
		<< "</post>";

	auto res_str = oss.str();

	ioremap::swarm::http_response reply;
	ioremap::swarm::http_headers headers;

	reply.set_code(200);
	headers.set_content_length(res_str.size());
	headers.set_content_type("text/plain");
	reply.set_headers(headers);

	send_reply(std::move(reply), std::move(res_str));

	auto end_time = std::chrono::system_clock::now();

	if (server()->logger().level() >= ioremap::swarm::SWARM_LOG_INFO){
		std::ostringstream oss;
		oss
			<< "Upload: done; status code: 200; spent time: "
			<< std::chrono::duration_cast<std::chrono::milliseconds>(end_time - m_beg_time).count()
			<< "; wrote into groups: [";
		for (auto itb = wrote_into_groups.begin(), it = itb; it != wrote_into_groups.end(); ++it) {
			if (it != itb) oss << ", ";
			oss << *it;
		}
		oss << ']';
		server()->logger().log(ioremap::swarm::SWARM_LOG_INFO, "%s", oss.str().c_str());
	}
}

ioremap::elliptics::async_write_result proxy::req_upload::write(unsigned int flags) {
	if (flags & first_chunk) {
		return m_session->write_prepare(m_key, m_content, m_offset, m_size);
	} else if (flags & last_chunk) {
		return m_session->write_commit(m_key, m_content, m_offset, m_size);
	}
	return m_session->write_plain(m_key, m_content, m_offset);
}

} // elliptics
