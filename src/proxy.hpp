#ifndef SRC__PROXY_HPP
#define SRC__PROXY_HPP

#include "lookup_result.hpp"

#include <elliptics/session.hpp>
#include <elliptics/mastermind.hpp>
#include <thevoid/server.hpp>

#include <boost/optional.hpp>

#include <swarm/network_query_list.h>

#include <memory>
#include <utility>
#include <map>

namespace elliptics {

struct namespace_t {
	std::string name;
	int groups_count;
	ioremap::elliptics::result_checker result_checker;
};

class proxy : public ioremap::thevoid::server<proxy>
{
public:

	bool initialize(const rapidjson::Value &config);

	struct req_upload
		: public ioremap::thevoid::simple_request_stream<proxy>
		, public std::enable_shared_from_this<req_upload>
	{
		void on_request(const ioremap::swarm::network_request &req, const boost::asio::const_buffer &buffer);
		void on_finished(const ioremap::elliptics::sync_write_result &swr, const ioremap::elliptics::error_info &error);

	private:
		boost::optional<ioremap::elliptics::session> m_session;
		ioremap::elliptics::key m_key;
		ioremap::elliptics::data_pointer m_content;
	};

	struct req_get
		: public ioremap::thevoid::simple_request_stream<proxy>
		, public std::enable_shared_from_this<req_get>
	{
		void on_request(const ioremap::swarm::network_request &req, const boost::asio::const_buffer &buffer);
		void on_finished(const ioremap::elliptics::sync_read_result &srr, const ioremap::elliptics::error_info &error, const boost::optional<std::string> &if_modified_since);
	private:
		ioremap::swarm::network_query_list m_query_list;
	};

	struct req_delete
		: public ioremap::thevoid::simple_request_stream<proxy>
		, public std::enable_shared_from_this<req_delete>
	{
		void on_request(const ioremap::swarm::network_request &req, const boost::asio::const_buffer &buffer);
		void on_finished(const ioremap::elliptics::sync_remove_result &srr, const ioremap::elliptics::error_info &error);
	};

	struct req_download_info
		: public ioremap::thevoid::simple_request_stream<proxy>
		, public std::enable_shared_from_this<req_download_info>
	{
		void on_request(const ioremap::swarm::network_request &req, const boost::asio::const_buffer &buffer);
		void on_finished(const ioremap::elliptics::sync_lookup_result &slr, const ioremap::elliptics::error_info &error);
	};

	struct req_ping
		: public ioremap::thevoid::simple_request_stream<proxy>
		, public std::enable_shared_from_this<req_ping>
	{
		void on_request(const ioremap::swarm::network_request &req, const boost::asio::const_buffer &buffer);
	};

	struct req_stat_log
		: public ioremap::thevoid::simple_request_stream<proxy>
		, public std::enable_shared_from_this<req_stat_log>
	{
		void on_request(const ioremap::swarm::network_request &req, const boost::asio::const_buffer &buffer);
		void on_finished(const ioremap::elliptics::sync_stat_result &ssr, const ioremap::elliptics::error_info &error);
	};

protected:
	ioremap::elliptics::session get_session();
	elliptics::lookup_result parse_lookup(const ioremap::elliptics::lookup_result_entry &entry);
	int die_limit() const;
	std::pair<ioremap::elliptics::key, elliptics::namespace_t> get_file_info(const ioremap::swarm::network_request &req);
	std::pair<ioremap::elliptics::session, ioremap::elliptics::key> prepare_session(const ioremap::swarm::network_request &req);
	std::vector<int> groups_for_upload(const elliptics::namespace_t &name_space);
	ioremap::swarm::logger &logger();

private:
	boost::optional<ioremap::elliptics::session> m_elliptics_session;
	boost::optional<ioremap::swarm::logger> m_elliptics_logger;
	boost::optional<ioremap::swarm::logger> m_proxy_logger;
	boost::optional<ioremap::swarm::logger> m_mastermind_logger;
	int m_die_limit;
	bool m_eblob_style_path;
	int m_direction_bit_num;
	int m_base_port;
	int m_groups_count;
	std::shared_ptr<elliptics::mastermind_t> m_mastermind;
	std::map<std::string, namespace_t> m_namespaces;
};

} // namespace elliptics

#endif /* SRC__PROXY_HPP */
