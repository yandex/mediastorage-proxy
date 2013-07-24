#ifndef SRC__PROXY_HPP
#define SRC__PROXY_HPP

#include "lookup_result.hpp"

#include <elliptics/session.hpp>
#include <elliptics/mastermind.hpp>
#include <thevoid/server.hpp>

#include <boost/optional.hpp>

#include <memory>
#include <utility>

namespace elliptics {

class proxy : public ioremap::thevoid::server<proxy>
{
public:

	bool initialize(const rapidjson::Value &config);

	struct req_upload
		: public ioremap::thevoid::simple_request_stream<proxy>
	{
		void on_request(const ioremap::swarm::network_request &req, const boost::asio::const_buffer &buffer);
	};

	struct req_get
		: public ioremap::thevoid::simple_request_stream<proxy>
	{
		void on_request(const ioremap::swarm::network_request &req, const boost::asio::const_buffer &buffer);
	};

	struct req_delete
		: public ioremap::thevoid::simple_request_stream<proxy>
	{
		void on_request(const ioremap::swarm::network_request &req, const boost::asio::const_buffer &buffer);
	};

	struct req_download_info
		: public ioremap::thevoid::simple_request_stream<proxy>
	{
		void on_request(const ioremap::swarm::network_request &req, const boost::asio::const_buffer &buffer);
	};

	struct req_ping
		: public ioremap::thevoid::simple_request_stream<proxy>
	{
		void on_request(const ioremap::swarm::network_request &req, const boost::asio::const_buffer &buffer);
	};

	struct req_stat_log
		: public ioremap::thevoid::simple_request_stream<proxy>
	{
		void on_request(const ioremap::swarm::network_request &req, const boost::asio::const_buffer &buffer);
	};

protected:
	ioremap::elliptics::session get_session();
	elliptics::lookup_result parse_lookup(const ioremap::elliptics::lookup_result_entry &entry);
	int die_limit() const;
	std::pair<ioremap::elliptics::session, ioremap::elliptics::key> prepare_session(const ioremap::swarm::network_request &req);
	std::vector<int> groups_for_upload();

private:
	boost::optional<ioremap::elliptics::session> m_elliptics_session;
	int m_die_limit;
	bool m_eblob_style_path;
	int m_base_port;
	int m_groups_count;
	std::shared_ptr<elliptics::mastermind_t> m_mastermind;
};

} // namespace elliptics

#endif /* SRC__PROXY_HPP */
