#ifndef SRC__PROXY_HPP
#define SRC__PROXY_HPP

#include "lookup_result.hpp"
#include "loggers.hpp"
#include "magic_provider.hpp"

#include <elliptics/session.hpp>
#include <libmastermind/mastermind.hpp>
#include <thevoid/server.hpp>

#include <boost/optional.hpp>
#include <boost/thread/tss.hpp>

#include <swarm/url_query.hpp>

#include <crypto++/hmac.h>
#include <crypto++/sha.h>

#include <memory>
#include <utility>
#include <map>
#include <chrono>
#include <vector>
#include <mutex>

namespace elliptics {

template <typename T>
T get_arg(const ioremap::swarm::url_query &query_list, const std::string &name, const T &default_value = T()) {
	auto &&arg = query_list.item_value(name);
	return arg ? boost::lexical_cast<T>(*arg) : default_value;
}

std::string id_str(const ioremap::elliptics::key &key, ioremap::elliptics::session sess);

enum tag_user_flags {
	UF_EMBEDS = 1
};

struct namespace_t {
	std::string name;
	int groups_count;
	ioremap::elliptics::result_checker result_checker;
	std::string auth_key;
	std::vector<int> static_couple;
	std::string sign_token;
	std::string sign_path_prefix;
	std::string sign_port;
};

typedef std::shared_ptr<namespace_t> namespace_ptr_t;

class proxy : public ioremap::thevoid::server<proxy>
{
public:

	bool initialize(const rapidjson::Value &config);

	struct req_upload
		: public ioremap::thevoid::buffered_request_stream<proxy>
		, public std::enable_shared_from_this<req_upload>
	{
		void on_request(const ioremap::swarm::http_request &req);
		void on_chunk(const boost::asio::const_buffer &buffer, unsigned int flags);
		void on_error(const boost::system::error_code &err);

		void on_wrote(const ioremap::elliptics::sync_write_result &swr, const ioremap::elliptics::error_info &error);
		void on_finished(const ioremap::elliptics::sync_write_result &swr, const ioremap::elliptics::error_info &error);

	private:
		ioremap::elliptics::async_write_result write(unsigned int flags);

		boost::optional<ioremap::elliptics::session> m_session;
		size_t m_offset;
		size_t m_size;
		bool m_embed;
		dnet_time m_timestamp;
		ioremap::elliptics::key m_key;
		std::string m_filename;
		ioremap::elliptics::data_pointer m_content;
		std::chrono::system_clock::time_point m_beg_time;
		std::vector<int> m_bad_groups;
		bool m_is_static_ns;
		namespace_ptr_t ns;
	};

	struct req_get
		: public ioremap::thevoid::simple_request_stream<proxy>
		, public std::enable_shared_from_this<req_get>
	{
		void on_request(const ioremap::swarm::http_request &req, const boost::asio::const_buffer &buffer);
		void on_lookup(const ioremap::elliptics::sync_read_result &slr, const ioremap::elliptics::error_info &error);
		void read_chunk();
		void on_read_chunk(const ioremap::elliptics::sync_read_result &srr, const ioremap::elliptics::error_info &error);
		void on_sent_chunk(const boost::system::error_code &error);
	private:
		boost::optional<ioremap::elliptics::session> m_session;
		ioremap::elliptics::key m_key;

		size_t m_offset;
		size_t m_size;
		size_t m_chunk_size;
		bool m_embed;

		boost::optional<std::string> m_if_modified_since;
		bool m_first_chunk;

		std::chrono::system_clock::time_point m_beg_time;
	};

	struct req_delete
		: public ioremap::thevoid::simple_request_stream<proxy>
		, public std::enable_shared_from_this<req_delete>
	{
		void on_request(const ioremap::swarm::http_request &req, const boost::asio::const_buffer &buffer);
		void on_finished(const ioremap::elliptics::sync_remove_result &srr, const ioremap::elliptics::error_info &error);
	};

	struct req_download_info
		: public ioremap::thevoid::simple_request_stream<proxy>
		, public std::enable_shared_from_this<req_download_info>
	{
		void on_request(const ioremap::swarm::http_request &req, const boost::asio::const_buffer &buffer);
		void on_finished(const ioremap::elliptics::sync_lookup_result &slr, const ioremap::elliptics::error_info &error);

	private:
		namespace_ptr_t ns;
	};

	struct req_ping
		: public ioremap::thevoid::simple_request_stream<proxy>
		, public std::enable_shared_from_this<req_ping>
	{
		void on_request(const ioremap::swarm::http_request &req, const boost::asio::const_buffer &buffer);
	};

	struct req_stat_log
		: public ioremap::thevoid::simple_request_stream<proxy>
		, public std::enable_shared_from_this<req_stat_log>
	{
		void on_request(const ioremap::swarm::http_request &req, const boost::asio::const_buffer &buffer);
		void on_finished(const ioremap::elliptics::sync_stat_result &ssr, const ioremap::elliptics::error_info &error);
	};

	struct req_cache
		: public ioremap::thevoid::simple_request_stream<proxy>
		, public std::enable_shared_from_this<req_cache>
	{
		void on_request(const ioremap::swarm::http_request &req, const boost::asio::const_buffer &buffer);
	};

	struct req_cache_update
		: public ioremap::thevoid::simple_request_stream<proxy>
		, public std::enable_shared_from_this<req_cache_update>
	{
		void on_request(const ioremap::swarm::http_request &req, const boost::asio::const_buffer &buffer);
	};

protected:
	ioremap::elliptics::session get_session();
	namespace_ptr_t get_namespace(const std::string &scriptname);
	elliptics::lookup_result parse_lookup(const ioremap::elliptics::lookup_result_entry &entry, const namespace_ptr_t &ns);
	int die_limit() const;
	std::pair<std::string, elliptics::namespace_ptr_t> get_file_info(const ioremap::swarm::http_request &req);
	std::vector<int> get_groups(int group, const std::string &filename);
	std::pair<ioremap::elliptics::session, ioremap::elliptics::key> prepare_session(const ioremap::swarm::http_request &req);
	std::pair<ioremap::elliptics::session, ioremap::elliptics::key> prepare_session(const std::string &url, const namespace_ptr_t &ns);
	std::vector<int> groups_for_upload(const elliptics::namespace_ptr_t &name_space, uint64_t size);
	ioremap::swarm::logger &logger();
    std::shared_ptr<mastermind::mastermind_t> &mastermind();
	bool check_basic_auth(const std::string &ns, const std::string &auth_key, const boost::optional<std::string> &auth_header);
	std::string hmac(const std::string &data, const namespace_ptr_t &ns);

	void namespaces_auto_update();

private:
	boost::optional<ioremap::elliptics::node> m_elliptics_node;
	boost::optional<ioremap::elliptics::session> m_elliptics_session;
	boost::optional<elliptics_logger_t> m_elliptics_logger;
	boost::optional<ioremap::swarm::logger> m_proxy_logger;
	boost::optional<ioremap::swarm::logger> m_mastermind_logger;
	int m_die_limit;
	bool m_eblob_style_path;
	int m_direction_bit_num;
	int m_base_port;
	int m_groups_count;
	int m_write_chunk_size;
	int m_read_chunk_size;
	std::shared_ptr<mastermind::mastermind_t> m_mastermind;
	std::map<std::string, namespace_ptr_t> m_namespaces;
	bool m_namespaces_auto_update;
	std::mutex m_namespaces_mutex;
	boost::thread_specific_ptr<magic_provider> m_magic;

	typedef CryptoPP::HMAC<CryptoPP::SHA512> hmac_type;
};

} // namespace elliptics

#endif /* SRC__PROXY_HPP */
