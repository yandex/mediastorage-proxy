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

#ifndef SRC__PROXY_HPP
#define SRC__PROXY_HPP

#include "lookup_result.hpp"
#include "loggers.hpp"
#include "magic_provider.hpp"
#include "utils.hpp"
#include "cdn_cache.hpp"

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
#include <tuple>

#if __GNUC__ == 4 && __GNUC_MINOR__ >= 6
#include <atomic>
#else
#include <cstdatomic>
#endif

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
	std::string auth_key_for_write;
	std::string auth_key_for_read;
	std::vector<int> static_couple;
	std::string sign_token;
	std::string sign_path_prefix;
	std::string sign_port;

	std::chrono::seconds redirect_expire_time;
	int64_t redirect_content_length_threshold;

	bool can_choose_couple_to_upload;
	int64_t multipart_content_length_threshold;

	int success_copies_num;
};

typedef std::shared_ptr<namespace_t> namespace_ptr_t;

class proxy : public ioremap::thevoid::server<proxy>
{
public:
	~proxy();

	bool initialize(const rapidjson::Value &config);

	struct req_delete
		: public ioremap::thevoid::simple_request_stream<proxy>
		, public std::enable_shared_from_this<req_delete>
	{
		void on_request(const ioremap::thevoid::http_request &req, const boost::asio::const_buffer &buffer);
		void on_lookup(const ioremap::elliptics::sync_lookup_result &slr, const ioremap::elliptics::error_info &error);
		void on_finished(const ioremap::elliptics::sync_remove_result &srr, const ioremap::elliptics::error_info &error);

	private:
		std::string url_str;
		ioremap::elliptics::key key;
		boost::optional<ioremap::elliptics::session> session;
		size_t total_size;
	};

	struct req_download_info
		: public ioremap::thevoid::simple_request_stream<proxy>
		, public std::enable_shared_from_this<req_download_info>
	{
		req_download_info(const std::string &handler_name_);
		void on_request(const ioremap::thevoid::http_request &req, const boost::asio::const_buffer &buffer);
		void on_finished(const ioremap::elliptics::sync_lookup_result &slr, const ioremap::elliptics::error_info &error);

	private:
		namespace_ptr_t ns;
		std::string x_regional_host;
		std::string handler_name;
	};

	struct req_download_info_1 : public req_download_info {
		req_download_info_1();
		static const std::string handler_name;
	};

	struct req_download_info_2 : public req_download_info {
		req_download_info_2();
		static const std::string handler_name;
	};

	struct req_ping
		: public ioremap::thevoid::simple_request_stream<proxy>
		, public std::enable_shared_from_this<req_ping>
	{
		void on_request(const ioremap::thevoid::http_request &req, const boost::asio::const_buffer &buffer);
	};

	struct req_cache
		: public ioremap::thevoid::simple_request_stream<proxy>
		, public std::enable_shared_from_this<req_cache>
	{
		void on_request(const ioremap::thevoid::http_request &req, const boost::asio::const_buffer &buffer);
	};

	struct req_cache_update
		: public ioremap::thevoid::simple_request_stream<proxy>
		, public std::enable_shared_from_this<req_cache_update>
	{
		void on_request(const ioremap::thevoid::http_request &req, const boost::asio::const_buffer &buffer);
	};

	struct req_statistics
		: public ioremap::thevoid::simple_request_stream<proxy>
		, public std::enable_shared_from_this<req_statistics>
	{
		void on_request(const ioremap::thevoid::http_request &req, const boost::asio::const_buffer &buffer);
	};

	struct req_stats
		: public ioremap::thevoid::simple_request_stream<proxy>
		, public std::enable_shared_from_this<req_stats>
	{
		void on_request(const ioremap::thevoid::http_request &req, const boost::asio::const_buffer &buffer);
	};

protected:
public:
	template <typename T>
	void register_handler(const std::string &name, bool exact_match);

	ioremap::elliptics::node generate_node(const rapidjson::Value &config, int &timeout_def);
	std::shared_ptr<mastermind::mastermind_t> generate_mastermind(const rapidjson::Value &config);
	std::shared_ptr<cdn_cache_t> generate_cdn_cache(const rapidjson::Value &config);

	ioremap::elliptics::session get_session();

	ioremap::elliptics::session
	read_session(const ioremap::thevoid::http_request &http_request, const couple_t &couple);

	ioremap::elliptics::session
	write_session(const ioremap::thevoid::http_request &http_request, const couple_t &couple);

	ioremap::elliptics::session
	remove_session(const ioremap::thevoid::http_request &http_request, const couple_t &couple);

	ioremap::elliptics::session
	lookup_session(const ioremap::thevoid::http_request &http_request, const couple_t &couple);

	ioremap::elliptics::session
	setup_session(ioremap::elliptics::session session
			, const ioremap::thevoid::http_request &http_request, const couple_t &couple);

	namespace_ptr_t get_namespace(const ioremap::thevoid::http_request &req, const std::string &handler_name);
	namespace_ptr_t get_namespace(const std::string &scriptname, const std::string &handler_name);
	elliptics::lookup_result parse_lookup(const ioremap::elliptics::lookup_result_entry &entry, const namespace_ptr_t &ns);
	int die_limit() const;
	std::pair<std::string, elliptics::namespace_ptr_t> get_file_info(const ioremap::thevoid::http_request &req);
	std::vector<int> get_groups(int group, const std::string &filename);
	std::pair<ioremap::elliptics::session, ioremap::elliptics::key> prepare_session(const ioremap::thevoid::http_request &req, const std::string &handler_name);
	std::pair<ioremap::elliptics::session, ioremap::elliptics::key> prepare_session(const std::string &url, const namespace_ptr_t &ns);
	std::vector<int> groups_for_upload(const elliptics::namespace_ptr_t &name_space, uint64_t size);
    std::shared_ptr<mastermind::mastermind_t> &mastermind();
	std::string get_auth_token(const boost::optional<std::string> &auth_header);
	bool check_basic_auth(const std::string &ns, const std::string &auth_key, const boost::optional<std::string> &auth_header);
	std::string hmac(const std::string &data, const namespace_ptr_t &ns);

	std::tuple<std::string, std::string, bool, size_t, std::string>
	generate_signature_for_elliptics_file(const ioremap::elliptics::sync_lookup_result &slr
		, std::string x_regional_host, const namespace_ptr_t &ns);

	void cache_update_callback(bool cache_is_expired_);

private:
public:
	boost::optional<ioremap::elliptics::node> m_elliptics_node;
	boost::optional<ioremap::elliptics::session> m_elliptics_session;

	boost::optional<ioremap::elliptics::session> elliptics_read_session;
	boost::optional<ioremap::elliptics::session> elliptics_write_session;
	boost::optional<ioremap::elliptics::session> elliptics_remove_session;
	boost::optional<ioremap::elliptics::session> elliptics_lookup_session;

	int m_die_limit;
	int m_groups_count;
	int m_write_chunk_size;
	int m_read_chunk_size;
	std::shared_ptr<mastermind::mastermind_t> m_mastermind;
	std::shared_ptr<cdn_cache_t> cdn_cache;
	std::map<std::string, namespace_ptr_t> m_namespaces;
	bool m_namespaces_auto_update;
	std::mutex m_namespaces_mutex;
	boost::thread_specific_ptr<magic_provider> m_magic;
	std::atomic<bool> cache_is_expired;

	struct {
		int def;
		int read;
		int write;
		int lookup;
		int remove;
	} timeout;

	struct {
		int data_flow_rate;
		int for_commit;
	} timeout_coef;

	typedef CryptoPP::HMAC<CryptoPP::SHA512> hmac_type;

	struct {
		std::string name;
		std::string value;

		std::set<std::string> handlers;
	} header_protector;
};

template <typename T>
void proxy::register_handler(const std::string &name, bool exact_match) {
	options opts;
	if (exact_match) {
		options::exact_match('/' + name)(&opts);
	} else {
		options::prefix_match('/' + name)(&opts);
	}

	if (header_protector.handlers.count(name)) {
		options::header(header_protector.name, header_protector.value)(&opts);
	}

	base_server::on(std::move(opts), std::make_shared<ioremap::thevoid::stream_factory<proxy, T>>(this));
}

} // namespace elliptics

#endif /* SRC__PROXY_HPP */
