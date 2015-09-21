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

#ifndef MDS_PROXY__SRC__DOWNLOAD_INFO__HPP
#define MDS_PROXY__SRC__DOWNLOAD_INFO__HPP

#include "proxy.hpp"

#include <thevoid/stream.hpp>

#include <string>
#include <utility>

namespace elliptics {

class download_info_t
	: public ioremap::thevoid::simple_request_stream<proxy>
	, public std::enable_shared_from_this<download_info_t>
{
public:
	download_info_t(const std::string &handler_name_);

	void
	on_request(const ioremap::thevoid::http_request &req
			, const boost::asio::const_buffer &buffer);

	void
	on_finished(const ioremap::elliptics::sync_lookup_result &slr
			, const ioremap::elliptics::error_info &error);

private:
	mastermind::namespace_state_t
	get_namespace_state(const std::string &path, const std::string &handler);

	void
	check_signature();

	void
	check_query_args();

	std::tuple<boost::optional<ioremap::elliptics::session>, ioremap::elliptics::key>
	prepare_session(const mastermind::namespace_state_t &ns_state);

	void
	process_get(ioremap::elliptics::session session, const ioremap::elliptics::key key);

	void
	send_response(std::tuple<std::string, std::string, std::string, std::string> res);

	std::string
	xml_response(std::tuple<std::string, std::string, std::string, std::string> res);

	kora::dynamic_t
	json_response_impl(std::tuple<std::string, std::string, std::string, std::string> res);

	std::string
	json_response(std::tuple<std::string, std::string, std::string, std::string> res);

	std::string
	jsonp_response(std::tuple<std::string, std::string, std::string, std::string> res);

	mastermind::namespace_state_t ns_state;
	std::string x_regional_host;
	std::string handler_name;
	boost::optional<std::chrono::seconds> expiration_time;
};

class download_info_1_t : public download_info_t {
public:
	download_info_1_t();
	static const std::string handler_name;
};

class download_info_2_t : public download_info_t {
public:
	download_info_2_t();
	static const std::string handler_name;
};

} // namespace elliptics

#endif /* MDS_PROXY__SRC__DOWNLOAD_INFO__HPP */

