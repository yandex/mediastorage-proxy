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

#ifndef MDS_PROXY__SRC__DELETE__HPP
#define MDS_PROXY__SRC__DELETE__HPP

#include "proxy.hpp"

namespace elliptics {

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

} // namespace elliptics

#endif /* MDS_PROXY__SRC__DELETE__HPP */

