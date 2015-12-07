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

#ifndef MDS_PROXY__SRC__ERROR__HPP
#define MDS_PROXY__SRC__ERROR__HPP

#include "loggers.hpp"

#include <boost/system/error_code.hpp>

#include <stdexcept>

namespace elliptics {

class proxy_error : public std::runtime_error
{
public:
	proxy_error(const std::string &message)
		: std::runtime_error(message)
	{}
};

class thevoid_error : public proxy_error
{
public:
	thevoid_error(const boost::system::error_code &error_code_)
		: proxy_error("error during process thevoid")
		, m_error_code(error_code_)
	{}

	const boost::system::error_code &
	error_code() const {
		return m_error_code;
	}

private:
	boost::system::error_code m_error_code;
};

class http_error : public proxy_error
{
public:
	http_error(int http_status_, const std::string &message)
		: proxy_error(message)
		, m_http_status(http_status_)
	{}

	int
	http_status() const {
		return m_http_status;
	}

	bool
	is_server_error() const {
		return m_http_status >= 500 && m_http_status <= 599;
	}


private:
	int m_http_status;
};

} // namespace elliptics

#endif /* MDS_PROXY__SRC__ERROR__HPP */

