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

#ifndef _ELLIPTICS_LOOKUP_RESULT_HPP_
#define _ELLIPTICS_LOOKUP_RESULT_HPP_

#include <elliptics/session.hpp>

#include <boost/optional.hpp>
#include <boost/none.hpp>

namespace elliptics {

class lookup_result {
public:
	lookup_result(const ioremap::elliptics::lookup_result_entry &entry, std::string sign_port);

	const std::string &host() const;
	uint16_t port() const;
	int group() const;
	int status() const;
	const std::string &addr() const;
	const std::string &path() const;
	const std::string &full_path() const;

private:
	ioremap::elliptics::lookup_result_entry m_entry;
	std::string m_sign_port;

	mutable boost::optional<std::string> m_host;
	mutable boost::optional<uint16_t> m_port;
	mutable boost::optional<std::string> m_addr;
	mutable boost::optional<std::string> m_path;
	mutable boost::optional<std::string> m_full_path;
};

} // namespace elliptics

#endif /* _ELLIPTICS_LOOKUP_RESULT_HPP_ */
