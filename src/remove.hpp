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

#ifndef MDS_PROXY__SRC__REMOVE__HPP
#define MDS_PROXY__SRC__REMOVE__HPP

#include "loggers.hpp"
#include "expected.hpp"

#include <elliptics/session.hpp>

#include <string>

namespace elliptics {

class remove_result_t {
public:
	remove_result_t(bool has_bad_response_, bool not_found_);

	bool
	is_failed() const;

	bool
	is_successful() const;

	bool
	key_was_not_found() const;

private:
	bool has_bad_response;
	bool not_found;

};

void
remove(shared_logger_t shared_logger
		, ioremap::elliptics::session session
		, std::string key
		, util::expected<remove_result_t>::callback_t next);

} // namespace elliptics

#endif /* MDS_PROXY__SRC__REMOVE__HPP */

