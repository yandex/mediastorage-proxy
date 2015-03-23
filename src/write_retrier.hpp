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

#ifndef MDS_PROXY__SRC__WRITE_RETRIER__HPP
#define MDS_PROXY__SRC__WRITE_RETRIER__HPP

#include "deferred_function.hpp"

#include <elliptics/session.hpp>

#include <swarm/logger.hpp>

#include <functional>
#include <memory>
#include <mutex>

namespace elliptics {

class write_retrier
	: public std::enable_shared_from_this<write_retrier>
{
public:
	typedef
		std::function<ioremap::elliptics::async_write_result
			(ioremap::elliptics::session)>
		command_t;

	write_retrier(
			ioremap::swarm::logger bh_logger_
			, ioremap::elliptics::session session_
			, command_t command_
			, size_t success_copies_num_
			, size_t limit_of_attempts_
			, double scale_retry_timeout_
			, ioremap::elliptics::async_write_result::handler promise
			);

	void
	start();

private:
	ioremap::swarm::logger &
	logger();

	void
	try_group(ioremap::elliptics::session group_session, size_t number_of_attempts);

	void
	on_finished(ioremap::elliptics::session group_session, size_t number_of_attempts
			, const ioremap::elliptics::sync_write_result &entries
			, const ioremap::elliptics::error_info &error_info);

	void
	init_error(const ioremap::elliptics::error_info &error_info_);

	void
	complete();

	ioremap::swarm::logger bh_logger;
	ioremap::elliptics::session session;
	command_t command;
	size_t success_copies_num;
	size_t limit_of_attempts;
	double scale_retry_timeout;
	ioremap::elliptics::async_write_result::handler promise;

	std::mutex error_info_mutex;
	ioremap::elliptics::error_info error_info;
	deferred_function_t complete_once;

};

ioremap::elliptics::async_write_result
try_write(
		ioremap::swarm::logger bh_logger
		, ioremap::elliptics::session session
		, write_retrier::command_t command
		, size_t success_copies_num
		, size_t limit_of_attempts
		, double scale_retry_timeout
		);

} // namespace elliptics

#endif /* MDS_PROXY__SRC__WRITE_RETRIER__HPP */

