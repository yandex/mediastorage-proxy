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

#include "write_retrier.hpp"
#include "loggers.hpp"

#include <sstream>

elliptics::write_retrier::write_retrier(
		ioremap::swarm::logger bh_logger_
		, ioremap::elliptics::session session_
		, command_t command_
		, size_t success_copies_num_
		, size_t limit_of_attempts_
		, ioremap::elliptics::async_write_result::handler promise_
		)
	: bh_logger(std::move(bh_logger_))
	, session(std::move(session_))
	, command(std::move(command_))
	, success_copies_num(success_copies_num_)
	, limit_of_attempts(limit_of_attempts_)
	, promise(std::move(promise_))
	, complete_once([this] { complete(); })
{
	  session.set_error_handler(ioremap::elliptics::error_handlers::none);
}

void
elliptics::write_retrier::start() {
	auto groups = session.get_groups();
	promise.set_total(groups.size());

	for (auto it = groups.begin(), end = groups.end(); it != end; ++it) {
		auto group_session = session.clone();
		group_session.set_groups({*it});

		complete_once.defer();
		try_group(std::move(group_session), 0);
	}

	complete_once();
}

ioremap::swarm::logger &
elliptics::write_retrier::logger() {
	return bh_logger;
}

void
elliptics::write_retrier::try_group(ioremap::elliptics::session group_session
		, size_t number_of_attempts) {
	auto self = shared_from_this();

	auto callback = [this, self, group_session, number_of_attempts] (
			const ioremap::elliptics::sync_write_result &entries
			, const ioremap::elliptics::error_info &error_info) {
		on_finished(std::move(group_session), number_of_attempts, entries, error_info);
	};

	std::ostringstream oss;
	oss << "write session: group=" << group_session.get_groups()[0]
		<< "; attempt=" << number_of_attempts << ";";
	auto msg = oss.str();
	MDS_LOG_INFO("%s", msg.c_str());

	command(group_session).connect(callback);
}

void
elliptics::write_retrier::on_finished(ioremap::elliptics::session group_session, size_t number_of_attempts
		, const ioremap::elliptics::sync_write_result &entries
		, const ioremap::elliptics::error_info &error_info) {
	std::ostringstream oss;
	oss << "write session is finished: group=" << group_session.get_groups()[0]
		<< "; attempt=" << number_of_attempts << "; status=";

	if (!error_info) {
		oss << "\"ok\"; description=\"success\"";
	} else {
		oss << "\"bad\"; description=\"" << error_info.message() << "\"";
	}

	number_of_attempts += 1;

	bool process_entries = true;

	switch (error_info.code()) {
	case -ETIMEDOUT:
		group_session.set_timeout(2 * group_session.get_timeout());
	case -EINTR:
	case -EAGAIN:
	case -ENOMEM:
	case -EBUSY:
	case -EINVAL:
	case -EMFILE:
		process_entries = false;
		break;
	}

	if (number_of_attempts == limit_of_attempts) {
		process_entries = true;
	}

	if (process_entries) {
		oss << "; decision=\"process result\"";
		auto msg = oss.str();
		MDS_LOG_INFO(msg.c_str());

		for (auto it = entries.begin(), end = entries.end(); it != end; ++it) {
			promise.process(*it);
		}

		if (error_info) {
			init_error(error_info);
		}

		complete_once();
		return;
	}

	oss << "; decision=\"try again\"";
	auto msg = oss.str();
	MDS_LOG_INFO(msg.c_str());
	try_group(std::move(group_session), number_of_attempts);
}

void
elliptics::write_retrier::init_error(const ioremap::elliptics::error_info &error_info_) {
	std::lock_guard<std::mutex> lock_guard(error_info_mutex);

	if (!error_info) {
		error_info = error_info_;
	}
}

void
elliptics::write_retrier::complete() {
	promise.complete(error_info);
}

ioremap::elliptics::async_write_result
elliptics::try_write(
		ioremap::swarm::logger bh_logger
		, ioremap::elliptics::session session
		, write_retrier::command_t command
		, size_t success_copies_num
		, size_t limit_of_attempts
		) {
	ioremap::elliptics::async_write_result future(session);
	ioremap::elliptics::async_write_result::handler promise(future);

	std::make_shared<write_retrier>(std::move(bh_logger), session.clone(), std::move(command), success_copies_num
			, limit_of_attempts, std::move(promise))->start();

	return future;
}

