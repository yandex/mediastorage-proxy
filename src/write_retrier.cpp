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

elliptics::write_retrier::write_retrier(
		ioremap::elliptics::session session_
		, command_t command_
		, size_t success_copies_num_
		, size_t limit_of_attempts_
		, ioremap::elliptics::async_write_result::handler promise_
		)
	: session(std::move(session_))
	, command(std::move(command_))
	, success_copies_num(success_copies_num_)
	, limit_of_attempts(limit_of_attempts_)
	, promise(std::move(promise_))
	, number_of_attempts(0)
{}

void
elliptics::write_retrier::start() {
	try_next();
}

void
elliptics::write_retrier::try_next() {
	auto self = shared_from_this();

	auto callback = [this, self] (
			const ioremap::elliptics::sync_write_result &entries
			, const ioremap::elliptics::error_info &error_info) {
		on_finished(entries, error_info);
	};

	command(session).connect(callback);
}

void
elliptics::write_retrier::on_finished(
		const ioremap::elliptics::sync_write_result &entries
		, const ioremap::elliptics::error_info &error_info) {
	promise.set_total(entries.size());

	for (auto it = entries.begin(), end = entries.end(); it != end; ++it) {
		promise.process(*it);
	}

	promise.complete(error_info);
}

ioremap::elliptics::async_write_result
elliptics::try_write(
		ioremap::elliptics::session session
		, write_retrier::command_t command
		, size_t success_copies_num
		, size_t limit_of_attempts
		) {
	ioremap::elliptics::async_write_result future(session);
	ioremap::elliptics::async_write_result::handler promise(future);

	std::make_shared<write_retrier>(session.clone(), std::move(command), success_copies_num
			, limit_of_attempts, std::move(promise))->start();

	return future;
}

