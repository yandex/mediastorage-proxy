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

#ifndef MDS_PROXY__SRC__LOOKUPER__HPP
#define MDS_PROXY__SRC__LOOKUPER__HPP

#include <elliptics/session.hpp>

#include <swarm/logger.hpp>

#include <vector>
#include <memory>
#include <string>
#include <mutex>

namespace elliptics {

class parallel_lookuper_t
	: public std::enable_shared_from_this<parallel_lookuper_t>
{
public:
	typedef ioremap::elliptics::sync_lookup_result entries_t;
	typedef ioremap::elliptics::error_info error_info_t;

	struct result_t {
		entries_t entries;
		error_info_t error_info;
	};

	parallel_lookuper_t(
			ioremap::swarm::logger bh_logger_
			, ioremap::elliptics::session session_
			, std::string key_
			);

	void
	start();

	ioremap::elliptics::async_lookup_result
	next_lookup_result();

	size_t
	total_size() const;

	size_t
	results_left() const;

#if 0
	ioremap::elliptics::async_lookup_result
	get_group(const ioremap::elliptics::lookup_result_entry &entry);
#endif

private:
	typedef std::mutex mutex_t;
	typedef std::unique_lock<mutex_t> lock_guard_t;

	ioremap::swarm::logger &
	logger();

	void
	on_lookup(const ioremap::elliptics::sync_lookup_result &entries
			, const ioremap::elliptics::error_info &error_info);

	void
	process_promise(ioremap::elliptics::async_lookup_result::handler &promise
			, const result_t &result);

	void
	process_promise(ioremap::elliptics::async_lookup_result::handler &promise);

	ioremap::swarm::logger bh_logger;
	ioremap::elliptics::session session;
	std::string key;

	mutable mutex_t results_mutex;
	std::list<result_t> results;
	std::list<ioremap::elliptics::async_lookup_result::handler> promises;
	size_t groups_to_handle;

};

typedef std::shared_ptr<parallel_lookuper_t> parallel_lookuper_ptr_t;

parallel_lookuper_ptr_t
make_parallel_lookuper(
		ioremap::swarm::logger bh_logger
		, ioremap::elliptics::session session
		, std::string key
		);

} // namespace elliptics

#endif /* MDS_PROXY__SRC__LOOKUPER__HPP */

