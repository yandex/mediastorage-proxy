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

#ifndef MDS_PROXY__SRC__UPLOADER__HPP
#define MDS_PROXY__SRC__UPLOADER__HPP

#include <elliptics/session.hpp>

#include <swarm/logger.hpp>

#include <memory>
#include <functional>
#include <system_error>
#include <mutex>

namespace elliptics {

enum class writer_errc {
	  success
	, unexpected_event
	, incorrect_size
	, internal
};

const std::error_category &
writer_category();

std::error_code
make_error_code(writer_errc e);

std::error_condition
make_error_condition(writer_errc e);

class writer_error : public std::system_error
{
public:
	writer_error(writer_errc e, const std::string &message = "");
};

class writer_t : public std::enable_shared_from_this<writer_t>
{
public:
	typedef std::function<void (const std::error_code &)> callback_t;

	struct entry_info_t {
		std::string address;
		std::string path;
		int group;
	};

	typedef std::vector<entry_info_t> entries_info_t;

	writer_t(ioremap::swarm::logger bh_logger_
			, const ioremap::elliptics::session &session_, std::string key_
			, size_t total_size_, size_t offset_, size_t commit_coef_, size_t success_copies_num_
			, callback_t on_complete_
			);

	void
	write(const char *data, size_t size);

	void
	write(const ioremap::elliptics::data_pointer &data_pointer);

	const entries_info_t &
	get_result() const;

	bool
	is_finished() const;

	bool
	is_committed() const;

	bool
	is_failed() const;

	size_t
	get_total_size() const;

	const std::string &
	get_key() const;

	std::string
	get_id() const;

private:
	enum class state_tag {
		  waiting
		, writing
		, committing
		, need_remove
		, removing
		, committed
		, failed
	};

	typedef std::recursive_mutex mutex_t;
	typedef std::lock_guard<mutex_t> lock_guard_t;

	ioremap::swarm::logger &
	logger();

	void
	log_chunk(const std::string &write_type, size_t chunk_size);

	void
	update_groups(const ioremap::elliptics::sync_write_result &entries);

	void
	set_result(const ioremap::elliptics::sync_write_result &entries);

	bool
	write_is_good(const ioremap::elliptics::error_info &error_info);

	ioremap::elliptics::async_write_result
	write_impl(const ioremap::elliptics::data_pointer &data_pointer);

	void
	on_data_wrote(const ioremap::elliptics::sync_write_result &entries
			, const ioremap::elliptics::error_info &error_info);

	void
	on_data_removed(const ioremap::elliptics::sync_remove_result &entries
			, const ioremap::elliptics::error_info &error_info);

	state_tag state;
	mutable mutex_t state_mutex;

	ioremap::swarm::logger bh_logger;

	ioremap::elliptics::session session;
	ioremap::elliptics::key key;

	size_t total_size;
	size_t offset;
	size_t commit_coef;
	size_t success_copies_num;

	callback_t on_complete;

	size_t written_size;
	std::vector<int> bad_groups;

	std::chrono::system_clock::time_point start_time;

	entries_info_t entries_info;
};


} // namespace elliptics

namespace std {

template <>
struct is_error_code_enum<elliptics::writer_errc>
	: public true_type
{};

} // namespace std

#endif /* MDS_PROXY__SRC__UPLOADER__HPP */

