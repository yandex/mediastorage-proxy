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

#include "writer.hpp"

#include "loggers.hpp"
#include "utils.hpp"
#include "lookup_result.hpp"
#include "write_retrier.hpp"
#include "proxy.hpp"

class error_category_t
	: public std::error_category
{
public:
	const char *
	name() const {
		return "writer error category";
	}

	std::string
	message(int ev) const {
		switch (static_cast<elliptics::writer_errc>(ev)) {
		case elliptics::writer_errc::success:
			return "success";
		case elliptics::writer_errc::unexpected_event:
			return "unexpected event";
		case elliptics::writer_errc::incorrect_size:
			return "incorrect size";
		case elliptics::writer_errc::internal:
			return "internal error";
		case elliptics::writer_errc::insufficient_storage:
			return "insufficient storage";
		default:
			return "unknown error";
		}
	}
};

const std::error_category &
elliptics::writer_category() {
	const static error_category_t instance;
	return instance;
}

std::error_code
elliptics::make_error_code(writer_errc e) {
	return std::error_code(static_cast<int>(e), writer_category());
}

std::error_condition
elliptics::make_error_condition(writer_errc e) {
	return std::error_condition(static_cast<int>(e), writer_category());
}

elliptics::writer_error::writer_error(writer_errc e, const std::string &message)
	: std::system_error(make_error_code(e), message)
{
}

elliptics::writer_t::writer_t(ioremap::swarm::logger bh_logger_
		, const ioremap::elliptics::session &session_, std::string key_
		, size_t total_size_, size_t offset_, size_t commit_coef_, size_t success_copies_num_
		, callback_t on_complete_, size_t limit_of_attempts_, double scale_retry_timeout_
		)
	: state(state_tag::waiting)
	, errc_for_client(writer_errc::success)
	, bh_logger(std::move(bh_logger_))
	, session(session_.clone())
	, key(std::move(key_))
	, total_size(total_size_)
	, offset(offset_)
	, commit_coef(commit_coef_)
	, success_copies_num(success_copies_num_)
	, on_complete(std::move(on_complete_))
	, limit_of_attempts(limit_of_attempts_)
	, scale_retry_timeout(scale_retry_timeout_)
	, written_size(0)
	, start_time(std::chrono::system_clock::now())
{
	session.set_filter(ioremap::elliptics::filters::all_with_ack);
	session.set_checker(ioremap::elliptics::checkers::at_least_one);

	key.transform(session);
	key.set_id(key.id());

	{
		std::ostringstream oss;
		oss
			<< "writing starts:"
			<< " key=" << key.remote()
			// The only reason to print elliptics key is ioremap::elliptics::key::transform
			// method doesn't log this information
			<< " elliptics-key=" << key.to_string()
			<< " offset=" << offset
			<< " total-size=" << total_size
			<< " groups=" << session.get_groups()
			<< " success-copiens-num=" << success_copies_num;

		auto msg = oss.str();

		MDS_LOG_INFO("%s", msg.c_str());
	}
}

void
elliptics::writer_t::write(const char *data, size_t size) {
	write(ioremap::elliptics::data_pointer::from_raw(
			reinterpret_cast<void *>(const_cast<char *>(data)), size));
}

void
elliptics::writer_t::write(const ioremap::elliptics::data_pointer &data_pointer) {
	lock_guard_t lock_guard(state_mutex);
	(void) lock_guard;

	switch (state) {
	case state_tag::waiting: {
		size_t future_size = data_pointer.size() + written_size;

		if (future_size > total_size) {
			throw writer_error(writer_errc::incorrect_size);
		}

		if (written_size == 0 && data_pointer.size() == total_size) {
			log_chunk("simple", data_pointer.size());
			auto async_result = session.write_data(key, data_pointer, offset);
			written_size = data_pointer.size();

			// Actually state should be changed immediately before return
			// But connect can call callback synchronously
			state = state_tag::committing;

			async_result.connect(std::bind(&writer_t::on_data_wrote
						, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
			return;
		}

		auto async_result = write_impl(data_pointer);
		written_size += data_pointer.size();
		offset += data_pointer.size();

		async_result.connect(std::bind(&writer_t::on_data_wrote
					, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
		break;
	}
	case state_tag::writing:
	case state_tag::committing:
	case state_tag::need_remove:
	case state_tag::removing:
	case state_tag::committed:
	case state_tag::failed:
		throw writer_error(writer_errc::unexpected_event);
	}
}

elliptics::writer_t::result_t
elliptics::writer_t::get_result() const {
	result_t result;

	result.id = get_id();
	result.key = get_key();
	result.total_size = get_total_size();
	result.entries_info = get_entries_info();

	return result;
}

const elliptics::writer_t::entries_info_t &
elliptics::writer_t::get_entries_info() const {
	lock_guard_t lock_guard(state_mutex);
	(void) lock_guard;

	switch (state) {
	case state_tag::committed:
	case state_tag::waiting:
	case state_tag::failed:
		return entries_info;
	case state_tag::writing:
	case state_tag::committing:
	case state_tag::need_remove:
	case state_tag::removing:
	// Default is needed only for avoding compile warning:
	// 'control reaches end of non-void function'
	default:
		throw writer_error(writer_errc::unexpected_event);
	}
}

bool
elliptics::writer_t::is_finished() const {
	lock_guard_t lock_guard(state_mutex);
	(void) lock_guard;

	return state == state_tag::committed
		|| state == state_tag::failed;
}

bool
elliptics::writer_t::is_committed() const {
	lock_guard_t lock_guard(state_mutex);
	(void) lock_guard;

	return state == state_tag::committed;
}

bool
elliptics::writer_t::is_failed() const {
	lock_guard_t lock_guard(state_mutex);
	(void) lock_guard;

	return state == state_tag::failed;
}

size_t
elliptics::writer_t::get_total_size() const {
	return total_size;
}

const std::string &
elliptics::writer_t::get_key() const {
	return key.remote();
}

std::string
elliptics::writer_t::get_id() const {
	return key.to_string();
}

ioremap::swarm::logger &
elliptics::writer_t::logger() {
	return bh_logger;
}

void
elliptics::writer_t::log_chunk(
		const std::string &write_type, size_t chunk_size) {
	std::ostringstream oss;
	oss
		<< "write chunk:"
		<< " key=" << key.remote()
		<< " total-size=" << total_size
		<< " offset=" << offset
		<< " chunk-size=" << chunk_size
		<< " data-left=" << (total_size - offset)
		<< " write-type=" << write_type;

	auto msg = oss.str();

	MDS_LOG_INFO("%s", msg.c_str());
}

void
elliptics::writer_t::update_groups(
		const ioremap::elliptics::sync_write_result &entries) {
	std::vector<int> good_groups;

	for (auto it = entries.begin(), end = entries.end(); it != end; ++it) {
		auto &entry = *it;

		int group_id = entry.command()->id.group_id;

		if (entry.status() == 0) {
			good_groups.emplace_back(group_id);
		} else {
			bad_groups.emplace_back(group_id);
		}
	}

	session.set_groups(good_groups);

	{
		std::ostringstream oss;
		oss
			<< "writing of chunk is finished:"
			<< " key=" << key.remote()
			<< " good-groups=" << good_groups
			<< " bad-groups=" << bad_groups;

		auto msg = oss.str();

		MDS_LOG_INFO("%s", msg.c_str());
	}
}

void
elliptics::writer_t::set_result(
		const ioremap::elliptics::sync_write_result &entries) {
	for (auto it = entries.begin(), end = entries.end(); it != end; ++it) {
		lookup_result pl(*it, "");
		if (pl.status() != 0) {
			continue;
		}

		entry_info_t entry_info;

		entry_info.address = pl.addr();
		entry_info.path = pl.full_path();
		entry_info.group = pl.group();

		entries_info.emplace_back(std::move(entry_info));
	}
}

bool
elliptics::writer_t::write_is_good(
		const ioremap::elliptics::error_info &error_info) {
	return !error_info && session.get_groups().size() >= success_copies_num;
}

ioremap::elliptics::async_write_result
elliptics::writer_t::write_impl(
		const ioremap::elliptics::data_pointer &data_pointer) {
	if (written_size == 0) {
		log_chunk("prepare", data_pointer.size());
		state = state_tag::writing;
		return session.write_prepare(key, data_pointer, offset, total_size);
	} else {
		size_t future_size = written_size + data_pointer.size();

		if (future_size > total_size) {
			throw writer_error(writer_errc::incorrect_size);
		}

		if (future_size == total_size) {
			if (commit_coef) {
				session.set_timeout(session.get_timeout() + total_size / commit_coef);
			}
			log_chunk("commit", data_pointer.size());
			state = state_tag::committing;
			return session.write_commit(key, data_pointer, offset, future_size);
		} else {
			log_chunk("plain", data_pointer.size());
			state = state_tag::writing;

			auto command = [key, data_pointer, offset] (ioremap::elliptics::session session)
			-> ioremap::elliptics::async_write_result {
				return session.write_plain(key, data_pointer, offset);
			};

			return try_write(ioremap::swarm::logger(logger(), blackhole::log::attributes_t())
					, session, command, success_copies_num, limit_of_attempts, scale_retry_timeout);
		}
	}
}

elliptics::writer_errc
elliptics::writer_t::choose_errc_for_client(const ioremap::elliptics::sync_write_result &entries) {
	bool is_insufficient_storage = false;

	for (auto it = entries.begin(), end = entries.end(); it != end; ++it) {
		auto status = it->status();

		switch (status) {
		case -ENOSPC:
			is_insufficient_storage = true;
			break;
		}

	}

	if (is_insufficient_storage) {
		return writer_errc::insufficient_storage;
	}

	return writer_errc::internal;
}

void
elliptics::writer_t::on_data_wrote(
		const ioremap::elliptics::sync_write_result &entries
		, const ioremap::elliptics::error_info &error_info) {
#define LOG_RESULT(VERBOSITY, STATUS) \
	do { \
		auto spent_time = std::chrono::duration_cast<std::chrono::milliseconds>( \
				std::chrono::system_clock::now() - start_time).count(); \
		 \
		std::ostringstream oss; \
		oss \
			<< "writing is finished:" \
			<< " key=" << key.remote() \
			<< " spent-time=" << spent_time << "ms" \
			<< " status=" << STATUS \
			<< " wrote into groups " << session.get_groups() \
			<< " failed to write into groups " << bad_groups; \
		 \
		auto msg = oss.str(); \
		MDS_LOG_##VERBOSITY("%s", msg.c_str()); \
	} while (0)

	lock_guard_t lock_guard(state_mutex);

	switch (state) {
	case state_tag::writing:
	case state_tag::committing: {
		update_groups(entries);

		if (write_is_good(error_info)) {
			if (state == state_tag::committing) {
				LOG_RESULT(INFO, "ok");
				set_result(entries);
				state = state_tag::committed;
			} else {
				state = state_tag::waiting;
			}

			lock_guard.unlock();
			on_complete(make_error_code(writer_errc::success));
			return;
		}

		LOG_RESULT(ERROR, "bad");

		state = state_tag::removing;
		errc_for_client = choose_errc_for_client(entries);

		{
			auto groups = session.get_groups();
			groups.insert(groups.end(), bad_groups.begin(), bad_groups.end());
			session.set_groups(groups);
		}

		{
			std::ostringstream oss;
			oss
				<< "remove start:"
				<< " key=" << key.remote()
				<< " groups=" << session.get_groups()
				;
			auto msg = oss.str();
			MDS_LOG_INFO("%s", msg.c_str());
		}

		// TODO: need to set remove-timeout
		auto async_result = session.remove(key);
		async_result.connect(std::bind(&writer_t::on_data_removed
					, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
		break;
	}
	case state_tag::waiting:
	case state_tag::need_remove:
	case state_tag::removing:
	case state_tag::committed:
	case state_tag::failed:
		throw writer_error(writer_errc::unexpected_event);
	}

#undef LOG_RESULT
}

void
elliptics::writer_t::on_data_removed(
		const ioremap::elliptics::sync_remove_result &entries
		, const ioremap::elliptics::error_info &error_info) {
	lock_guard_t lock_guard(state_mutex);

	switch (state) {
	case state_tag::removing: {
		MDS_LOG_INFO("remove is finished");
		state = state_tag::failed;
		lock_guard.unlock();
		on_complete(make_error_code(errc_for_client));
		break;
	}
	case state_tag::waiting:
	case state_tag::writing:
	case state_tag::committing:
	case state_tag::need_remove:
	case state_tag::committed:
	case state_tag::failed:
		throw writer_error(writer_errc::unexpected_event);
	}
}

#define logger() *shared_logger

namespace detail {

void
can_be_written_on_lookup(shared_logger_t shared_logger
		, const ioremap::elliptics::sync_lookup_result &entries
		, const ioremap::elliptics::error_info &error_info
		, util::expected<bool>::callback_t next) {

	for (auto it = entries.begin(), end = entries.end(); it != end; ++it) {
		const int group_id = it->command()->id.group_id;

		if (it->status() == -ENOENT) {
			continue;
		}

		if (it->status() == 0) {
			MDS_LOG_INFO("key was found in group=%d", group_id);
			next(false);
			return;
		}

		const auto entry_error_info = it->error();
		MDS_LOG_ERROR("cannot check group=%d: %s", group_id , entry_error_info.message().c_str());
		
		next(util::expected_from_exception<std::runtime_error>("cannot check some group"));
		return;
	}

	MDS_LOG_INFO("key was not found in any group");
	next(true);
}

} // namespace detail

void
elliptics::can_be_written(shared_logger_t shared_logger
		, ioremap::elliptics::session session
		, std::string key
		, mastermind::namespace_state_t ns_state
		, util::expected<bool>::callback_t next) {

	{
		std::ostringstream oss;
		oss << "check for update couple " << session.get_groups();
		auto msg = oss.str();
		MDS_LOG_INFO("%s", msg.c_str());
	}

	if (!proxy_settings(ns_state).check_for_update) {
		MDS_LOG_INFO("check for update is disabled for the namespace");
		next(true);
		return;
	}

	session = session.clone();
	session.set_filter(ioremap::elliptics::filters::all);

	auto future = session.parallel_lookup(key);

	auto next_ = std::bind(&detail::can_be_written_on_lookup, shared_logger
			, std::placeholders::_1, std::placeholders::_2
			, std::move(next));

	future.connect(next_);
}

