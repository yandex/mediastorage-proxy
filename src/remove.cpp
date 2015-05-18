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

#include "remove.hpp"

#include "timer.hpp"
#include "utils.hpp"

#define logger() *shared_logger

elliptics::remove_result_t::remove_result_t(bool has_bad_response_, bool not_found_)
	: has_bad_response(has_bad_response_)
	, not_found(not_found_)
{}

bool
elliptics::remove_result_t::is_failed() const {
	return has_bad_response;
}

bool
elliptics::remove_result_t::is_successful() const {
	return !has_bad_response;
}

bool
elliptics::remove_result_t::key_was_not_found() const {
	return not_found;
}

namespace {

void
remove_was_done(shared_logger_t shared_logger
		, const ioremap::elliptics::sync_remove_result &entries
		, const ioremap::elliptics::error_info &error_info
		, const std::string &key, util::timer_t timer, size_t groups_count
		, util::expected<elliptics::remove_result_t>::callback_t next) {
	{
		using elliptics::operator <<;

		std::ostringstream oss;
		oss << "remove was done: key=" << key << "; spent-time=" << timer.str_ms()
			<< "; " << error_info;
		auto msg = oss.str();

		if (error_info) {
			MDS_LOG_ERROR("%s", msg.c_str());
		} else {
			MDS_LOG_INFO("%s", msg.c_str());
		}
	}

	bool has_bad_response = false;
	size_t enoent_count = 0;

	for (auto it = entries.begin(), end = entries.end(); it != end; ++it) {
		auto status = it->status();

		if (status != 0) {
			if (status != -ENOENT) {
				has_bad_response = true;
			} else {
				enoent_count += 1;
			}
		}
	}

	// The reason for this check: ELL-250
	if (entries.size() != groups_count) {
		has_bad_response = true;
	}

	elliptics::remove_result_t remove_result{has_bad_response, enoent_count == entries.size()};
	next(remove_result);
}

} // namespace

void
elliptics::remove(shared_logger_t shared_logger
		, ioremap::elliptics::session session
		, std::string key
		, util::expected<remove_result_t>::callback_t next) {
	{
		std::ostringstream oss;
		oss << "remove: key=\"" << key << "\"; groups=" << session.get_groups();
		auto msg = oss.str();
		MDS_LOG_INFO("%s", msg.c_str());
	}

	util::timer_t timer;

	session = session.clone();
	session.set_filter(ioremap::elliptics::filters::all_with_ack);

	auto future = session.remove(key);

	auto next_ = std::bind(remove_was_done, std::move(shared_logger)
			, std::placeholders::_1, std::placeholders::_2
			, key, timer, session.get_groups().size(), std::move(next));

	future.connect(next_);
}

