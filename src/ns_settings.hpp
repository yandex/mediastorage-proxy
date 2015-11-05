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

#ifndef MDS_PROXY__SRC__NS_SETTINGS__HPP
#define MDS_PROXY__SRC__NS_SETTINGS__HPP

#include <elliptics/session.hpp>

#include <libmastermind/mastermind.hpp>

#include <vector>
#include <string>
#include <chrono>

namespace elliptics {

struct settings_t
	: public mastermind::namespace_state_t::user_settings_t {

	settings_t()
		: redirect_content_length_threshold(-1)
		, can_choose_couple_to_upload(false)
		, multipart_content_length_threshold(0)
		, custom_expiration_time(false)
		, success_copies_num(-1)
		, check_for_update(true)
	{}

	std::string name;
	ioremap::elliptics::result_checker result_checker;

	std::string auth_key_for_write;
	std::string auth_key_for_read;

	std::vector<int> static_couple;

	std::string sign_token;
	std::string sign_path_prefix;
	std::string sign_port;

	std::chrono::seconds redirect_expire_time;
	int64_t redirect_content_length_threshold;

	bool can_choose_couple_to_upload;
	int64_t multipart_content_length_threshold;
	bool custom_expiration_time;

	int success_copies_num;

	bool check_for_update;
};

const settings_t &
proxy_settings(const mastermind::namespace_state_t &ns_state);

} // namespace elliptics

#endif /* MDS_PROXY__SRC__NS_SETTINGS__HPP */

