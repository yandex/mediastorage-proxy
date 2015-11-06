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

#ifndef MDS_PROXY__SRC__UTILS__HPP
#define MDS_PROXY__SRC__UTILS__HPP

#include <swarm/logger.hpp>

#include <thevoid/stream.hpp>
#include <elliptics/session.hpp>

#include <libmastermind/mastermind.hpp>

#include <list>
#include <vector>
#include <mutex>
#include <algorithm>
#include <cstring>
#include <functional>
#include <chrono>
#include <stdexcept>
#include <sstream>
#include <iostream>
#include <string>

namespace elliptics {

typedef int group_t;
typedef std::vector<group_t> groups_t;

typedef std::vector<int> couple_t;

template <typename T>
std::ostream &
operator << (std::ostream &stream, const std::vector<T> &vector) {
	stream << '[';

	{
		// The reason for declarations before for-loop is compiler' bug (gcc <= 4.6):
		// 'variable ‘auto begin’ with ‘auto’ type used in its own initializer'
		// in statement:
		// auto begin = vector.begin(), it = begin;
		auto begin = vector.begin(), end = vector.end();
		for (auto it = begin; it != end; ++it) {
			if (it != begin) {
				stream << ", ";
			}

			stream << *it;
		}
	}

	stream << ']';

	return stream;
}

std::ostream &
operator << (std::ostream &stream, const ioremap::elliptics::error_info &error_info);

template <typename T, typename Server, typename... Args>
std::shared_ptr<ioremap::thevoid::base_request_stream>
make_request_stream(Server *server
		, const std::shared_ptr<ioremap::thevoid::reply_stream> &reply
		, Args &&...args) {
	auto request_stream = std::make_shared<T>(std::forward<Args>(args)...);
	request_stream->set_server(server);
	request_stream->initialize(reply);
	return request_stream;
}

std::string
encode_for_xml(const std::string &string);

std::string
url_encode(const std::string &string);

struct file_location_t {
	std::string host;
	std::string path;
};

file_location_t
make_file_location(const ioremap::elliptics::sync_lookup_result &slr
		, const mastermind::namespace_state_t &ns_state);

std::string
make_signature_ts(boost::optional<std::chrono::seconds> optional_expiration_time
		, const mastermind::namespace_state_t &ns_state);

std::string
make_signature_message(const file_location_t &file_location, const std::string &ts
		, const std::vector<std::tuple<std::string, std::string>> &args
			= std::vector<std::tuple<std::string, std::string>>{});

std::string
make_signature(const std::string &message, const std::string &token);

} // namespace elliptics

#endif /* MDS_PROXY__SRC__UTILS__HPP */

