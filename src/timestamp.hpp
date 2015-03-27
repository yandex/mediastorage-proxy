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

#ifndef MDS_PROXY__SRC__TIMESTAMP__HPP
#define MDS_PROXY__SRC__TIMESTAMP__HPP

#include <boost/lexical_cast.hpp>

#include <chrono>
#include <string>

namespace utils {

template <typename Duration>
struct timestamp_traits;

template <>
struct timestamp_traits<std::chrono::seconds> {
	static
	std::string
	suffix() { return "s"; }
};

template <>
struct timestamp_traits<std::chrono::milliseconds> {
	static
	std::string
	suffix() { return "ms"; }
};

template <>
struct timestamp_traits<std::chrono::microseconds> {
	static
	std::string
	suffix() { return "us"; }
};

template <>
struct timestamp_traits<std::chrono::nanoseconds> {
	static
	std::string
	suffix() { return "ns"; }
};

template <typename Duration, typename Clock = std::chrono::system_clock>
class timestamp {
public:
	typedef Duration duration_type;
	typedef Clock clock_type;
	typedef typename clock_type::time_point time_point_type;
	typedef timestamp_traits<duration_type> traits_type;

	timestamp() {
		reset();
	}

	void
	reset() {
		time_point = clock_type::now();
	}

	typename duration_type::rep
	get() const {
		return std::chrono::duration_cast<duration_type>(
				clock_type::now() - time_point).count();
	}

	std::string
	str() const {
		return boost::lexical_cast<std::string>(get()) + traits_type::suffix();
	}

private:
	time_point_type time_point;
};

typedef timestamp<std::chrono::seconds> s_timestamp_t;
typedef timestamp<std::chrono::milliseconds> ms_timestamp_t;
typedef timestamp<std::chrono::microseconds> us_timestamp_t;
typedef timestamp<std::chrono::nanoseconds> ns_timestamp_t;

} // namespace utils

#endif /* MDS_PROXY__SRC__TIMESTAMP__HPP */

