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

#ifndef MDS_PROXY__SRC__TIMER__HPP
#define MDS_PROXY__SRC__TIMER__HPP

#include <boost/lexical_cast.hpp>

#include <chrono>
#include <string>

namespace util {

namespace detail {

template <typename Duration>
struct timer_traits;

template <>
struct timer_traits<std::chrono::seconds> {
	static
	std::string
	suffix() { return "s"; }
};

template <>
struct timer_traits<std::chrono::milliseconds> {
	static
	std::string
	suffix() { return "ms"; }
};

template <>
struct timer_traits<std::chrono::microseconds> {
	static
	std::string
	suffix() { return "us"; }
};

template <>
struct timer_traits<std::chrono::nanoseconds> {
	static
	std::string
	suffix() { return "ns"; }
};

} // namespace detail

template <typename Clock>
class timer {
public:
	typedef Clock clock_type;
	typedef typename clock_type::time_point time_point_type;

	timer() {
		reset();
	}

	void
	reset() {
		time_point = clock_type::now();
	}

	template <typename Duration>
	typename Duration::rep
	get() const {
		return std::chrono::duration_cast<Duration>(
				clock_type::now() - time_point).count();
	}

	template <typename Duration>
	std::string
	str() const {
		return boost::lexical_cast<std::string>(get<Duration>())
			+ detail::timer_traits<Duration>::suffix();
	}

	/*
	 * Specialize method get() and method str() for certain durations.
	 * Methods will have a form get_xxx() and str_xxx() with 'xxx' that determines
	 * certain duration. For instance the suffix 'ms' means milliseconds.
	 */
#define SPECIALIZE_FOR_DURATION(duration, suffix) \
	duration::rep \
	get_##suffix() const { \
		return get<duration>(); \
	} \
	 \
	std::string \
	str_##suffix() const { \
		return str<duration>(); \
	}

	SPECIALIZE_FOR_DURATION(std::chrono::seconds, s)
	SPECIALIZE_FOR_DURATION(std::chrono::milliseconds, ms)
	SPECIALIZE_FOR_DURATION(std::chrono::microseconds, us)
	SPECIALIZE_FOR_DURATION(std::chrono::nanoseconds, ns)

#undef SPECIALIZE_FOR_DURATION

private:
	time_point_type time_point;
};

typedef timer<std::chrono::system_clock> system_timer_t;
//typedef timer<std::chrono::steady_clock> steady_timer_t;
typedef timer<std::chrono::high_resolution_clock> high_resolution_timer_t;

typedef system_timer_t timer_t;

} // namespace util

#endif /* MDS_PROXY__SRC__TIMER__HPP */

