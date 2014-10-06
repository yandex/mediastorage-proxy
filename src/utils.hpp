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

#ifndef MDS_PROXY__SRC__UTILS__HPP
#define MDS_PROXY__SRC__UTILS__HPP

#include <thevoid/stream.hpp>

#include <swarm/logger.hpp>

#include <elliptics/session.hpp>

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

namespace elliptics {

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

} // namespace elliptics

#endif /* MDS_PROXY__SRC__UTILS__HPP */

