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

#ifndef SRC__RANGES_HPP
#define SRC__RANGES_HPP

#include <boost/optional.hpp>

#include <string>
#include <list>

namespace elliptics {

struct range_t {
	size_t offset;
	size_t size;
};

typedef std::list<range_t> ranges_t;

boost::optional<ranges_t> parse_range_header(const std::string &header, size_t total_size);

} // namespace elliptics

#endif /* SRC__RANGES_HPP */
