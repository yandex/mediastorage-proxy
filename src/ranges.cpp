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

#include "ranges.hpp"

#include <string>
#include <vector>
#include <cctype>
#include <cstring>
#include <stdexcept>

namespace elliptics {

struct range_impl_t {
	enum types_tag {
		prefix,
		part,
		suffix
	};

	types_tag type;
	size_t first;
	size_t last;
	size_t size;

	range_impl_t()
		: type(part)
		, first(0)
		, last(-1)
	{}
};

size_t parse_pos(const char *&s) {
	size_t res = 0;
	while (isdigit(*s)) res = res * 10 + *s++ - '0';
	return res;
}

range_impl_t parse_range(const char *&s) {
	range_impl_t range;
	if (*s == '-') {
		range.type = range_impl_t::suffix;
		range.last = parse_pos(++s);
	} else {
		range.first = parse_pos(s);
		if (*s != '-') {
			throw std::runtime_error("Header is malformed");
		}
		++s;
		if (isdigit(*s)) {
			range.last = parse_pos(s);
			range.type = range_impl_t::part;
		} else {
			range.type = range_impl_t::prefix;
		}
	}
	return range;
}

std::vector<range_impl_t> parse_header_impl(const char *s, size_t total_size) {
	std::vector<range_impl_t> res;
	if (strncmp(s, "bytes=", sizeof("bytes=") - 1)) {
		throw std::runtime_error("Header is malformed");
	}
	s += sizeof("bytes=") - 1;
	size_t last_byte = total_size - 1;
	while (*s) {
		while (isspace(*s)) ++s;
		auto range = parse_range(s);

		if (range.type != range_impl_t::suffix) {
			if (range.type == range_impl_t::part && range.first > range.last) {
				throw std::runtime_error("Header is malformed");
			}

			if (range.type == range_impl_t::prefix || range.last >= total_size) {
				range.last = last_byte;
			}

			if (range.first > last_byte) {
				continue;
			}
		} else {
			if (total_size < range.last) {
				range.last = total_size;
			}
		}

		res.push_back(range);

		while (isspace(*s)) ++s;
		if (*s && *s != ',') {
			throw std::runtime_error("Header is malformed");
		}
		if (*s) ++s;
	}
	return res;
}

boost::optional<ranges_t> parse_range_header(const std::string &header, size_t total_size) {
	try {
		auto res_impl = parse_header_impl(header.c_str(), total_size);
		if (res_impl.empty()) {
			return boost::none;
		}
		ranges_t res;

		for (auto it = res_impl.begin(), end = res_impl.end(); it != end; ++it) {
			range_t range;
			if (it->type != range_impl_t::suffix) {
				range.offset = it->first;
				range.size = it->last - it->first + 1;
			} else {
				range.offset = total_size - it->last;
				range.size = it->last;
			}
			res.push_back(range);
		}

		return res;
	} catch (...) {
		return boost::none;
	}
}

} // namespace elliptics

