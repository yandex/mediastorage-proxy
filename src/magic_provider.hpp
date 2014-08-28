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

#ifndef MAGIC_PROVIDER_HPP
#define MAGIC_PROVIDER_HPP

#include <boost/noncopyable.hpp>

#include <magic.h>

namespace elliptics {

class magic_provider : private boost::noncopyable {

public:
	magic_provider () {
		magic_ = magic_open(MAGIC_MIME_TYPE);
		magic_load(magic_, 0);
	}

	~magic_provider() {
		magic_close(magic_);
	}

public:
	std::string type(const std::string &content) {
		const char *result(magic_buffer(magic_, content.data(), content.size()));

		if (result) {
			return result;
		}

		return "application/octet-stream";
	}

private:
	magic_t magic_;

};

} // namespace elliptics

#endif /* MAGIC_PROVIDER_HPP */
