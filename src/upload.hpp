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

#ifndef MDS_PROXY__SRC__UPLOAD__HPP
#define MDS_PROXY__SRC__UPLOAD__HPP

#include "utils.hpp"
#include "proxy.hpp"
#include "loggers.hpp"
#include "couple_iterator.hpp"

#include <thevoid/stream.hpp>

#include <boost/optional.hpp>

#include <map>
#include <vector>
#include <mutex>

namespace elliptics {

class upload_t
	: public ioremap::thevoid::request_stream<proxy>
	, public std::enable_shared_from_this<upload_t>
{
public:
	void
	on_headers(ioremap::thevoid::http_request &&http_request);

	size_t
	on_data(const boost::asio::const_buffer &buffer);

	void
	on_close(const boost::system::error_code &error);

private:
	boost::optional<couple_iterator_t>
	create_couple_iterator(const ioremap::thevoid::http_request &http_request
			, const mastermind::namespace_state_t &ns_state, size_t total_size);

	std::shared_ptr<base_request_stream> request_stream;
};

} // namespace elliptics

#endif /* MDS_PROXY__SRC__UPLOAD__HPP */

