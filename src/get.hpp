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

#ifndef SRC__GET__HPP
#define SRC__GET__HPP

#include "handler.hpp"
#include "proxy.hpp"
#include "ranges.hpp"

#include <mds/read_controller.h>

#include <boost/optional.hpp>

#include <vector>

namespace elliptics {

struct req_get
	: public handler<ioremap::thevoid::simple_request_stream>
{
	req_get();

	void
	on_request(const ioremap::thevoid::http_request &http_request
			, const boost::asio::const_buffer &const_buffer);

private:
	enum class redirect_arg_tag {
		  none
		, client_want_redirect
	};

	folly::Future<folly::Unit>
	process_request(mds::ReadControllerPtr read_controller, mds::FileInfoPtr file_info);

	std::tuple<boost::optional<ioremap::thevoid::http_response>, bool>
	process_precondition_headers(time_t timestamp, const std::string &etag);

	redirect_arg_tag
	get_redirect_arg();

	std::vector<std::tuple<std::string, std::string>>
	get_redirect_query_args();

	boost::optional<ioremap::thevoid::http_response>
	try_to_redirect_request(const mds::FileInfoPtr &file_info);

	folly::Future<folly::Unit>
	process_streaming(mds::ReadControllerPtr read_controller
			, ioremap::swarm::http_headers http_headers
			, size_t size, bool send_whole_file);

	folly::Future<folly::Unit>
	process_whole_file(mds::ReadControllerPtr read_controller
			, ioremap::swarm::http_headers http_headers);

	folly::Future<folly::Unit>
	process_whole_file(mds::ReadStreamPtr read_stream
			, ioremap::swarm::http_headers http_headers);

	std::string
	detect_content_type(const mds::ReadStreamResult &result);

	folly::Future<folly::Unit>
	process_range(mds::ReadControllerPtr read_controller
			, ioremap::swarm::http_headers http_headers, size_t offset, size_t size);

	folly::Future<folly::Unit>
	process_ranges(mds::ReadControllerPtr read_controller
			, ioremap::swarm::http_headers http_headers
			, ranges_t ranges, std::list<std::string> boundaries);

	folly::Future<folly::Unit>
	stream_ranges(mds::ReadControllerPtr read_controller, ranges_t ranges
				, std::list<std::string> ranges_headers);

	folly::Future<folly::Unit>
	stream_range(mds::ReadControllerPtr read_controller, uint64_t offset, uint64_t size);

	folly::Future<folly::Unit>
	stream_range(mds::ReadStreamPtr read_stream);


	mastermind::namespace_state_t ns_state;
	boost::optional<std::chrono::seconds> expiration_time;
};

} // namespace elliptics

#endif /* SRC__GET__HPP */

