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

#ifndef SRC__GET__HPP
#define SRC__GET__HPP

#include "proxy.hpp"

#include "ranges.hpp"

#include <elliptics/session.hpp>

#include <boost/optional.hpp>

#include <memory>
#include <vector>

namespace elliptics {

class get_helper_t;

struct req_get
	: public ioremap::thevoid::simple_request_stream<proxy>
	, public std::enable_shared_from_this<req_get>
{
	void on_request(const ioremap::thevoid::http_request &req, const boost::asio::const_buffer &buffer);
	void on_lookup(const ioremap::elliptics::sync_lookup_result &slr, const ioremap::elliptics::error_info &error);
private:
	typedef std::function<void (void)> callback_t;

	std::tuple<bool, bool> process_precondition_headers(const time_t timestamp, const size_t size);
	bool try_to_redirect_request(const ioremap::elliptics::sync_lookup_result &slr
			, const size_t size, bool send_whole_file);
	void start_reading(const size_t size, bool send_whole_file);

	std::shared_ptr<get_helper_t> make_get_helper(size_t offset, size_t size);

	void on_simple_read(const std::shared_ptr<get_helper_t> &get_helper, callback_t read_is_done);
	void on_simple_range_read(const std::shared_ptr<get_helper_t> &get_helper
			, callback_t read_is_done);

	void on_simple_data_sent(const boost::system::error_code &error_code
			, const std::shared_ptr<get_helper_t> &get_helper
			, callback_t read_is_done);

	void read_range(ranges_t ranges, std::list<std::string> ranges_headers);

	void on_error();

	void on_read_is_done();

	ioremap::elliptics::session get_session();

	ioremap::thevoid::http_response prospect_http_response;

	boost::optional<ioremap::elliptics::session> m_session;
	namespace_ptr_t ns;
	std::string key;

	size_t total_size;

	bool m_first_chunk;

	std::vector<int> bad_groups;
};

} // namespace elliptics

#endif /* SRC__GET__HPP */

