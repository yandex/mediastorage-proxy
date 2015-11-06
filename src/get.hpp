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

#include <boost/asio/buffer.hpp>
#include <elliptics/utils.hpp>

namespace boost {
namespace asio {

const_buffers_1
buffer(const ioremap::elliptics::data_pointer &data_pointer);

} // namespace asio
} // namespace boost

#include "proxy.hpp"

#include "ranges.hpp"
#include "lookuper.hpp"
#include "timer.hpp"

#include <elliptics/session.hpp>

#include <boost/optional.hpp>

#include <memory>
#include <vector>

namespace elliptics {

namespace ie = ioremap::elliptics;

struct req_get
	: public ioremap::thevoid::simple_request_stream<proxy>
	, public std::enable_shared_from_this<req_get>
{
	void
	on_request(const ioremap::thevoid::http_request &http_request
			, const boost::asio::const_buffer &const_buffer);

private:
	enum class redirect_arg_tag {
		  none
		, client_want_redirect
	};

	groups_t
	get_cached_groups();

	void
	find_first_group(std::function<void (const ie::lookup_result_entry &)> on_result
			, std::function<void ()> on_error);

	void
	next_first_group_is_found(const ie::sync_lookup_result &entries
			, const ie::error_info &error_info
			, std::function<void (const ie::lookup_result_entry &)> on_result
			, std::function<void ()> on_error);

	void
	find_other_group(std::function<void ()> on_result
			, std::function<void ()> on_error);

	void
	next_other_group_is_found(const ie::sync_lookup_result &entries
			, const ie::error_info &error_info
			, std::function<void ()> on_result
			, std::function<void ()> on_error);

	void
	all_groups_were_processed(std::function<void ()> on_error);

	bool
	check_lookup_result_entry(const ie::lookup_result_entry &entry);

	bool
	lookup_result_entries_are_equal(const ie::lookup_result_entry &lhs
			, const ie::lookup_result_entry &rhs);

	void
	process_group_info(const ie::lookup_result_entry &entry);

	void
	set_csum_type(const ie::lookup_result_entry &entry);

	void
	read_chunk(size_t offset, size_t size
			, std::function<void (const ie::read_result_entry &)> on_result
			, std::function<void ()> on_error);

	void
	read_chunk_is_finished(
			const ie::sync_read_result &entries
			, const ie::error_info &error_info
			, util::timer_t timer
			, size_t offset, size_t size
			, std::function<void (const ie::read_result_entry &)> on_result
			, std::function<void ()> on_error);

	void
	send_chunk(ie::data_pointer data_pointer
			, std::function<void ()> on_result
			, std::function<void ()> on_error);

	void
	send_chunk_is_finished(const boost::system::error_code &error_code
			, util::timer_t timer
			, std::function<void ()> on_result
			, std::function<void ()> on_error);

	void
	read_and_send_chunk(size_t offset, size_t size
			, std::function<void ()> on_result
			, std::function<void ()> on_error);

	void
	read_and_send_range(size_t offset, size_t size
			, std::function<void ()> on_result
			, std::function<void ()> on_error);
	void
	read_and_send_ranges(ranges_t ranges, std::list<std::string> ranges_headers
			, std::function<void ()> on_result
			, std::function<void ()> on_error);

	void
	process_whole_file();

	void
	process_range(size_t offset, size_t size);

	void
	process_ranges(ranges_t ranges, std::list<std::string> boundaries);

	void
	detect_content_type(const ie::read_result_entry &entry);

	std::tuple<bool, bool> process_precondition_headers(const time_t timestamp, const size_t size);

	redirect_arg_tag
	get_redirect_arg();

	std::vector<std::tuple<std::string, std::string>>
	get_redirect_query_args();

	bool try_to_redirect_request(const ie::sync_lookup_result &slr, const size_t size);
	void start_reading(const size_t size, bool send_whole_file);

	size_t
	total_size();

	void
	on_error();

	void
	request_is_finished();

	ie::session
	get_session();

	ioremap::thevoid::http_response prospect_http_response;

	boost::optional<ie::session> m_session;
	mastermind::namespace_state_t ns_state;
	std::string key;
	parallel_lookuper_ptr_t parallel_lookuper_ptr;
	boost::optional<ie::lookup_result_entry> lookup_result_entry_opt;

	bool m_first_chunk;
	bool with_chunked_csum;
	bool headers_were_sent;
	bool some_data_were_sent;
	bool has_internal_storage_error;

	groups_t cached_groups;
	std::vector<int> bad_groups;

	boost::optional<std::chrono::seconds> expiration_time;
};

} // namespace elliptics

#endif /* SRC__GET__HPP */

