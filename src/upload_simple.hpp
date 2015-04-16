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

#ifndef MDS_PROXY__SRC__UPLOAD_SIMPLE__HPP
#define MDS_PROXY__SRC__UPLOAD_SIMPLE__HPP

#include "upload.hpp"
#include "writer.hpp"
#include "couple_iterator.hpp"
#include "expected.hpp"
#include "buffered_writer.hpp"
#include "deferred_function.hpp"

#include <libmastermind/mastermind.hpp>

#include <fstream>
#include <list>
#include <stdexcept>
#include <functional>

namespace elliptics {

struct upload_simple_t
	: public ioremap::thevoid::buffered_request_stream<proxy>
	, public std::enable_shared_from_this<upload_simple_t>
{
	upload_simple_t(mastermind::namespace_state_t ns_state_
			, couple_iterator_t couple_iterator_, std::string filename_);

	void
	on_request(const ioremap::thevoid::http_request &http_request);

	void
	on_chunk(const boost::asio::const_buffer &buffer, unsigned int flags);

	void
	on_error(const boost::system::error_code &error_code);

	void
	on_write_is_done(const std::error_code &error_code);

	void
	send_result();

	void
	headers_are_sent(const std::string &res_str, const boost::system::error_code &error_code);

	void
	data_is_sent(const boost::system::error_code &error_code);

	void
	fallback();

	void
	remove(const util::expected<void>::callback_t next);

private:
	void
	get_next_couple_info(util::expected<mastermind::couple_info_t>::callback_t next);

	void
	process_couple_info(mastermind::couple_info_t couple_info_);

	void
	process_chunk(ioremap::elliptics::data_pointer chunk);

	void
	process_chunk_write_error(const std::error_code &error_code);

	std::shared_ptr<writer_t>
	make_writer(const groups_t &groups);

	mastermind::namespace_state_t ns_state;
	couple_iterator_t couple_iterator;
	std::string filename;
	std::string key;

	std::shared_ptr<writer_t> writer;
	ioremap::elliptics::data_pointer data_pointer;

	deferred_function_t deferred_fallback;

	boost::optional<ioremap::elliptics::session> lookup_session;
	boost::optional<ioremap::elliptics::session> write_session;

	size_t offset;
	mastermind::couple_info_t couple_info;
	bool can_retry_couple;

	bool has_internal_error;
	size_t attempt_to_choose_a_couple;
};

} // namespace elliptics

#endif /* MDS_PROXY__SRC__UPLOAD_SIMPLE__HPP */

