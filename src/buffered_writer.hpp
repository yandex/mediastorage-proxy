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

#ifndef MDS_PROXY__SRC__BUFFERED_WRITER__HPP
#define MDS_PROXY__SRC__BUFFERED_WRITER__HPP

#include "writer.hpp"

#include <system_error>

namespace elliptics {

enum class buffered_writer_errc {
	  success
	, interrupted
	, unexpected_event
};

const std::error_category &
buffered_writer_category();

std::error_code
make_error_code(buffered_writer_errc e);

std::error_condition
make_error_condition(buffered_writer_errc e);

class buffered_writer_error : public std::system_error
{
public:
	buffered_writer_error(buffered_writer_errc e, const std::string &message = "");
};

class buffered_writer_t : public std::enable_shared_from_this<buffered_writer_t>
{
public:
	typedef std::function<void (const std::error_code &)> callback_t;
	typedef std::shared_ptr<writer_t> writer_ptr_t;

	buffered_writer_t(ioremap::swarm::logger bh_logger_, std::string key_, size_t chunk_size_
			, callback_t on_finished_);

	void
	append(const char *data, size_t size);

	void
	write(const ioremap::elliptics::session &session, size_t commit_coef
			, size_t success_copies_num, size_t limit_of_middle_chunk_attempts
			, double scale_retry_timeout);

	void
	interrupt();

	const std::string &
	get_key() const;

	bool
	is_finished() const;

	bool
	is_completed() const;

	bool
	is_failed() const;

	bool
	is_interrupted() const;

	const writer_ptr_t &
	get_writer() const;

	const writer_t::result_t &
	get_result() const;

private:
	enum class state_tag {
		  appending
		, writing
		, interrupting
		, completed
		, failed
		, interrupted
	};

	typedef std::recursive_mutex mutex_t;
	typedef std::unique_lock<mutex_t> lock_guard_t;
	typedef std::vector<char> buffer_t;

	ioremap::swarm::logger &
	logger();

	void
	append_impl(const char *data, size_t size);

	void
	write_impl(const ioremap::elliptics::session &session, size_t commit_coef
			, size_t success_copies_num, size_t limit_of_middle_chunk_attempts
			, double scale_retry_timeout);

	void
	write_chunk();

	void
	on_chunk_wrote(const std::error_code &error_code);

	state_tag state;
	mutable mutex_t state_mutex;

	ioremap::swarm::logger bh_logger;

	std::string key;
	size_t chunk_size;

	callback_t on_finished;

	std::list<buffer_t> buffers;

	size_t total_size;

	writer_ptr_t writer;
	writer_t::result_t result;
};

} // namespace elliptics

namespace std {

template <>
struct is_error_code_enum<elliptics::buffered_writer_errc>
	: public true_type
{};

} // namespace std

#endif /* MDS_PROXY__SRC__BUFFERED_WRITER__HPP */

