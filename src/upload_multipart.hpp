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

#ifndef MDS_PROXY__SRC__UPLOAD_MULTIPART__HPP
#define MDS_PROXY__SRC__UPLOAD_MULTIPART__HPP

#include "upload.hpp"
#include "writer.hpp"
#include "couple_iterator.hpp"
#include "expected.hpp"
#include "buffered_writer.hpp"
#include "deferred_function.hpp"
#include "remove.hpp"

#include <libmastermind/mastermind.hpp>

#include <fstream>
#include <list>
#include <stdexcept>
#include <functional>

namespace elliptics {

struct upload_multipart_t
	: public ioremap::thevoid::request_stream<proxy>
	, public std::enable_shared_from_this<upload_multipart_t>
{
	upload_multipart_t(mastermind::namespace_state_t ns_state_, couple_t couple_);

	void
	on_headers(ioremap::thevoid::http_request &&http_request_);

	size_t
	on_data(const boost::asio::const_buffer &buffer);

	void
	on_close(const boost::system::error_code &error);

private:

	enum class multipart_state_tag {
		init, headers, body, after_body, end
	};

	class multipart_context_t {
	public:
		typedef std::vector<char> buffer_t;
		typedef buffer_t::const_iterator const_iterator;

		multipart_context_t();

		const_iterator
		begin() const;

		const_iterator
		end() const;

		size_t
		size() const;

		void
		append(const char *data, size_t size);

		void
		skip(size_t size);

		void
		trim();

		void
		interrupt(bool is_error_);

		bool
		interrupted() const;

		bool
		error() const;

		multipart_state_tag state;

	private:
		void
		reset();

		buffer_t buffer;
		buffer_t::const_iterator iterator;

		bool need_data;
		bool is_error;
		bool is_interrupted;
	} multipart_context;

	enum class error_type_tag {
		  none
		, insufficient_storage
		, internal
		, multipart
		, client
	};

	void sm_init();
	void sm_headers();
	void sm_body();
	void sm_after_body();
	void sm_end();

	void start_writing();

	void
	on_writer_is_finished(const std::error_code &error_code);

	void
	set_error(error_type_tag e);

	bool
	is_error();

	error_type_tag
	get_error();

	void
	interrupt_writers(error_type_tag e);

	void
	interrupt_writers();

	void
	on_writers_are_finished();

	void
	send_result();

	void
	headers_are_sent(const std::string &res_str, const boost::system::error_code &error_code);

	void
	data_is_sent(const boost::system::error_code &error_code);

	void
	remove_files();

	void
	on_removed(util::expected<remove_result_t> result);

	void
	send_error();

	deferred_function_t interrupt_writers_once;
	deferred_function_t join_upload_tasks;
	deferred_function_t join_remove_tasks;

	error_type_tag error_type;
	std::mutex error_type_mutex;

	ioremap::thevoid::http_request http_request;
	mastermind::namespace_state_t ns_state;
	couple_t couple;
	int couple_id;

	std::string boundary;

	std::shared_ptr<buffered_writer_t> buffered_writer;
	std::string current_filename;

	std::mutex buffered_writers_mutex;
	std::map<std::string, std::shared_ptr<buffered_writer_t>> buffered_writers;
	std::map<std::string, writer_t::result_t> results;
};

} // namespace elliptics

#endif /* MDS_PROXY__SRC__UPLOAD_MULTIPART__HPP */

