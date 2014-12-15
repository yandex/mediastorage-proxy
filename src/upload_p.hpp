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

#ifndef MDS_PROXY__SRC__UPLOAD__P_HPP
#define MDS_PROXY__SRC__UPLOAD__P_HPP

#include "upload.hpp"

#include <fstream>
#include <list>

namespace elliptics {

class upload_helper_t
	: public std::enable_shared_from_this<upload_helper_t>
{
public:
	typedef std::function<void (void)> callback_t;

	struct entry_info_t {
		std::string address;
		std::string path;
		int group;
	};

	typedef std::vector<entry_info_t> entries_info_t;

	upload_helper_t(ioremap::swarm::logger bh_logger_
			, const ioremap::elliptics::session &session_, std::string key_
			, size_t total_size_, size_t offset_, size_t commit_coef_, size_t success_copies_num_
			);

	void
	write(const char *data, size_t size, callback_t on_wrote, callback_t on_error);

	void
	write(const ioremap::elliptics::data_pointer &data_pointer
			, callback_t on_wrote, callback_t on_error);

	bool
	is_finished() const;

	const entries_info_t &
	upload_result() const;

private:
	ioremap::swarm::logger &
	logger();

	ioremap::elliptics::async_write_result
	write_impl(const ioremap::elliptics::data_pointer &data_pointer);

	void
	log_chunk_upload(const std::string &write_type, size_t chunk_size);

	void
	update_groups(const ioremap::elliptics::sync_write_result &entries);

	void
	set_upload_result(const ioremap::elliptics::sync_write_result &entries);

	bool
	upload_is_good(const ioremap::elliptics::error_info &error_info);

	void
	on_data_wrote(const ioremap::elliptics::sync_write_result &entries
			, const ioremap::elliptics::error_info &error_info
			, callback_t on_wrote, callback_t on_error);

	ioremap::swarm::logger bh_logger;

public:

	ioremap::elliptics::session session;
	ioremap::elliptics::key key;

	size_t total_size;

private:
	size_t written_size;
	size_t offset;
	size_t commit_coef;
	size_t success_copies_num;

	std::vector<int> bad_groups;

	std::chrono::system_clock::time_point start_time;

	entries_info_t entries_info;
};

class upload_buffer_t
	: public std::enable_shared_from_this<upload_buffer_t>
{
public:
	typedef std::function<void (const std::shared_ptr<upload_helper_t> &)> on_wrote_callback_t;
	typedef std::function<void ()> on_error_callback_t;

	upload_buffer_t(ioremap::swarm::logger bh_logger_, std::string key_, size_t chunk_size_);

	bool
	append(const char *data, size_t size);

	void
	write(const ioremap::elliptics::session &session, size_t commit_coef, size_t success_copies_num
			, on_wrote_callback_t on_wrote_callback, on_error_callback_t on_error_callback);

	void
	stop();

	const std::string &
	get_key() const;

private:
	ioremap::swarm::logger &
	logger();

	void
	write_impl(on_wrote_callback_t on_wrote_callback_
			, const on_error_callback_t &on_error_callback);

	ioremap::swarm::logger bh_logger;

	std::string key;
	size_t chunk_size;
	typedef std::vector<char> buffer_t;
	std::list<buffer_t> buffers;

	size_t total_size;

	std::atomic<bool> is_stopped;

public:
	std::shared_ptr<upload_helper_t> upload_helper;
};

struct upload_simple_t
	: public ioremap::thevoid::buffered_request_stream<proxy>
	, public std::enable_shared_from_this<upload_simple_t>
{
	upload_simple_t(mastermind::namespace_state_t ns_state_
			, couple_t couple_, std::string filename_);

	void
	on_request(const ioremap::thevoid::http_request &http_request);

	void
	on_chunk(const boost::asio::const_buffer &buffer, unsigned int flags);

	void
	on_finished();

	void
	on_error(const boost::system::error_code &error_code);

	void
	remove_if_failed();

	void
	on_removed(const ioremap::elliptics::sync_remove_result &result
			, const ioremap::elliptics::error_info &error_info);

private:
	mastermind::namespace_state_t ns_state;
	couple_t couple;
	std::string filename;
	std::string key;

	bool m_single_chunk;

	std::shared_ptr<upload_helper_t> upload_helper;

	bool request_is_failed;
	bool reply_was_sent;
	std::mutex mutex;
};

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

	void
	on_finished(const std::shared_ptr<upload_helper_t> &upload_helper);

	void
	on_internal_error();

	void
	on_error();

	void
	send_result();

	void
	on_removed(const std::string &key, const ioremap::elliptics::sync_remove_result &result
			, const ioremap::elliptics::error_info &error_info);

	void
	send_error();

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

	void sm_init();
	void sm_headers();
	void sm_body();
	void sm_after_body();
	void sm_end();

	void start_writing();

	ioremap::thevoid::http_request http_request;
	mastermind::namespace_state_t ns_state;
	couple_t couple;

	std::string boundary;

	std::shared_ptr<upload_buffer_t> upload_buffer;
	std::string current_filename;

	std::vector<std::tuple<std::shared_ptr<upload_buffer_t>, std::string>> upload_buffers;

	std::mutex mutex;
	bool request_is_failed;

	std::atomic<size_t> upload_tasks_count;
	std::atomic<size_t> remove_tasks_count;
	std::atomic<bool> is_internal_error;
};

} // namespace elliptics

#endif /* MDS_PROXY__SRC__UPLOAD__P_HPP */

