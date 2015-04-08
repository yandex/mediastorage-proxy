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

#ifndef MDS_PROXY__SRC__UPLOAD__P_HPP
#define MDS_PROXY__SRC__UPLOAD__P_HPP

#include "upload.hpp"
#include "writer.hpp"
#include "buffered_writer.hpp"
#include "deferred_function.hpp"

#include <libmastermind/mastermind.hpp>

#include <fstream>
#include <list>
#include <stdexcept>

namespace elliptics {

class couple_iterator_t {
public:
	static
	mastermind::couple_info_t
	create_couple_info(mastermind::groups_t groups) {
		mastermind::couple_info_t result;
		result.id = *std::min_element(groups.begin(), groups.end());
		result.groups = std::move(groups);
		return result;
	}

	couple_iterator_t(mastermind::couple_sequence_t &couple_sequence_)
		: couple_sequence(std::move(couple_sequence_))
		, iter(couple_sequence.begin())
	{
	}

	couple_iterator_t(mastermind::couple_info_t single_couple_info_)
		: iter(couple_sequence.end())
		, single_couple_info(std::move(single_couple_info_))
	{
	}

	couple_iterator_t(mastermind::groups_t groups)
		: iter(couple_sequence.end())
		, single_couple_info(create_couple_info(std::move(groups)))
	{
	}

	bool
	has_next() const {
		return iter != couple_sequence.end() || single_couple_info.groups.size();
	}

	mastermind::couple_info_t
	next() {
		if (!has_next()) {
			throw std::runtime_error("null couple iterator");
		}

		if (single_couple_info.groups.size()) {
			auto result = std::move(single_couple_info);
			single_couple_info.groups.clear();
			return result;
		}

		auto result = *iter++;
		return result;
	}

private:
	mastermind::couple_sequence_t couple_sequence;
	mastermind::couple_sequence_t::const_iterator iter;

	mastermind::couple_info_t single_couple_info;

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
	remove();

	void
	on_removed(const ioremap::elliptics::sync_remove_result &result
			, const ioremap::elliptics::error_info &error_info);

private:
	mastermind::namespace_state_t ns_state;
	couple_t couple;
	int couple_id;
	std::string filename;
	std::string key;

	bool m_single_chunk;

	std::shared_ptr<writer_t> writer;

	deferred_function_t deferred_fallback;
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
	on_writer_is_finished(const std::string &current_filename
			, const std::error_code &error_code);

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
	on_removed(const std::string &key, const ioremap::elliptics::sync_remove_result &result
			, const ioremap::elliptics::error_info &error_info);

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

#endif /* MDS_PROXY__SRC__UPLOAD__P_HPP */

