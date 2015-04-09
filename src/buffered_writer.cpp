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

#include "buffered_writer.hpp"
#include "loggers.hpp"

class error_category_t
	: public std::error_category
{
public:
	const char *
	name() const {
		return "buffered writer error category";
	}

	std::string
	message(int ev) const {
		switch (static_cast<elliptics::buffered_writer_errc>(ev)) {
		case elliptics::buffered_writer_errc::success:
			return "success";
		case elliptics::buffered_writer_errc::interrupted:
			return "writing was interrupted";
		case elliptics::buffered_writer_errc::unexpected_event:
			return "unexpected event";
		default:
			return "unknown error";
		}
	}
};

const std::error_category &
elliptics::buffered_writer_category() {
	const static error_category_t instance;
	return instance;
}

std::error_code
elliptics::make_error_code(buffered_writer_errc e) {
	return std::error_code(static_cast<int>(e), buffered_writer_category());
}

std::error_condition
elliptics::make_error_condition(buffered_writer_errc e) {
	return std::error_condition(static_cast<int>(e), buffered_writer_category());
}

elliptics::buffered_writer_error::buffered_writer_error(buffered_writer_errc e
		, const std::string &message)
	: std::system_error(make_error_code(e), message)
{
}

elliptics::buffered_writer_t::buffered_writer_t(ioremap::swarm::logger bh_logger_,
		std::string key_, size_t chunk_size_ , callback_t on_finished_)
	: state(state_tag::appending)
	, bh_logger(std::move(bh_logger_))
	, key(std::move(key_))
	, chunk_size(chunk_size_)
	, on_finished(std::move(on_finished_))
	, total_size(0)
{
}

void
elliptics::buffered_writer_t::append(const char *data, size_t size) {
	lock_guard_t lock_guard(state_mutex);
	(void) lock_guard;

	switch (state) {
	case state_tag::appending:
		append_impl(data, size);
		break;
	case state_tag::writing:
	case state_tag::interrupting:
	case state_tag::completed:
	case state_tag::failed:
	case state_tag::interrupted:
		throw buffered_writer_error(buffered_writer_errc::unexpected_event);
	}
}

void
elliptics::buffered_writer_t::write(const ioremap::elliptics::session &session, size_t commit_coef
		, size_t success_copies_num, size_t limit_of_middle_chunk_attempts
		, double scale_retry_timeout) {
	lock_guard_t lock_guard(state_mutex);

	switch (state) {
	case state_tag::appending:
		state = state_tag::writing;
		write_impl(session, commit_coef, success_copies_num, limit_of_middle_chunk_attempts
				, scale_retry_timeout);
		break;
	case state_tag::interrupted:
		buffers.clear();
		result = writer->get_result();
		writer.reset();
		lock_guard.unlock();
		on_finished(buffered_writer_errc::interrupted);
		break;
	case state_tag::writing:
	case state_tag::interrupting:
	case state_tag::completed:
	case state_tag::failed:
		throw buffered_writer_error(buffered_writer_errc::unexpected_event);
	}
}

void
elliptics::buffered_writer_t::interrupt() {
	lock_guard_t lock_guard(state_mutex);
	(void) lock_guard;

	switch (state) {
	case state_tag::appending:
		state = state_tag::interrupted;
		buffers.clear();
		break;
	case state_tag::writing:
		state = state_tag::interrupting;
		break;
	case state_tag::interrupting:
	case state_tag::completed:
	case state_tag::failed:
	case state_tag::interrupted:
		// nothing to do
		break;
	}
}

const std::string &
elliptics::buffered_writer_t::get_key() const {
	return key;
}

bool
elliptics::buffered_writer_t::is_finished() const {
	return is_completed() || is_failed() || is_interrupted();
}

bool
elliptics::buffered_writer_t::is_completed() const {
	lock_guard_t lock_guard(state_mutex);
	(void) lock_guard;

	return state_tag::completed == state;
}

bool
elliptics::buffered_writer_t::is_failed() const {
	lock_guard_t lock_guard(state_mutex);
	(void) lock_guard;

	return state_tag::failed == state;
}

bool
elliptics::buffered_writer_t::is_interrupted() const {
	lock_guard_t lock_guard(state_mutex);
	(void) lock_guard;

	return state_tag::interrupted == state;
}

const elliptics::writer_t::result_t &
elliptics::buffered_writer_t::get_result() const {
	return result;
}

ioremap::swarm::logger &
elliptics::buffered_writer_t::logger() {
	return bh_logger;
}

void
elliptics::buffered_writer_t::append_impl(const char *data, size_t size) {
	total_size += size;

	{
		size_t buffers_size = 0;

		if (!buffers.empty()) {
			buffers_size += (buffers.size() - 1) * chunk_size;
			buffers_size += buffers.back().size();
		}
		MDS_LOG_DEBUG("buffer append: key=%s append-size=%llu buffer-size=%llu total-size=%llu"
				, key.c_str(), size, buffers_size, total_size);
	}

	while (size != 0) {
		if (buffers.empty() || buffers.back().size() == chunk_size) {
			buffer_t buffer;
			buffer.reserve(chunk_size);

			buffers.emplace_back(std::move(buffer));
		}

		auto &buffer = buffers.back();
		auto buffer_size = buffer.size();

		auto part_size = std::min(size, chunk_size - buffer_size);
		buffer.insert(buffer.end(), data, data + part_size);

		data += part_size;
		size -= part_size;
	}
}

void
elliptics::buffered_writer_t::write_impl(const ioremap::elliptics::session &session
		, size_t commit_coef, size_t success_copies_num, size_t limit_of_middle_chunk_attempts
		, double scale_retry_timeout) {
	auto self = shared_from_this();
	auto callback = [this, self] (const std::error_code &error_code) {
		on_chunk_wrote(error_code);
	};

	writer = std::make_shared<writer_t>(
			ioremap::swarm::logger(logger(), blackhole::log::attributes_t()), session, get_key()
			, total_size, 0, commit_coef, success_copies_num, callback
			, limit_of_middle_chunk_attempts, scale_retry_timeout);

	write_chunk();
}

void
elliptics::buffered_writer_t::write_chunk() {
	auto buffer = std::move(buffers.front());
	buffers.pop_front();
	writer->write(buffer.data(), buffer.size());
}

void
elliptics::buffered_writer_t::on_chunk_wrote(const std::error_code &error_code) {
	lock_guard_t lock_guard(state_mutex);

	switch (state) {
	case state_tag::writing:
		if (error_code) {
			state = state_tag::failed;
			result = writer->get_result();
			writer.reset();
			lock_guard.unlock();
			on_finished(error_code);
			break;
		}

		if (buffers.empty()) {
			state = state_tag::completed;
			result = writer->get_result();
			writer.reset();
			lock_guard.unlock();
			on_finished(buffered_writer_errc::success);
			break;
		}

		write_chunk();
		break;
	case state_tag::interrupting:
		state = state_tag::interrupted;
		buffers.clear();
		result = writer->get_result();
		writer.reset();
		lock_guard.unlock();
		on_finished(buffered_writer_errc::interrupted);
		break;
	case state_tag::appending:
	case state_tag::completed:
	case state_tag::failed:
	case state_tag::interrupted:
		throw buffered_writer_error(buffered_writer_errc::unexpected_event);
	}
}

