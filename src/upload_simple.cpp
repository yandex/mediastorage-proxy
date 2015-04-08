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

#include "upload_p.hpp"

namespace elliptics {

upload_simple_t::upload_simple_t(mastermind::namespace_state_t ns_state_
		, couple_iterator_t couple_iterator_, std::string filename_)
	: ns_state(std::move(ns_state_))
	, couple_iterator(std::move(couple_iterator_))
	, filename(std::move(filename_))
	, key(ns_state.name() + '.' + filename)
	, deferred_fallback([this] { fallback(); })
	, can_retry_couple(true)
	, has_internal_error(false)
{
}

void
upload_simple_t::on_request(const ioremap::thevoid::http_request &http_request) {
	set_chunk_size(server()->m_write_chunk_size);

	// The method runs in thevoid's io-loop, therefore proxy's dtor cannot run in this moment
	// Hence write_session can be safely used without any check
	lookup_session = *server()->lookup_session(http_request, {});
	write_session = *server()->write_session(http_request, {});

	offset = get_arg<uint64_t>(http_request.url().query(), "offset", 0);

	auto self = shared_from_this();
	auto next = [this, self] (util::expected<mastermind::couple_info_t> result) {
		try {
			process_couple_info(std::move(result.get()));
			try_next_chunk();
		} catch (const std::exception &ex) {
			MDS_LOG_INFO("cannot obtain couple: %s", ex.what());
			send_reply(500);
		}
	};

	get_next_couple_info(std::move(next));
}

void
upload_simple_t::on_chunk(const boost::asio::const_buffer &buffer, unsigned int flags) {
	const char *buffer_data = boost::asio::buffer_cast<const char *>(buffer);
	const size_t buffer_size = boost::asio::buffer_size(buffer);

	auto chunk = ioremap::elliptics::data_pointer::from_raw(
		reinterpret_cast<void *>(const_cast<char *>(buffer_data)), buffer_size);

	if (can_retry_couple) {
		data_pointer = chunk;
	}

	process_chunk(std::move(chunk));
}

// The on_error call means an error occurred during working with socket (either read or write).
// The close method is used as a part of send_headers callback.
// That means on_error will not be called if socket write error occurrs.
// Thus, only socket read error should be handled.
void
upload_simple_t::on_error(const boost::system::error_code &error_code) {
	MDS_LOG_ERROR("error during reading request: %s", error_code.message().c_str());
	deferred_fallback();
}

void
upload_simple_t::on_write_is_done(const std::error_code &error_code) {
	if (error_code) {
		process_chunk_write_error(error_code);
		return;
	}

	can_retry_couple = false;
	data_pointer = ioremap::elliptics::data_pointer();

	// Fallback will be executed if it is called twice: here and in on_error.
	if (deferred_fallback()) {
		return;
	}

	if (!writer->is_committed()) {
		try_next_chunk();
		return;
	}

	send_result();

	// Release writer to break cyclic links
	writer.reset();
}

void
upload_simple_t::send_result() {
	const auto &result = writer->get_result();

	std::ostringstream oss;
	oss 
		<< "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
		<< "<post obj=\"" << encode_for_xml(result.key)
		<< "\" id=\"" << result.id
		<< "\" groups=\"" << ns_state.settings().groups_count()
		<< "\" size=\"" << result.total_size
		<< "\" key=\"";

	if (proxy_settings(ns_state).static_couple.empty()) {
		oss << couple_info.id << '/';
	}

	oss << encode_for_xml(filename) << "\">\n";

	const auto &entries_info = result.entries_info;

	for (auto it = entries_info.begin(), end = entries_info.end(); it != end; ++it) {
		oss
			<< "<complete"
			<< " addr=\"" << it->address << "\""
			<< " path=\"" << it->path << "\""
			<< " group=\"" << it->group << "\""
			<< " status=\"0\"/>\n";
	}

	oss
		<< "<written>" << entries_info.size() << "</written>\n"
		<< "</post>";

	auto res_str = oss.str();

	ioremap::thevoid::http_response reply;
	ioremap::swarm::http_headers headers;

	reply.set_code(200);
	headers.set_content_length(res_str.size());
	headers.set_content_type("text/xml");
	reply.set_headers(headers);

	send_headers(std::move(reply)
			, std::bind(&upload_simple_t::headers_are_sent, shared_from_this()
				, res_str, std::placeholders::_1));
}

void
upload_simple_t::headers_are_sent(const std::string &res_str
		, const boost::system::error_code &error_code) {
	if (error_code) {
		MDS_LOG_ERROR("cannot send headers: %s", error_code.message().c_str());
		fallback();
		return;
	}

	MDS_LOG_INFO("headers are sent");

	send_data(std::move(res_str)
			, std::bind(&upload_simple_t::data_is_sent, shared_from_this()
				, std::placeholders::_1));
}

void
upload_simple_t::data_is_sent(const boost::system::error_code &error_code) {
	if (error_code) {
		MDS_LOG_ERROR("cannot send data: %s", error_code.message().c_str());
		fallback();
		return;
	}

	MDS_LOG_INFO("data is sent");

	close(boost::system::error_code());
}

void
upload_simple_t::fallback() {
	close(boost::system::error_code());
	remove([] (util::expected<void>) {});
}

void
upload_simple_t::remove(const util::expected<void>::callback_t next) {
	MDS_LOG_INFO("removing key %s", key.c_str());

	if (auto session = server()->remove_session(request(), couple_info.groups)) {
		auto future = session->remove(key);

		auto self = shared_from_this();
		auto next_ = [this, self, next] (const ioremap::elliptics::sync_remove_result &entries
				, const ioremap::elliptics::error_info &error_info) {
			if (error_info) {
				next(util::expected_from_exception<std::runtime_error>(error_info.message()));
			} else {
				next(util::expected<void>());
			}
		};

		future.connect(next_);

		return;
	}

	next(util::expected_from_exception<std::runtime_error>("remove-session is uninitialized"));
}

} // namespace elliptics

void
elliptics::upload_simple_t::get_next_couple_info(
		util::expected<mastermind::couple_info_t>::callback_t next) {
	if (!couple_iterator.has_next()) {
		next(util::expected_from_exception<std::runtime_error>(
					"there is no couple to process upload"));
		return;
	}

	auto self = shared_from_this();
	auto couple_info = couple_iterator.next();

	auto next_ = [this, self, couple_info, next] (util::expected<bool> result) {
		try {
			if (result.get()) {
				MDS_LOG_INFO("key can be written");
				next(couple_info);
				return;
			}

			MDS_LOG_INFO("key cannot be written");
			send_reply(403);
			return;
		} catch (const std::exception &ex) {
			MDS_LOG_ERROR("cannot check key for update: %s", ex.what());
			get_next_couple_info(std::move(next));
		}
	};

	auto session = lookup_session->clone();
	session.set_groups(couple_info.groups);

	can_be_written(
			make_shared_logger(logger())
			, std::move(session), key, ns_state
			, std::move(next_));
}

std::shared_ptr<elliptics::writer_t>
elliptics::upload_simple_t::make_writer(const groups_t &groups) {
	auto session = write_session->clone();
	session.set_groups(groups);

	auto self = shared_from_this();
	auto on_complete = [this, self] (const std::error_code &error_code) {
		on_write_is_done(error_code);
	};

	return std::make_shared<writer_t>(
			copy_logger(logger())
			, session, key
			, *request().headers().content_length(), offset
			, server()->timeout_coef.data_flow_rate , proxy_settings(ns_state).success_copies_num
			, on_complete, server()->limit_of_middle_chunk_attempts
			, server()->scale_retry_timeout
			);
}

void
elliptics::upload_simple_t::process_couple_info(mastermind::couple_info_t couple_info_) {
	couple_info = std::move(couple_info_);

	lookup_session->set_groups(couple_info.groups);
	write_session->set_groups(couple_info.groups);

	writer = make_writer(couple_info.groups);
}

void
elliptics::upload_simple_t::process_chunk(ioremap::elliptics::data_pointer chunk) {
	// There are two parallel activities:
	// 1. Reading client request
	// 2. Writing data into elliptics
	// Errors which could happen in second part are handled by writer object (involving removing of
	// needless file). But errors which could happen during reading request should be handled by
	// this object.
	// When such error is ocurred the on_error method will be called. But chunk writing can process
	// in this moment, so we cannot remove file and need to wait until writing is finished.
	// Otherwise if chunk writing does not process we have to initiate file removing in on_error
	// method.
	// To solve this problem deferred call of fallback method is used. The method will be executed
	// only on second call. The method is deferred by one call before each chunk writing, is called
	// after each chunk writing is finished and is called in on_error.
	deferred_fallback.defer();

	writer->write(chunk);
}

void
elliptics::upload_simple_t::process_chunk_write_error(const std::error_code &error_code) {
	if (error_code != make_error_code(writer_errc::insufficient_storage)) {
		has_internal_error = true;
	}

	ns_state.weights().set_feedback(couple_info.id
			, mastermind::namespace_state_t::weights_t::feedback_tag::temporary_unavailable);

	if (can_retry_couple) {
		writer.reset();

		auto self = shared_from_this();
		auto next = [this, self] (util::expected<void> result) {
			try {
				result.get();
				MDS_LOG_INFO("key was removed");
			} catch (const std::exception &ex) {
				MDS_LOG_ERROR("cannot remove key: %s", ex.what());
			}

			auto next = [this, self] (util::expected<mastermind::couple_info_t> result) {
				try {
					process_couple_info(std::move(result.get()));
					process_chunk(data_pointer);
				} catch (const std::exception &ex) {
					MDS_LOG_INFO("cannot obtain couple: %s", ex.what());
					send_reply(500);
				}
			};

			get_next_couple_info(std::move(next));
		};

		remove(std::move(next));
		return;
	}

	MDS_LOG_ERROR("could not write file into storage: %s"
			, error_code.message().c_str());

	if (has_internal_error) {
		send_reply(500);
		return;
	}

	if (error_code == make_error_code(writer_errc::insufficient_storage)) {
		send_reply(507);
	} else {
		send_reply(500);
	}
}

