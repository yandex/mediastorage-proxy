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

#include "upload_p.hpp"

namespace elliptics {

upload_simple_t::upload_simple_t(namespace_ptr_t ns_, couple_t couple_, std::string filename_)
	: ns(std::move(ns_))
	, couple(std::move(couple_))
	, filename(std::move(filename_))
	, key(ns->name + '.' + filename)
	, m_single_chunk(false)
	, request_is_failed(false)
	, reply_was_sent(false)
{
}

void
upload_simple_t::on_request(const ioremap::thevoid::http_request &http_request) {
	set_chunk_size(server()->m_write_chunk_size);

	auto query_list = http_request.url().query();
	auto offset = get_arg<uint64_t>(query_list, "offset", 0);

	upload_helper = std::make_shared<upload_helper_t>(
			ioremap::swarm::logger(logger(), blackhole::log::attributes_t())
			, server()->write_session(http_request, couple), key
			, *http_request.headers().content_length(), offset
			, server()->timeout_coef.data_flow_rate , ns->success_copies_num
			);
}

void
upload_simple_t::on_chunk(const boost::asio::const_buffer &buffer, unsigned int flags) {
	const char *buffer_data = boost::asio::buffer_cast<const char *>(buffer);
	const size_t buffer_size = boost::asio::buffer_size(buffer);

	// Fix flags to single_chunk if first chunk == data size 
	if ((flags & last_chunk) && m_single_chunk && (buffer_size == 0)) {
		MDS_LOG_INFO("on_chunk: skipping empty commit");
		return;
	}

	if ((flags == first_chunk) && (buffer_size == upload_helper->total_size)) {
		MDS_LOG_INFO("on_chunk: fixing flags to single_chunk");
		flags = single_chunk;
	}

	if (flags == single_chunk) {
		m_single_chunk = true;
	}

	{
		// There should be lambda instead of typedef & bind, but gcc 4.4 doesn't support it
		typedef void (upload_simple_t::*on_error_f)(int);
		upload_helper->write(buffer_data, buffer_size
				, std::bind(&upload_simple_t::on_finished, shared_from_this())
				, std::bind((on_error_f)&upload_simple_t::send_reply, shared_from_this(), 500));
	}
}

void
upload_simple_t::on_finished() {
	if (!upload_helper->is_finished()) {
		std::lock_guard<std::mutex> lock(mutex);
		(void) lock;

		if (request_is_failed) {
			return;
		}

		try_next_chunk();
		return;
	}

	std::ostringstream oss;
	oss 
		<< "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
		<< "<post obj=\"" << upload_helper->key.remote()
		<< "\" id=\"" << upload_helper->key.to_string()
		<< "\" groups=\"" << ns->groups_count
		<< "\" size=\"" << upload_helper->total_size
		<< "\" key=\"";

	if (ns->static_couple.empty()) {
		const auto &groups = upload_helper->session.get_groups();
		auto git = std::min_element(groups.begin(), groups.end());
		oss << *git << '/';
	}

	oss << filename << "\">\n";

	const auto &upload_result = upload_helper->upload_result();

	for (auto it = upload_result.begin(), end = upload_result.end(); it != end; ++it) {
		oss
			<< "<complete"
			<< " addr=\"" << it->address << "\""
			<< " path=\"" << it->path << "\""
			<< " group=\"" << it->group << "\""
			<< " status=\"0\"/>\n";
	}

	oss
		<< "<written>" << upload_result.size() << "</written>\n"
		<< "</post>";

	auto res_str = oss.str();

	ioremap::thevoid::http_response reply;
	ioremap::swarm::http_headers headers;

	reply.set_code(200);
	headers.set_content_length(res_str.size());
	headers.set_content_type("text/xml");
	reply.set_headers(headers);

	std::lock_guard<std::mutex> lock(mutex);
	(void) lock;

	if (!request_is_failed) {
		reply_was_sent = true;
		send_reply(std::move(reply), std::move(res_str));
	} else {
		remove_if_failed();
	}
}

void
upload_simple_t::on_error(const boost::system::error_code &error_code) {
	std::lock_guard<std::mutex> lock(mutex);
	(void) lock;

	if (reply_was_sent) {
		remove_if_failed();
		return;
	}

	if (request_is_failed) {
		return;
	}

	request_is_failed = true;

	MDS_LOG_ERROR("request is failed: %s", error_code.message().c_str());
}

void
upload_simple_t::remove_if_failed() {
	MDS_LOG_INFO("removing key %s", key.c_str());
	auto session = server()->remove_session(request(), couple);

	auto future = session.remove(key);
	future.connect(std::bind(&upload_simple_t::on_removed, shared_from_this()
				, std::placeholders::_1, std::placeholders::_2));
}

void
upload_simple_t::on_removed(const ioremap::elliptics::sync_remove_result &result
		, const ioremap::elliptics::error_info &error_info) {
	if (error_info) {
		MDS_LOG_ERROR("cannot remove key %s: %s", key.c_str(), error_info.message().c_str());
	} else {
		MDS_LOG_INFO("key %s was removed", key.c_str());
	}
}

} // namespace elliptics

