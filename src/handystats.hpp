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

#ifndef SRC__HANDYSTATS_HPP
#define SRC__HANDYSTATS_HPP

#include <cstdio>
#include <string>

#include <thevoid/stream.hpp>

#include <handystats/chrono.hpp>

#define __HANDY_NAME_USE BOOST_PP_CAT(__C_HANDY_NAME_BUF_, __LINE__)
#define __HANDY_NAME_SET(...) char __HANDY_NAME_USE[255]; snprintf(__HANDY_NAME_USE, (sizeof(__HANDY_NAME_USE) - 1), __VA_ARGS__)
#define FORMATTED(MACRO, NAME_ARGS, ...) __HANDY_NAME_SET NAME_ARGS; MACRO(__HANDY_NAME_USE, ##__VA_ARGS__)

namespace elliptics {

struct base_request_wrapper
{
	base_request_wrapper()
	{
		m_start_timestamp = handystats::chrono::internal_clock::now();

		m_sent_bytes = 0;
		m_received_bytes = 0;
	}

	handystats::chrono::time_point m_start_timestamp;

	size_t m_sent_bytes;
	size_t m_received_bytes;

	ioremap::thevoid::http_response m_response;
};

template <typename RequestStream>
struct request_wrapper
	: base_request_wrapper
	, std::enable_if <
		std::is_base_of<ioremap::thevoid::base_request_stream, RequestStream>::value,
		RequestStream
	>::type
{
	template <typename... Args>
	request_wrapper(Args&& ...args)
		: RequestStream(args...)
	{
	}

	void send_reply(ioremap::thevoid::http_response &&rep) {
		m_response = rep;
		RequestStream::send_reply(std::move(rep));
	}

	template <typename T>
	void send_reply(ioremap::thevoid::http_response &&rep, T &&data) {
		m_sent_bytes += data.size();
		m_response = rep;
		RequestStream::send_reply(std::move(rep), std::move(data));
	}

	void send_reply(int code) {
		m_response.set_code(code);
		RequestStream::send_reply(code);
	}

	void send_headers(ioremap::thevoid::http_response &&rep, typename RequestStream::result_function &&handler) {
		m_response = rep;
		RequestStream::send_headers(std::move(rep), std::move(handler));
	}

	template <typename T>
	void send_headers(ioremap::thevoid::http_response &&rep, T &&data, typename RequestStream::result_function &&handler) {
		m_sent_bytes += data.size();
		m_response = rep;
		RequestStream::send_headers(std::move(rep), std::move(data), std::move(handler));
	}

	void send_data(const boost::asio::const_buffer &data, typename RequestStream::result_function &&handler) {
		m_sent_bytes += boost::asio::buffer_size(data);
		RequestStream::send_data(data, std::move(handler));
	}

	template <typename T>
	typename std::enable_if<!std::is_same<T, boost::asio::const_buffer>::value, void>::type
	send_data(T &&data, typename RequestStream::result_function &&handler) {
		m_sent_bytes += data.size();
		RequestStream::send_data(std::move(data), std::move(handler));
	}
};

} // namespace elliptics

#endif // SRC__HANDYSTATS_HPP
