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

#include "utils.hpp"
#include "ns_settings.hpp"
#include "lookup_result.hpp"
#include "hex.hpp"

#include <crypto++/hmac.h>
#include <crypto++/sha.h>

#include <cctype>
#include <iterator>

std::ostream &
elliptics::operator << (std::ostream &stream, const ioremap::elliptics::error_info &error_info) {
	stream << "status=\"" << (error_info ? "bad" : "ok") << "\"; description=\"";

	if (error_info) {
		stream << error_info.message() << "\"; ";
	} else {
		stream << "success\"; ";
	}

	return stream;
}

std::string
elliptics::encode_for_xml(const std::string &string) {
	std::ostringstream oss;

	std::string::size_type pos = 0;

	do {
		auto pos2 = string.find_first_of("\"\'<>&", pos);
		oss << string.substr(pos, pos2 - pos);
		pos = pos2;

		if (pos != std::string::npos) {
			switch (string[pos]) {
			case '\"': oss << "&quot;"; break;
			case '\'': oss << "&apos;"; break;
			case '<': oss << "&lt;"; break;
			case '>': oss << "&gt;"; break;
			case '&': oss << "&amp;"; break;
			}
			pos += 1;
		}
	} while (pos != std::string::npos && pos < string.size());

	return oss.str();
}

std::string
elliptics::url_encode(const std::string &string) {
	std::string result;
	result.reserve(3 * string.size());
	auto output = std::back_inserter(result);

	for (auto it = string.begin(), end = string.end(); it != end; ++it) {
		char symbol = *it;

		if (isalnum(symbol)) {
			*output++ = symbol;
			continue;
		}

		switch (symbol) {
			case '-': case '_': case '.': case '!': case '~':
			case '*': case '(': case ')': case '\'':
				*output++ = symbol;
				break;
			default:
				*output++ = '%';
				output = hex_one(symbol, output);
		}
	}

	return result;
}

elliptics::file_location_t
elliptics::make_file_location(const ioremap::elliptics::sync_lookup_result &slr
		, const mastermind::namespace_state_t &ns_state) {
	const auto &path_prefix = ns_settings(ns_state).sign_path_prefix;

	for (auto it = slr.begin(); it != slr.end(); ++it) {
		if (it->error()) {
			continue;
		}

		lookup_result entry(*it, ns_settings(ns_state).sign_port);

		if (entry.path().substr(0, path_prefix.size()) != path_prefix) {
			throw std::runtime_error{
				"path_prefix does not match: prefix=" + path_prefix + "; path=" + entry.path()};
		}

		file_location_t file_location;

		file_location.host = entry.host();
		file_location.path = '/' + ns_state.name() + '/' + entry.path().substr(path_prefix.size());

		return file_location;
	}

	throw std::runtime_error{
			"cannot determine file location: there is no good lookup result entry"};
}

std::string
elliptics::make_signature_ts(boost::optional<std::chrono::seconds> opt_expiration_time
		, const mastermind::namespace_state_t &ns_state) {
	using namespace std::chrono;

	auto now = system_clock::now().time_since_epoch();
	auto expiration_time = opt_expiration_time.get_value_or(
			ns_settings(ns_state).redirect_expire_time);

	auto ts = duration_cast<microseconds>(now + expiration_time).count();

	return hex_one<std::string>(ts);
}

std::string
elliptics::make_signature_message(const file_location_t &file_location, const std::string &ts
		, const std::vector<std::tuple<std::string, std::string>> &args) {
	std::ostringstream oss;

	oss << file_location.host << file_location.path << '/' << ts;

	for (auto it = args.begin(), end = args.end(); it != end; ++it) {
		oss << '&' << std::get<0>(*it) << '=' << std::get<1>(*it);
	}

	return oss.str();
}

std::string
elliptics::make_signature(const std::string &message, const std::string &token) {
	using namespace CryptoPP;

	HMAC<SHA256> hmac((const byte *)token.data(), token.size());
	hmac.Update((const byte *)message.data(), message.size());
	std::vector<byte> res(hmac.DigestSize());
	hmac.Final(res.data());

	return hex<std::string>(res);
}

