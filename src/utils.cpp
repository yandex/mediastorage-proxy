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

