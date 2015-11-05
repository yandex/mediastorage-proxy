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

#ifndef MDS_PROXY__SRC__HEX__HPP
#define MDS_PROXY__SRC__HEX__HPP

#include <iterator>
#include <type_traits>

namespace elliptics {

template <typename T, typename OutputIterator>
typename std::enable_if<std::is_integral<T>::value, OutputIterator>::type
hex_one(T val, OutputIterator out) {
	const size_t num_hex_digits = 2 * sizeof(T);
	char res[num_hex_digits];
	char *p = res + num_hex_digits;

	for (size_t i = 0; i != num_hex_digits; ++i, val >>= 4) {
		*--p = "0123456789abcdef"[val & 0x0F];
	}

	return std::copy(res, res + num_hex_digits, out);
}

template <typename OutputSequence, typename T>
OutputSequence
hex_one(T val) {
	OutputSequence output;
	output.reserve(2 * sizeof(T));

	hex_one(val, std::back_inserter(output));

	return output;
}

template <typename InputIterator, typename OutputIterator>
OutputIterator
hex(InputIterator it, InputIterator end, OutputIterator out) {

	for (; it != end; ++it) {
		out = hex_one(*it, out);
	}

	return out;
}

template <typename OutputSequence, typename InputSequence>
OutputSequence
hex(const InputSequence &input) {
	OutputSequence output;
	output.reserve(input.size() * (2 * sizeof(typename InputSequence::value_type)));

	hex(std::begin(input), std::end(input), std::back_inserter(output));

	return output;
}

template <typename Sequence>
Sequence
hex(const Sequence &input) {
	return hex<Sequence, Sequence>(input);
}

} // namespace elliptics

#endif /* MDS_PROXY__SRC__HEX__HPP */

