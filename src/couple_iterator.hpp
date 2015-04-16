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

#ifndef MDS_PROXY__SRC__COUPLE_ITERATOR__HPP
#define MDS_PROXY__SRC__COUPLE_ITERATOR__HPP

#include <libmastermind/mastermind.hpp>
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

	couple_iterator_t(mastermind::couple_sequence_t couple_sequence_)
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

} // namespace elliptics

#endif /* MDS_PROXY__SRC__COUPLE_ITERATOR__HPP */

