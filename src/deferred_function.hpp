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

#ifndef MDS_PROXY__SRC__DEFERRED_FUNCTION__HPP
#define MDS_PROXY__SRC__DEFERRED_FUNCTION__HPP

#include <atomic>
#include <functional>


namespace elliptics {

class deferred_function_t {
public:
	typedef std::function<void (void)> function_t;

	deferred_function_t(function_t function_ = function_t(), int counter_ = 1)
		: function(std::move(function_))
		, counter(counter_)
	{
	}

	void
	defer(int count = 1) {
		counter += 1;
	}

	bool
	operator ()() {
		if (--counter) {
			return false;
		}

		if (!function) {
			return false;
		}

		function();

		reset();

		return true;
	}

	void
	reset(function_t function_ = function_t(), int counter_ = 1) {
		function = std::move(function_);
		counter = counter_;
	}

private:
	function_t function;
	std::atomic<int> counter;
};

} // namespace elliptics


#endif /* MDS_PROXY__SRC__DEFERRED_FUNCTION__HPP */

