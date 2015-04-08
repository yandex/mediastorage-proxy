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

#ifndef MDS_PROXY__SRC__EXPECTED__HPP
#define MDS_PROXY__SRC__EXPECTED__HPP

#include <stdexcept>
#include <utility>

namespace util {

namespace detail {

struct expected_with_exception {
	std::exception_ptr exception_ptr;
};

} // namespace detail

template <typename T>
class expected {
public:
	typedef std::function<void (expected<T>)> callback_t;

	template <typename E>
	static
	expected<T>
	from_exception(const E &exception) {
		if (typeid(exception) != typeid(E)) {
			throw std::runtime_error("slicing detected");
		}

		return from_exception(std::make_exception_ptr(exception));
	}

	static
	expected<T>
	from_exception(std::exception_ptr exception_ptr) {
		expected<T> result;
		result.value_is_set = false;
		new (&result.exception_ptr) std::exception_ptr(std::move(exception_ptr));
		return result;
	}

	static
	expected<T>
	from_exception() {
		return from_exception(std::current_exception());
	}

	template <typename F>
	static
	expected<T> from_function(F function) {
		try {
			return expected(function());
		} catch (...) {
			return from_exception();
		}
	}

	expected(const T &value_)
		: value_is_set(true)
		, value(value_)
	{}

	expected(T &&value_)
		: value_is_set(true)
		, value(std::move(value_))
	{}

	expected(const expected &that)
		: value_is_set(that.value_is_set)
	{
		if (value_is_set) {
			new (&value) T(that.value);
		} else {
			new (&exception_ptr) std::exception_ptr(that.exception_ptr);
		}
	}

	expected(expected &&that)
		: value_is_set(that.value_is_set)
	{
		if (value_is_set) {
			new (&value) T(std::move(that.value));
		} else {
			new (&exception_ptr) std::exception_ptr(std::move(that.exception_ptr));
		}
	}

	expected(detail::expected_with_exception &&that)
		: value_is_set(false)
		, exception_ptr(std::move(that.exception_ptr))
	{}

	~expected() {
		using std::exception_ptr;

		if (value_is_set) {
			value.~T();
		} else {
			this->exception_ptr.~exception_ptr();
		}
	}


	void
	swap(expected &rhs) {
		if (value_is_set) {
			if (rhs.value_is_set) {
				using std::swap;
				swap(value, rhs.value);
			} else {
				auto tmp = std::move(rhs.exception_ptr);
				new (&rhs.value) T(std::move(value));
				new (&exception_ptr) std::exception_ptr(tmp);
				std::swap(value_is_set, rhs.value_is_set);
			}
		} else {
			if (rhs.value_is_set) {
				rhs.swap(*this);
			} else {
				exception_ptr.swap(rhs.exception_ptr);
			}
		}
	}

	bool
	has_value() const {
		return value_is_set;
	}

	T &
	get() {
		if (!value_is_set) {
			std::rethrow_exception(exception_ptr);
		}

		return value;
	}

	const T &
	get() const {
		if (!value_is_set) {
			std::rethrow_exception(exception_ptr);
		}

		return value;
	}

private:
	expected()
	{}

	bool value_is_set;
	union {
		T value;
		std::exception_ptr exception_ptr;
	};

};

template <>
class expected<void> {
public:
	typedef std::function<void (expected<void>)> callback_t;

	template <typename E>
	static
	expected<void>
	from_exception(const E &exception) {
		if (typeid(exception) != typeid(E)) {
			throw std::runtime_error("slicing detected");
		}

		return from_exception(std::make_exception_ptr(exception));
	}

	static
	expected<void>
	from_exception(std::exception_ptr exception_ptr) {
		expected<void> result;
		result.exception_ptr = std::exception_ptr(std::move(exception_ptr));
		return result;
	}

	static
	expected<void>
	from_exception() {
		return from_exception(std::current_exception());
	}

	template <typename F>
	static
	expected<void> from_function(F function) {
		try {
			return expected(function());
		} catch (...) {
			return from_exception();
		}
	}

	expected()
	{}

	expected(const expected &that)
		: exception_ptr(that.exception_ptr)
	{}

	expected(expected &&that)
		: exception_ptr(std::move(that.exception_ptr))
	{}

	expected(detail::expected_with_exception &&that)
		: exception_ptr(std::move(that.exception_ptr))
	{}

	~expected() {
	}


	void
	swap(expected &rhs) {
		exception_ptr.swap(rhs.exception_ptr);
	}

	bool
	has_value() const {
		return !exception_ptr;
	}

	void
	get() {
		if (exception_ptr) {
			std::rethrow_exception(exception_ptr);
		}
	}

private:
	std::exception_ptr exception_ptr;

};

template <typename E, typename... Args>
detail::expected_with_exception
expected_from_exception(Args &&...args) {
	return detail::expected_with_exception{
		std::make_exception_ptr(E(std::forward<Args>(args)...))
	};
}

} // namespace util

#endif /* MDS_PROXY__SRC__EXPECTED__HPP */

