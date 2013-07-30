#ifndef INCLUDE__ELLIPTICS_FASTCGI__DATA_CONTAINER_HPP
#define INCLUDE__ELLIPTICS_FASTCGI__DATA_CONTAINER_HPP

#include <map>
#include <string>
#include <sstream>
#include <ctime>

#include <boost/optional.hpp>
#include <boost/none.hpp>

#include <msgpack.hpp>

#include <elliptics/session.hpp>

namespace elliptics {

template<typename T>
void read(ioremap::elliptics::data_pointer &data_pointer, T&ob) {
	ob = *data_pointer.data<T>();
	data_pointer = data_pointer.skip<T>();
}

template<typename T>
struct type_traits_base {
	typedef T type;
	static ioremap::elliptics::data_pointer convert(const type &ob) {
		ioremap::elliptics::data_buffer data_buffer;
		msgpack::pack(data_buffer, ob);
		return std::move(data_buffer);
	}

	static type convert(ioremap::elliptics::data_pointer data_pointer) {
		type res;
		msgpack::unpacked unpacked;
		msgpack::unpack(&unpacked, (const char *)data_pointer.data(), data_pointer.size());
		unpacked.get().convert(&res);
		return res;
	}
};

template<size_t type>
struct type_traits;

enum DNET_COMMON_EMBED_TYPES {
	  DNET_FCGI_EMBED_DATA      = 1
	, DNET_FCGI_EMBED_TIMESTAMP = 2
};

template<> struct type_traits<DNET_FCGI_EMBED_DATA> : type_traits_base<void*> {};
template<> struct type_traits<DNET_FCGI_EMBED_TIMESTAMP> : type_traits_base<timespec> {
	static ioremap::elliptics::data_pointer convert(const type &ob) {
		ioremap::elliptics::data_buffer data_buffer(sizeof(type));
		type t;
		t.tv_sec = dnet_bswap64(ob.tv_sec);
		t.tv_nsec = dnet_bswap64(ob.tv_nsec);
		data_buffer.write(t.tv_sec);
		data_buffer.write(t.tv_nsec);
		return std::move(data_buffer);
	}

	static type convert(ioremap::elliptics::data_pointer data_pointer) {
		type res;

		read(data_pointer, res.tv_sec);
		read(data_pointer, res.tv_nsec);

		res.tv_sec = dnet_bswap64(res.tv_sec);
		res.tv_nsec = dnet_bswap64(res.tv_nsec);

		return res;
	}
};

class data_container_t {
public:
	data_container_t() {}

	data_container_t(const std::string &message)
		: data(std::move(ioremap::elliptics::data_buffer(message.data(), message.size())))
	{
	}

	data_container_t(const ioremap::elliptics::data_pointer &data_pointer)
		: data(data_pointer)
	{
	}

	data_container_t(const data_container_t &ds)
		: data(ds.data)
		, embeds(ds.embeds)
	{}

	data_container_t(data_container_t &&ds)
		: data(std::move(ds.data))
		, embeds(std::move(ds.embeds))
	{}

	data_container_t &operator = (data_container_t &&ds) {
		data = std::move(ds.data);
		embeds = std::move(ds.embeds);
		return *this;
	}

	template<size_t type>
	boost::optional<typename type_traits<type>::type> get() const {
		auto it = embeds.find(type);
		if (it == embeds.end())
			return boost::none;
		return type_traits<type>::convert(it->second.data_pointer);
	}

	template<size_t type>
	void set(const typename type_traits<type>::type &ob) {
		embed_t e(type_traits<type>::convert(ob), type, 0);
		embeds.insert(std::make_pair(type, e));
	}

	size_t embeds_count() const {
		return embeds.size();
	}

	static ioremap::elliptics::data_pointer pack(const data_container_t &ds);
	static data_container_t unpack(ioremap::elliptics::data_pointer data_pointer, bool embeded = false);

	ioremap::elliptics::data_pointer data;

private:
	struct embed_t {
		struct header_t {
			uint64_t size;
			uint32_t type;
			uint32_t flags;
		};

		embed_t() {}

		embed_t(const ioremap::elliptics::data_pointer &data_pointer, uint32_t type, uint32_t flags) {
			this->data_pointer = data_pointer;
			header.type = type;
			header.flags = flags;
			header.size = data_pointer.size();
		}

		header_t header;
		ioremap::elliptics::data_pointer data_pointer;
	};

	static embed_t::header_t bswap(const embed_t::header_t &header);

	std::map<size_t, embed_t> embeds;
};
} // namespace elliptcis

#endif /* INCLUDE__ELLIPTICS_FASTCGI__DATA_CONTAINER_HPP */
