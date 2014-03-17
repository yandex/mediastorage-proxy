#ifndef MAGIC_PROVIDER_HPP
#define MAGIC_PROVIDER_HPP

#include <boost/noncopyable.hpp>

#include <magic.h>

namespace elliptics {

class magic_provider : private boost::noncopyable {

public:
	magic_provider () {
		magic_ = magic_open(MAGIC_MIME_TYPE);
		magic_load(magic_, 0);
	}

	~magic_provider() {
		magic_close(magic_);
	}

public:
	std::string type(const std::string &content) {
		const char *result(magic_buffer(magic_, content.data(), content.size()));

		if (result) {
			return result;
		}

		return "application/octet-stream";
	}

private:
	magic_t magic_;

};

} // namespace elliptics

#endif /* MAGIC_PROVIDER_HPP */
