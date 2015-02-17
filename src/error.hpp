#ifndef MDS_PROXY__SRC__ERROR__HPP
#define MDS_PROXY__SRC__ERROR__HPP

#include "loggers.hpp"

#include <stdexcept>

namespace elliptics {

class proxy_error : public std::runtime_error
{
public:
	proxy_error(const std::string &message)
		: std::runtime_error(message)
	{}
};

class http_error : public proxy_error
{
public:
	http_error(int http_status_, const std::string &message)
		: proxy_error(message)
		, m_http_status(http_status_)
	{}

	int
	http_status() const {
		return m_http_status;
	}

	bool
	is_server_error() const {
		return m_http_status >= 500 && m_http_status <= 599;
	}


private:
	int m_http_status;
};

} // namespace elliptics

#endif /* MDS_PROXY__SRC__ERROR__HPP */

