#ifndef _ELLIPTICS_LOOKUP_RESULT_HPP_
#define _ELLIPTICS_LOOKUP_RESULT_HPP_

#include <elliptics/session.hpp>

#include <boost/optional.hpp>
#include <boost/none.hpp>

namespace elliptics {

class lookup_result {
public:
	lookup_result(const ioremap::elliptics::lookup_result_entry &entry, std::string sign_port);

	const std::string &host() const;
	uint16_t port() const;
	int group() const;
	int status() const;
	const std::string &addr() const;
	const std::string &path() const;
	const std::string &full_path() const;

private:
	ioremap::elliptics::lookup_result_entry m_entry;
	std::string m_sign_port;

	mutable boost::optional<std::string> m_host;
	mutable boost::optional<uint16_t> m_port;
	mutable boost::optional<std::string> m_addr;
	mutable boost::optional<std::string> m_path;
	mutable boost::optional<std::string> m_full_path;
};

} // namespace elliptics

#endif /* _ELLIPTICS_LOOKUP_RESULT_HPP_ */
