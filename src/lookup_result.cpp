#include "lookup_result.hpp"

#include <elliptics/interface.h>

#include <sstream>

#include <boost/lexical_cast.hpp>

#include <sys/socket.h>
#include <netdb.h>

namespace {

static inline char*
file_backend_get_dir(const unsigned char *id, uint64_t bit_num, char *dst) {
	char *res = dnet_dump_id_len_raw(id, (bit_num + 7) / 8, dst);

	if (res) {
		res[bit_num / 4] = '\0';
	}

	return res;
}

} // namespace

namespace elliptics {

lookup_result::lookup_result(const ioremap::elliptics::lookup_result_entry &entry, bool eblob_style_path, int base_port, int directory_bit_num)
	: m_entry(entry)
	, m_eblob_style_path(eblob_style_path)
	, m_base_port(base_port)
	, m_directory_bit_num(directory_bit_num)
{
}

const std::string &lookup_result::host() const
{
	if (!m_host) {
		char hbuf[NI_MAXHOST];
		memset(hbuf, 0, NI_MAXHOST);
		struct dnet_addr *addr = m_entry.storage_address();

		if (getnameinfo((const sockaddr*)addr, addr->addr_len, hbuf, sizeof(hbuf), NULL, 0, 0) != 0) {
			throw std::runtime_error("can not make dns lookup");
		}

		m_host.reset(hbuf);
	}

	return *m_host;
}

uint16_t lookup_result::port() const
{
	if (!m_port) {
		struct dnet_addr *addr = m_entry.storage_address();
		m_port.reset(dnet_server_convert_port((struct sockaddr *)addr->addr, addr->addr_len));
	}

	return *m_port;
}

int lookup_result::group() const
{
	return m_entry.command()->id.group_id;
}

int lookup_result::status() const
{
	return m_entry.command()->status;
}

const std::string &lookup_result::addr() const
{
	if (!m_addr) {
		char addr_dst[512];
		struct dnet_addr *addr = m_entry.storage_address();
		dnet_server_convert_dnet_addr_raw(addr, addr_dst, sizeof (addr_dst) - 1);
		std::string tmp(addr_dst);
		m_addr.reset(addr_dst);
	}

	return *m_addr;
}

const std::string &lookup_result::path() const
{
	if (!m_path) {
		std::string p;
		struct dnet_file_info *info = m_entry.file_info();
		if (m_eblob_style_path) {
			p = m_entry.file_path();
			p = p.substr(p.find_last_of("/\\") + 1);
			std::ostringstream oss;
			oss << '/' << (port() - m_base_port) << '/'
				<< p << ':' << info->offset
				<< ':' << info->size;
			m_path.reset(oss.str());
		} else {
			char id[2 * DNET_ID_SIZE + 1];
			char hex_dir[2 * DNET_ID_SIZE + 1];

			dnet_dump_id_len_raw(m_entry.command()->id.id, DNET_ID_SIZE, id);
			file_backend_get_dir(m_entry.command()->id.id, m_directory_bit_num, hex_dir);

			std::ostringstream oss;
			oss << '/' << boost::lexical_cast<std::string>(port() - m_base_port) << '/' << hex_dir << '/' << id;
			m_path.reset(oss.str());
		}
	}

	return *m_path;
}

const std::string &lookup_result::full_path() const
{
	if (!m_full_path) {
		struct dnet_file_info *info = m_entry.file_info();
		m_full_path.reset((char *)(info + 1));
	}

	return *m_full_path;
}

} // namespace elliptics
