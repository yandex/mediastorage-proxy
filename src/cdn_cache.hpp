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

#ifndef MDS_PROXY__SRC__CDN_CACHE__HPP
#define MDS_PROXY__SRC__CDN_CACHE__HPP

#include "loggers.hpp"

#include <unordered_set>
#include <memory>
#include <mutex>
#include <thread>
#include <string>

namespace elliptics {

class cdn_cache_t {
public:
	struct config_t {
		std::string url;
		int timeout;
		int update_period;
		std::string cache_path;
	};

	cdn_cache_t(ioremap::swarm::logger bh_logger_, config_t config_);
	~cdn_cache_t();

	bool
	check_host(const std::string &host);

	void
	cache_force_update();

private:
	typedef std::shared_ptr<std::unordered_set<std::string>> cache_ptr_t;

	ioremap::swarm::logger &
	logger();

	void
	serialize() const;

	void
	deserialize();

	cache_ptr_t
	parse_cache(const std::string &raw_data) const;

	cache_ptr_t
	copy_cache() const;

	void
	set_cache(cache_ptr_t cache_ptr_);

	void
	update_cache();

	void
	background_loop();

	ioremap::swarm::logger bh_logger;

	config_t config;

	mutable std::mutex cache_mutex;
	cache_ptr_t cache_ptr;

	std::mutex background_updater_mutex;
	std::thread background_updater;
	std::condition_variable background_updater_cv;
	bool work_is_done;
};

} // namespace elliptics

#endif /* MDS_PROXY__SRC__CDN_CACHE__HPP */

