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

#ifndef SRC__LOGGERS_HPP
#define SRC__LOGGERS_HPP

#include <swarm/logger.hpp>
#include <cocaine/framework/logging.hpp>
#include <elliptics/session.hpp>
#include <memory>

#define MDS_LOG(verb, ...) BH_LOG(logger(), verb, __VA_ARGS__)
#define MDS_LOG_ERROR(...) MDS_LOG(SWARM_LOG_ERROR, __VA_ARGS__)
#define MDS_LOG_WARNING(...) MDS_LOG(SWARM_LOG_WARNING, __VA_ARGS__)
#define MDS_LOG_INFO(...) MDS_LOG(SWARM_LOG_INFO, __VA_ARGS__)
#define MDS_LOG_NOTICE(...) MDS_LOG(SWARM_LOG_NOTICE, __VA_ARGS__)
#define MDS_LOG_DEBUG(...) MDS_LOG(SWARM_LOG_DEBUG, __VA_ARGS__)

typedef std::shared_ptr<ioremap::swarm::logger> shared_logger_t;

ioremap::swarm::logger
copy_logger(const ioremap::swarm::logger &logger);

shared_logger_t
make_shared_logger(const ioremap::swarm::logger &logger);

class cocaine_logger_t : public cocaine::framework::logger_t {
public:
	cocaine_logger_t(ioremap::swarm::logger logger_)
		: logger(std::move(logger_))
	{}

	cocaine_logger_t(cocaine_logger_t &&other)
		: logger(std::move(other.logger))
	{}

	void emit(cocaine::logging::priorities priority, const std::string& message) {
		//int lvl = level(priority);
		//m_logger.log(lvl, "%s", message.c_str());
		BH_LOG(logger, level(priority), message);
	}

	cocaine::logging::priorities verbosity() const {
		using namespace cocaine::logging;
		return priorities::debug;
		/*switch(m_logger.log().verbosity()) {
		case blackhole::defaults::severity::error:
			return priorities::error;
		case blackhole::defaults::severity::info:
			return priorities::info;
		case blackhole::defaults::severity::notice:
			return priorities::info;
		default:
			return priorities::debug;
		}*/
	}

private:
	blackhole::defaults::severity level(cocaine::logging::priorities priority) {
		using namespace cocaine::logging;
		switch(priority) {
		case priorities::ignore:
			return blackhole::defaults::severity::error;
		case priorities::error:
			return blackhole::defaults::severity::error;
		case priorities::warning:
			return blackhole::defaults::severity::warning;
		case priorities::info:
			return blackhole::defaults::severity::info;
		default:
			return blackhole::defaults::severity::debug;
		}
	}

	ioremap::swarm::logger logger;
};

#endif /* SRC__LOGGERS_HPP */
