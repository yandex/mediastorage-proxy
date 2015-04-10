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

#include "loggers.hpp"

ioremap::swarm::logger
copy_logger(const ioremap::swarm::logger &logger) {
	return ioremap::swarm::logger{logger, blackhole::log::attributes_t()};
}

shared_logger_t
make_shared_logger(const ioremap::swarm::logger &logger) {
	typedef ioremap::swarm::logger logger_t;
	return std::make_shared<logger_t>(logger_t{logger, blackhole::log::attributes_t()});
}

