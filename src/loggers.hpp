#ifndef SRC__LOGGERS_HPP
#define SRC__LOGGERS_HPP

#include <swarm/logger.h>
#include <cocaine/framework/logging.hpp>
#include <elliptics/session.hpp>

class cocaine_logger_t : public cocaine::framework::logger_t {
public:
	cocaine_logger_t(const ioremap::swarm::logger &logger)
		: m_logger(logger)
	{}

	void emit(cocaine::logging::priorities priority, const std::string& message) {
		int lvl = level(priority);
		m_logger.log(lvl, "%s", message.c_str());
	}

	cocaine::logging::priorities verbosity() const {
		using namespace cocaine::logging;
		switch(m_logger.get_level()) {
		case ioremap::swarm::LOG_DATA:
			return priorities::ignore;
		case ioremap::swarm::LOG_ERROR:
			return priorities::error;
		case ioremap::swarm::LOG_INFO:
			return priorities::info;
		case ioremap::swarm::LOG_NOTICE:
			return priorities::info;
		default:
			return priorities::debug;
		}
	}

private:
	int level(cocaine::logging::priorities priority) {
		using namespace cocaine::logging;
		switch(priority) {
		case priorities::ignore:
			return ioremap::swarm::LOG_DATA;
		case priorities::error:
			return ioremap::swarm::LOG_ERROR;
		case priorities::warning:
			return ioremap::swarm::LOG_ERROR;
		case priorities::info:
			return ioremap::swarm::LOG_INFO;
		default:
			return ioremap::swarm::LOG_DEBUG;
		}
	}

	ioremap::swarm::logger m_logger;
};

class swarm_logger_interface : public ioremap::elliptics::logger_interface {
public:
	swarm_logger_interface(const ioremap::swarm::logger &logger)
		: m_logger(logger)
	{
	}

	~swarm_logger_interface()
	{
	}

	virtual void log(const int level, const char *msg)
	{
		m_logger.log(level, "%s", msg);
	}

private:
	ioremap::swarm::logger m_logger;
};

class elliptics_logger_t : public ioremap::elliptics::logger {
public:
	elliptics_logger_t(const ioremap::swarm::logger &logger) : ioremap::elliptics::logger(new swarm_logger_interface(logger))
	{
	}
};

#endif /* SRC__LOGGERS_HPP */
