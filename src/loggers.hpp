#ifndef SRC__LOGGERS_HPP
#define SRC__LOGGERS_HPP

#include <swarm/logger.hpp>
#include <cocaine/framework/logging.hpp>
#include <elliptics/session.hpp>

#define MDS_LOG_ERROR(log, ...) BH_LOG((log), SWARM_LOG_ERROR, __VA_ARGS__)
#define MDS_LOG_WARNING(log, ...) BH_LOG((log), SWARM_LOG_WARNING, __VA_ARGS__)
#define MDS_LOG_INFO(log, ...) BH_LOG((log), SWARM_LOG_INFO, __VA_ARGS__)
#define MDS_LOG_NOTICE(log, ...) BH_LOG((log), SWARM_LOG_NOTICE, __VA_ARGS__)
#define MDS_LOG_DEBUG(log, ...) BH_LOG((log), SWARM_LOG_DEBUG, __VA_ARGS__)

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
