#include "cdn_cache.hpp"

#include <yandex/threads/boost_threaded.hpp>
#include <yandex/http/curl_wrapper.hpp>

#include <fstream>
#include <iterator>
#include <sstream>

namespace elliptics {

cdn_cache_t::cdn_cache_t(ioremap::swarm::logger bh_logger_, config_t config_)
	: bh_logger(std::move(bh_logger_))
	, config(std::move(config_))
	, work_is_done(false)
{
	deserialize();

	if (!config.url.empty()) {
		MDS_LOG_INFO("starting background thread");
		background_updater = std::thread(std::bind(&cdn_cache_t::background_loop, this));
	}
}

cdn_cache_t::~cdn_cache_t() {
	if (background_updater.joinable()) {
		MDS_LOG_INFO("stopping cdn cache updater");
		{
			std::lock_guard<std::mutex> lock(background_updater_mutex);
			(void) lock;

			work_is_done = true;
			background_updater_cv.notify_one();
		}

		MDS_LOG_INFO("joining background thread");
		background_updater.join();
	}
}

bool
cdn_cache_t::check_host(const std::string &host) {
	auto local_cache = copy_cache();

	auto it = local_cache->find(host);

	bool host_was_found = true;

	if (it == local_cache->end()) {
		host_was_found = false;
	}

	MDS_LOG_INFO("regional host \"%s\" %s in the cdn cache", host.c_str()
			, (host_was_found ? "was found" : "was not found"));

	return host_was_found;
}

ioremap::swarm::logger &
cdn_cache_t::logger() {
	return bh_logger;
}

void
cdn_cache_t::serialize() const {
	if (config.cache_path.empty()) {
		return;
	}

	auto local_cache = copy_cache();

	std::ostringstream oss;

	for (auto it = local_cache->begin(), end = local_cache->end(); it != end; ++it) {
		oss << *it << std::endl;
	}

	auto raw_data = oss.str();
	std::ofstream output(config.cache_path.c_str());
	std::copy(raw_data.begin(), raw_data.end(), std::ostreambuf_iterator<char>(output));
}

void
cdn_cache_t::deserialize() {
	if (config.cache_path.empty()) {
		return;
	}

	std::string raw_data;

	{
		typedef std::istreambuf_iterator<char> input_iterator_t;
		std::ifstream input(config.cache_path.c_str());
		raw_data.assign(input_iterator_t(input), input_iterator_t());
	}

	set_cache(parse_cache(raw_data));
}

cdn_cache_t::cache_ptr_t
cdn_cache_t::parse_cache(const std::string &raw_data) const {
	auto local_cache = std::make_shared<cache_ptr_t::element_type>();
	std::string::size_type pos = 0;

	while (pos != std::string::npos) {
		auto new_pos = raw_data.find('\n', pos);
		auto size = new_pos == std::string::npos ? std::string::npos : new_pos - pos;

		{
			auto row = raw_data.substr(pos, size);

			if (!row.empty()) {
				local_cache->insert(std::move(row));
			}
		}

		pos = new_pos == std::string::npos ? std::string::npos : new_pos + 1;
	}

	return local_cache;
}

cdn_cache_t::cache_ptr_t
cdn_cache_t::copy_cache() const {
	std::lock_guard<std::mutex> lock(cache_mutex);
	(void) lock;

	return cache_ptr;
}

void
cdn_cache_t::set_cache(cache_ptr_t cache_ptr_) {
	{
		std::lock_guard<std::mutex> lock(cache_mutex);
		(void) lock;
		cache_ptr.swap(cache_ptr_);
	}
}

void
cdn_cache_t::update_cache() {
	MDS_LOG_INFO("downloading new data");

	std::stringstream res;
	std::string raw_data;

	try {
		yandex::common::curl_wrapper<yandex::common::boost_threading_traits> curl(config.url);
		curl.header("Expect", "");
		curl.timeout(config.timeout);

		auto status = curl.perform(res);
		res.str().swap(raw_data);

		if (status != 200) {
			MDS_LOG_ERROR("cannot download data: status=%d", static_cast<int>(status));
			MDS_LOG_DEBUG("cannot download data: body=\"%s\"", raw_data.c_str());
			return;
		}
	} catch (const std::exception &ex) {
		return;
	}

	set_cache(parse_cache(raw_data));
	serialize();
}

void
cdn_cache_t::background_loop() {
	std::unique_lock<std::mutex> lock(background_updater_mutex);
#if __GNUC__ == 4 && __GNUC_MINOR__ >= 6
	auto no_timeout = std::cv_status::no_timeout;
	auto timeout = std::cv_status::timeout;
#else
	bool no_timeout = true;
	bool timeout = false;
#endif

	MDS_LOG_INFO("background loop update period is %ds, source url is %s"
			, config.update_period, config.url.c_str());

	do {
		MDS_LOG_INFO("backgroung loop begin");
		update_cache();
		MDS_LOG_INFO("backgroung loop end");

		auto tm = timeout;

		do {
			tm = background_updater_cv.wait_for(lock, std::chrono::seconds(config.update_period));
		} while (tm == no_timeout && work_is_done == false);
	} while (work_is_done == false);
}

} // namespace elliptics

