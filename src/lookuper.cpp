#include "lookuper.hpp"
#include "loggers.hpp"

elliptics::parallel_lookuper_t::parallel_lookuper_t(
		ioremap::swarm::logger bh_logger_
		, ioremap::elliptics::session session_
		, std::string key_
		)
	: bh_logger(std::move(bh_logger_))
	, session(session_.clone())
	, key(std::move(key_))
	, groups_to_handle(0)
{
}

void
elliptics::parallel_lookuper_t::start() {
	const auto &groups = session.get_groups();
	groups_to_handle = groups.size();

	auto self = shared_from_this();
	auto callback = [this, self] (
			const ioremap::elliptics::sync_lookup_result &entries
			, const ioremap::elliptics::error_info &error_info) {
		on_lookup(entries, error_info);
	};

	for (auto it = groups.begin(), end = groups.end(); it != end; ++it) {
		auto group_session = session.clone();
		group_session.set_filter(ioremap::elliptics::filters::all_with_ack);
		group_session.set_groups({*it});
		auto future = group_session.lookup(key);
		future.connect(callback);
	}
}

ioremap::elliptics::async_lookup_result
elliptics::parallel_lookuper_t::next_lookup_result() {
	lock_guard_t lock_guard(results_mutex);

	ioremap::elliptics::async_lookup_result future(session);
	ioremap::elliptics::async_lookup_result::handler promise(future);

	if (!results.empty()) {
		auto result = std::move(results.front());
		results.pop_front();

		lock_guard.unlock();
		process_promise(promise, result);
		return future;
	}

	if (groups_to_handle - promises.size()) {
		promises.emplace_back(std::move(promise));
		return future;
	}

	lock_guard.unlock();
	process_promise(promise);
	return future;
}

size_t
elliptics::parallel_lookuper_t::total_size() const {
	return session.get_groups().size();
}

size_t
elliptics::parallel_lookuper_t::results_left() const {
	lock_guard_t lock_guard(results_mutex);
	return groups_to_handle + results.size();
}

ioremap::swarm::logger &
elliptics::parallel_lookuper_t::logger() {
	return bh_logger;
}

void
elliptics::parallel_lookuper_t::on_lookup(const ioremap::elliptics::sync_lookup_result &entries
		, const ioremap::elliptics::error_info &error_info) {
	lock_guard_t lock_guard(results_mutex);

	groups_to_handle -= 1;
	result_t result{entries, error_info};

	if (!promises.empty()) {
		auto promise = std::move(promises.front());
		promises.pop_front();

		lock_guard.unlock();
		process_promise(promise, result);
		return;
	}

	results.emplace_back(std::move(result));
}

void
elliptics::parallel_lookuper_t::process_promise(
		ioremap::elliptics::async_lookup_result::handler &promise
		, const result_t &result) {
	auto &entries = result.entries;

	promise.set_total(entries.size());

	for (auto it = entries.begin(), end = entries.end(); it != end; ++it) {
		promise.process(*it);
	}

	promise.complete(result.error_info);
}

void
elliptics::parallel_lookuper_t::process_promise(
		ioremap::elliptics::async_lookup_result::handler &promise) {
	promise.complete(ioremap::elliptics::error_info(EPIPE, "There is no enough groups"));
}

elliptics::parallel_lookuper_ptr_t
elliptics::make_parallel_lookuper(
		ioremap::swarm::logger bh_logger
		, ioremap::elliptics::session session
		, std::string key
		) {
	auto parallel_lookuper = std::make_shared<parallel_lookuper_t>(std::move(bh_logger)
			, std::move(session), std::move(key));
	parallel_lookuper->start();
	return parallel_lookuper;
}

