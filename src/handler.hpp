#ifndef MDS_PROXY__SRC__HANDLER__HPP
#define MDS_PROXY__SRC__HANDLER__HPP

#include "error.hpp"
#include "handystats.hpp"
#include "proxy.hpp"

#include <thevoid/http_response.hpp>

#include <folly/futures/Future.h>

#include <memory>

namespace elliptics {

template <template <typename> class BaseStream>
class handler
	: public BaseStream<proxy>
	, public std::enable_shared_from_this<handler<BaseStream>> {
public:
	typedef BaseStream<proxy> stream_type;
	typedef handler<BaseStream> self_type;

	handler(std::string handler_name_)
		: handler_name(std::move(handler_name_))
		, m_headers_were_sent(false)
	{
	}

	// TODO: this method is an ugly hack
	void
	start_request() {
		MDS_REQUEST_START(handler_name, instance_id());
	}

	folly::Future<folly::Unit>
	send_headers(ioremap::thevoid::http_response http_response) {
		auto promise_ptr = std::make_shared<folly::Promise<folly::Unit>>();
		auto future_result = promise_ptr->getFuture();
		auto self = self_type::shared_from_this();

		auto next = [this, self, promise_ptr](const boost::system::error_code &error_code) {
			if (!error_code) {
				promise_ptr->setValue();
			} else {
				promise_ptr->setException(thevoid_error{error_code});
			}
		};

		MDS_REQUEST_SEND_HEADERS(handler_name, http_response.code(), instance_id());
		stream_type::send_headers(std::move(http_response), std::move(next));
		m_headers_were_sent = true;

		return future_result;
	}

	folly::Future<folly::Unit>
	send_headers(int code, ioremap::swarm::http_headers http_headers) {
		return send_headers(make_http_response(code, std::move(http_headers)));
	}

	folly::Future<folly::Unit>
	send_data(std::string data) {
		auto promise_ptr = std::make_shared<folly::Promise<folly::Unit>>();
		auto future_result = promise_ptr->getFuture();
		auto self = self_type::shared_from_this();

		auto next = [this, self, promise_ptr](const boost::system::error_code &error_code) {
			if (!error_code) {
				promise_ptr->setValue();
			} else {
				promise_ptr->setException(thevoid_error{error_code});
			}
		};

		stream_type::send_data(std::move(data), std::move(next));

		return future_result;
	}

	folly::Future<folly::Unit>
	send_data(std::unique_ptr<folly::IOBuf> iobuf) {
		return send_data(iobuf->moveToFbString().toStdString());
	}

	void
	close(const boost::system::error_code &err) {
		MDS_REQUEST_CLOSE(handler_name, instance_id());
		stream_type::close(err);
	}

	void
	close() {
		close(boost::system::error_code());
	}

	void
	send_reply(ioremap::thevoid::http_response http_response) {
		// The result of sending headers is lost here.
		send_headers(std::move(http_response));
		close();
	}

	void
	send_reply(int code, ioremap::swarm::http_headers http_headers) {
		send_reply(make_http_response(code, std::move(http_headers)));
	}

	void
	send_reply(int code) {
		ioremap::swarm::http_headers http_headers;
		http_headers.set_content_length(0);
		send_reply(code, std::move(http_headers));
	}

	bool
	headers_were_sent() {
		return m_headers_were_sent;
	}

private:
	static
	ioremap::thevoid::http_response
	make_http_response(int code, ioremap::swarm::http_headers http_headers) {
		ioremap::thevoid::http_response http_response;

		http_response.set_code(code);
		http_response.set_headers(std::move(http_headers));

		return http_response;
	}

	uint64_t
	instance_id() {
		return reinterpret_cast<uint64_t>(self_type::reply().get());
	}

	std::string handler_name;
	bool m_headers_were_sent;
};

} // namespace elliptics

#endif /* MDS_PROXY__SRC__HANDLER__HPP */

