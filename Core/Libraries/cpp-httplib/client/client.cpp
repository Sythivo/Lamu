#include "client.h"

using namespace httplib;

namespace HTTP
{
    template <class Rep, class Period>
    void ClientImpl::set_connection_timeout(
        const std::chrono::duration<Rep, Period>& duration) {
        detail::duration_to_sec_and_usec(duration, [&](time_t sec, time_t usec) {
            set_connection_timeout(sec, usec);
            });
    }

    template <class Rep, class Period>
    void ClientImpl::set_read_timeout(
        const std::chrono::duration<Rep, Period>& duration) {
        detail::duration_to_sec_and_usec(
            duration, [&](time_t sec, time_t usec) { set_read_timeout(sec, usec); });
    }

    template <class Rep, class Period>
    void ClientImpl::set_write_timeout(
        const std::chrono::duration<Rep, Period>& duration) {
        detail::duration_to_sec_and_usec(
            duration, [&](time_t sec, time_t usec) { set_write_timeout(sec, usec); });
    }

    template <class Rep, class Period>
    void Client::set_connection_timeout(
        const std::chrono::duration<Rep, Period>& duration) {
        cli_->set_connection_timeout(duration);
    }

    template <class Rep, class Period>
    void
        Client::set_read_timeout(const std::chrono::duration<Rep, Period>& duration) {
        cli_->set_read_timeout(duration);
    }

    template <class Rep, class Period>
    void
        Client::set_write_timeout(const std::chrono::duration<Rep, Period>& duration) {
        cli_->set_write_timeout(duration);
    }
    ClientImpl::ClientImpl(const std::string& host)
        : ClientImpl(host, 80, std::string(), std::string()) {}

    ClientImpl::ClientImpl(const std::string& host, int port)
        : ClientImpl(host, port, std::string(), std::string()) {}

    ClientImpl::ClientImpl(const std::string& host, int port,
        const std::string& client_cert_path,
        const std::string& client_key_path)
        : host_(host), port_(port),
        host_and_port_(adjust_host_string(host) + ":" + std::to_string(port)),
        client_cert_path_(client_cert_path), client_key_path_(client_key_path) {}

    ClientImpl::~ClientImpl() {
        std::lock_guard<std::mutex> guard(socket_mutex_);
        shutdown_socket(socket_);
        close_socket(socket_);
    }

    bool ClientImpl::is_valid() const { return true; }

    void ClientImpl::copy_settings(const ClientImpl& rhs) {
        client_cert_path_ = rhs.client_cert_path_;
        client_key_path_ = rhs.client_key_path_;
        connection_timeout_sec_ = rhs.connection_timeout_sec_;
        read_timeout_sec_ = rhs.read_timeout_sec_;
        read_timeout_usec_ = rhs.read_timeout_usec_;
        write_timeout_sec_ = rhs.write_timeout_sec_;
        write_timeout_usec_ = rhs.write_timeout_usec_;
        basic_auth_username_ = rhs.basic_auth_username_;
        basic_auth_password_ = rhs.basic_auth_password_;
        bearer_token_auth_token_ = rhs.bearer_token_auth_token_;
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        digest_auth_username_ = rhs.digest_auth_username_;
        digest_auth_password_ = rhs.digest_auth_password_;
#endif
        keep_alive_ = rhs.keep_alive_;
        follow_location_ = rhs.follow_location_;
        url_encode_ = rhs.url_encode_;
        address_family_ = rhs.address_family_;
        tcp_nodelay_ = rhs.tcp_nodelay_;
        socket_options_ = rhs.socket_options_;
        compress_ = rhs.compress_;
        decompress_ = rhs.decompress_;
        interface_ = rhs.interface_;
        proxy_host_ = rhs.proxy_host_;
        proxy_port_ = rhs.proxy_port_;
        proxy_basic_auth_username_ = rhs.proxy_basic_auth_username_;
        proxy_basic_auth_password_ = rhs.proxy_basic_auth_password_;
        proxy_bearer_token_auth_token_ = rhs.proxy_bearer_token_auth_token_;
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        proxy_digest_auth_username_ = rhs.proxy_digest_auth_username_;
        proxy_digest_auth_password_ = rhs.proxy_digest_auth_password_;
#endif
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        ca_cert_file_path_ = rhs.ca_cert_file_path_;
        ca_cert_dir_path_ = rhs.ca_cert_dir_path_;
        ca_cert_store_ = rhs.ca_cert_store_;
#endif
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        server_certificate_verification_ = rhs.server_certificate_verification_;
#endif
        logger_ = rhs.logger_;
    }

    socket_t ClientImpl::create_client_socket(Error& error) const {
        if (!proxy_host_.empty() && proxy_port_ != -1) {
            return detail::create_client_socket(
                proxy_host_, std::string(), proxy_port_, address_family_, tcp_nodelay_,
                socket_options_, connection_timeout_sec_, connection_timeout_usec_,
                read_timeout_sec_, read_timeout_usec_, write_timeout_sec_,
                write_timeout_usec_, interface_, error);
        }

        // Check is custom IP specified for host_
        std::string ip;
        auto it = addr_map_.find(host_);
        if (it != addr_map_.end()) ip = it->second;

        return detail::create_client_socket(
            host_, ip, port_, address_family_, tcp_nodelay_, socket_options_,
            connection_timeout_sec_, connection_timeout_usec_, read_timeout_sec_,
            read_timeout_usec_, write_timeout_sec_, write_timeout_usec_, interface_,
            error);
    }

    bool ClientImpl::create_and_connect_socket(Socket& socket,
        Error& error) {
        auto sock = create_client_socket(error);
        if (sock == INVALID_SOCKET) { return false; }
        socket.sock = sock;
        return true;
    }

    void ClientImpl::shutdown_ssl(Socket& /*socket*/,
        bool /*shutdown_gracefully*/) {
        // If there are any requests in flight from threads other than us, then it's
        // a thread-unsafe race because individual ssl* objects are not thread-safe.
        assert(socket_requests_in_flight_ == 0 ||
            socket_requests_are_from_thread_ == std::this_thread::get_id());
    }

    void ClientImpl::shutdown_socket(Socket& socket) {
        if (socket.sock == INVALID_SOCKET) { return; }
        detail::shutdown_socket(socket.sock);
    }

    void ClientImpl::close_socket(Socket& socket) {
        // If there are requests in flight in another thread, usually closing
        // the socket will be fine and they will simply receive an error when
        // using the closed socket, but it is still a bug since rarely the OS
        // may reassign the socket id to be used for a new socket, and then
        // suddenly they will be operating on a live socket that is different
        // than the one they intended!
        assert(socket_requests_in_flight_ == 0 ||
            socket_requests_are_from_thread_ == std::this_thread::get_id());

        // It is also a bug if this happens while SSL is still active
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        assert(socket.ssl == nullptr);
#endif
        if (socket.sock == INVALID_SOCKET) { return; }
        detail::close_socket(socket.sock);
        socket.sock = INVALID_SOCKET;
    }

    bool ClientImpl::read_response_line(Stream& strm, const Request& req,
        Response& res) {
        std::array<char, 2048> buf{};

        detail::stream_line_reader line_reader(strm, buf.data(), buf.size());

        if (!line_reader.getline()) { return false; }

#ifdef CPPHTTPLIB_ALLOW_LF_AS_LINE_TERMINATOR
        const static std::regex re("(HTTP/1\\.[01]) (\\d{3})(?: (.*?))?\r\n");
#else
        const static std::regex re("(HTTP/1\\.[01]) (\\d{3})(?: (.*?))?\r?\n");
#endif

        std::cmatch m;
        if (!std::regex_match(line_reader.ptr(), m, re)) {
            return req.method == "CONNECT";
        }
        res.version = std::string(m[1]);
        res.status = std::stoi(std::string(m[2]));
        res.reason = std::string(m[3]);

        // Ignore '100 Continue'
        while (res.status == 100) {
            if (!line_reader.getline()) { return false; } // CRLF
            if (!line_reader.getline()) { return false; } // next response line

            if (!std::regex_match(line_reader.ptr(), m, re)) { return false; }
            res.version = std::string(m[1]);
            res.status = std::stoi(std::string(m[2]));
            res.reason = std::string(m[3]);
        }

        return true;
    }

    bool ClientImpl::send(Request& req, Response& res, Error& error) {
        std::lock_guard<std::recursive_mutex> request_mutex_guard(request_mutex_);

        {
            std::lock_guard<std::mutex> guard(socket_mutex_);

            // Set this to false immediately - if it ever gets set to true by the end of
            // the request, we know another thread instructed us to close the socket.
            socket_should_be_closed_when_request_is_done_ = false;

            auto is_alive = false;
            if (socket_.is_open()) {
                is_alive = detail::is_socket_alive(socket_.sock);
                if (!is_alive) {
                    // Attempt to avoid sigpipe by shutting down nongracefully if it seems
                    // like the other side has already closed the connection Also, there
                    // cannot be any requests in flight from other threads since we locked
                    // request_mutex_, so safe to close everything immediately
                    const bool shutdown_gracefully = false;
                    shutdown_ssl(socket_, shutdown_gracefully);
                    shutdown_socket(socket_);
                    close_socket(socket_);
                }
            }

            if (!is_alive) {
                if (!create_and_connect_socket(socket_, error)) { return false; }

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
                // TODO: refactoring
                if (is_ssl()) {
                    auto& scli = static_cast<SSLClient&>(*this);
                    if (!proxy_host_.empty() && proxy_port_ != -1) {
                        bool success = false;
                        if (!scli.connect_with_proxy(socket_, res, success, error)) {
                            return success;
                        }
                    }

                    if (!scli.initialize_ssl(socket_, error)) { return false; }
                }
#endif
            }

            // Mark the current socket as being in use so that it cannot be closed by
            // anyone else while this request is ongoing, even though we will be
            // releasing the mutex.
            if (socket_requests_in_flight_ > 1) {
                assert(socket_requests_are_from_thread_ == std::this_thread::get_id());
            }
            socket_requests_in_flight_ += 1;
            socket_requests_are_from_thread_ = std::this_thread::get_id();
        }

        for (const auto& header : default_headers_) {
            if (req.headers.find(header.first) == req.headers.end()) {
                req.headers.insert(header);
            }
        }

        auto close_connection = !keep_alive_;
        auto ret = process_socket(socket_, [&](Stream& strm) {
            return handle_request(strm, req, res, close_connection, error);
            });

        // Briefly lock mutex in order to mark that a request is no longer ongoing
        {
            std::lock_guard<std::mutex> guard(socket_mutex_);
            socket_requests_in_flight_ -= 1;
            if (socket_requests_in_flight_ <= 0) {
                assert(socket_requests_in_flight_ == 0);
                socket_requests_are_from_thread_ = std::thread::id();
            }

            if (socket_should_be_closed_when_request_is_done_ || close_connection ||
                !ret) {
                shutdown_ssl(socket_, true);
                shutdown_socket(socket_);
                close_socket(socket_);
            }
        }

        if (!ret) {
            if (error == Error::Success) { error = Error::Unknown; }
        }

        return ret;
    }

    Result ClientImpl::send(const Request& req) {
        auto req2 = req;
        return send_(std::move(req2));
    }

    Result ClientImpl::send_(Request&& req) {
        auto res = detail::make_unique<Response>();
        auto error = Error::Success;
        auto ret = send(req, *res, error);
        return Result{ ret ? std::move(res) : nullptr, error, std::move(req.headers) };
    }

    bool ClientImpl::handle_request(Stream& strm, Request& req,
        Response& res, bool close_connection,
        Error& error) {
        if (req.path.empty()) {
            error = Error::Connection;
            return false;
        }

        auto req_save = req;

        bool ret;

        if (!is_ssl() && !proxy_host_.empty() && proxy_port_ != -1) {
            auto req2 = req;
            req2.path = "http://" + host_and_port_ + req.path;
            ret = process_request(strm, req2, res, close_connection, error);
            req = req2;
            req.path = req_save.path;
        }
        else {
            ret = process_request(strm, req, res, close_connection, error);
        }

        if (!ret) { return false; }

        if (300 < res.status && res.status < 400 && follow_location_) {
            req = req_save;
            ret = redirect(req, res, error);
        }

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        if ((res.status == 401 || res.status == 407) &&
            req.authorization_count_ < 5) {
            auto is_proxy = res.status == 407;
            const auto& username =
                is_proxy ? proxy_digest_auth_username_ : digest_auth_username_;
            const auto& password =
                is_proxy ? proxy_digest_auth_password_ : digest_auth_password_;

            if (!username.empty() && !password.empty()) {
                std::map<std::string, std::string> auth;
                if (detail::parse_www_authenticate(res, auth, is_proxy)) {
                    Request new_req = req;
                    new_req.authorization_count_ += 1;
                    new_req.headers.erase(is_proxy ? "Proxy-Authorization"
                        : "Authorization");
                    new_req.headers.insert(detail::make_digest_authentication_header(
                        req, auth, new_req.authorization_count_, detail::random_string(10),
                        username, password, is_proxy));

                    Response new_res;

                    ret = send(new_req, new_res, error);
                    if (ret) { res = new_res; }
                }
            }
        }
#endif

        return ret;
    }

    bool ClientImpl::redirect(Request& req, Response& res, Error& error) {
        if (req.redirect_count_ == 0) {
            error = Error::ExceedRedirectCount;
            return false;
        }

        auto location = detail::decode_url(res.get_header_value("location"), true);
        if (location.empty()) { return false; }

        const static std::regex re(
            R"((?:(https?):)?(?://(?:\[([\d:]+)\]|([^:/?#]+))(?::(\d+))?)?([^?#]*(?:\?[^#]*)?)(?:#.*)?)");

        std::smatch m;
        if (!std::regex_match(location, m, re)) { return false; }

        auto scheme = is_ssl() ? "https" : "http";

        auto next_scheme = m[1].str();
        auto next_host = m[2].str();
        if (next_host.empty()) { next_host = m[3].str(); }
        auto port_str = m[4].str();
        auto next_path = m[5].str();

        auto next_port = port_;
        if (!port_str.empty()) {
            next_port = std::stoi(port_str);
        }
        else if (!next_scheme.empty()) {
            next_port = next_scheme == "https" ? 443 : 80;
        }

        if (next_scheme.empty()) { next_scheme = scheme; }
        if (next_host.empty()) { next_host = host_; }
        if (next_path.empty()) { next_path = "/"; }

        if (next_scheme == scheme && next_host == host_ && next_port == port_) {
            return detail::redirect(*this, req, res, next_path, location, error);
        }
        else {
            if (next_scheme == "https") {
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
                SSLClient cli(next_host.c_str(), next_port);
                cli.copy_settings(*this);
                if (ca_cert_store_) { cli.set_ca_cert_store(ca_cert_store_); }
                return detail::redirect(cli, req, res, next_path, location, error);
#else
                return false;
#endif
            }
            else {
                ClientImpl cli(next_host.c_str(), next_port);
                cli.copy_settings(*this);
                return detail::redirect(cli, req, res, next_path, location, error);
            }
        }
    }

    bool ClientImpl::write_content_with_provider(Stream& strm,
        const Request& req,
        Error& error) {
        auto is_shutting_down = []() { return false; };

        if (req.is_chunked_content_provider_) {
            // TODO: Brotli suport
            std::unique_ptr<detail::compressor> compressor;
#ifdef CPPHTTPLIB_ZLIB_SUPPORT
            if (compress_) {
                compressor = detail::make_unique<detail::gzip_compressor>();
            }
            else
#endif
            {
                compressor = detail::make_unique<detail::nocompressor>();
            }

            return detail::write_content_chunked(strm, req.content_provider_,
                is_shutting_down, *compressor, error);
        }
        else {
            return detail::write_content(strm, req.content_provider_, 0,
                req.content_length_, is_shutting_down, error);
        }
    } // namespace httplib

    bool ClientImpl::write_request(Stream& strm, Request& req, bool close_connection, Error& error) {
        // Prepare additional headers
        if (close_connection) {
            if (!req.has_header("Connection")) {
                req.headers.emplace("Connection", "close");
            }
        }

        if (!req.has_header("Host")) {
            if (is_ssl()) {
                if (port_ == 443) {
                    req.headers.emplace("Host", host_);
                }
                else {
                    req.headers.emplace("Host", host_and_port_);
                }
            }
            else {
                if (port_ == 80) {
                    req.headers.emplace("Host", host_);
                }
                else {
                    req.headers.emplace("Host", host_and_port_);
                }
            }
        }

        if (!req.has_header("Accept")) { req.headers.emplace("Accept", "*/*"); }

        if (!req.has_header("User-Agent")) {
            req.headers.emplace("User-Agent", std::string("luma/") + VERSION);
        }

        if (req.body.empty()) {
            if (req.content_provider_) {
                if (!req.is_chunked_content_provider_) {
                    if (!req.has_header("Content-Length")) {
                        auto length = std::to_string(req.content_length_);
                        req.headers.emplace("Content-Length", length);
                    }
                }
            }
            else {
                if (req.method == "POST" || req.method == "PUT" ||
                    req.method == "PATCH") {
                    req.headers.emplace("Content-Length", "0");
                }
            }
        }
        else {
            if (!req.has_header("Content-Type")) {
                req.headers.emplace("Content-Type", "text/plain");
            }

            if (!req.has_header("Content-Length")) {
                auto length = std::to_string(req.body.size());
                req.headers.emplace("Content-Length", length);
            }
        }

        if (!basic_auth_password_.empty() || !basic_auth_username_.empty()) {
            if (!req.has_header("Authorization")) {
                req.headers.insert(make_basic_authentication_header(
                    basic_auth_username_, basic_auth_password_, false));
            }
        }

        if (!proxy_basic_auth_username_.empty() &&
            !proxy_basic_auth_password_.empty()) {
            if (!req.has_header("Proxy-Authorization")) {
                req.headers.insert(make_basic_authentication_header(
                    proxy_basic_auth_username_, proxy_basic_auth_password_, true));
            }
        }

        if (!bearer_token_auth_token_.empty()) {
            if (!req.has_header("Authorization")) {
                req.headers.insert(make_bearer_token_authentication_header(
                    bearer_token_auth_token_, false));
            }
        }

        if (!proxy_bearer_token_auth_token_.empty()) {
            if (!req.has_header("Proxy-Authorization")) {
                req.headers.insert(make_bearer_token_authentication_header(
                    proxy_bearer_token_auth_token_, true));
            }
        }

        // Request line and headers
        {
            detail::BufferStream bstrm;

            const auto& path = url_encode_ ? detail::encode_url(req.path) : req.path;
            bstrm.write_format("%s %s HTTP/1.1\r\n", req.method.c_str(), path.c_str());

            detail::write_headers(bstrm, req.headers);

            // Flush buffer
            auto& data = bstrm.get_buffer();
            if (!detail::write_data(strm, data.data(), data.size())) {
                error = Error::Write;
                return false;
            }
        }

        // Body
        if (req.body.empty()) {
            return write_content_with_provider(strm, req, error);
        }

        if (!detail::write_data(strm, req.body.data(), req.body.size())) {
            error = Error::Write;
            return false;
        }

        return true;
    }

    std::unique_ptr<Response> ClientImpl::send_with_content_provider(
        Request& req, const char* body, size_t content_length,
        ContentProvider content_provider,
        ContentProviderWithoutLength content_provider_without_length,
        const std::string& content_type, Error& error) {
        if (!content_type.empty()) {
            req.headers.emplace("Content-Type", content_type);
        }

#ifdef CPPHTTPLIB_ZLIB_SUPPORT
        if (compress_) { req.headers.emplace("Content-Encoding", "gzip"); }
#endif

#ifdef CPPHTTPLIB_ZLIB_SUPPORT
        if (compress_ && !content_provider_without_length) {
            // TODO: Brotli support
            detail::gzip_compressor compressor;

            if (content_provider) {
                auto ok = true;
                size_t offset = 0;
                DataSink data_sink;

                data_sink.write = [&](const char* data, size_t data_len) -> bool {
                    if (ok) {
                        auto last = offset + data_len == content_length;

                        auto ret = compressor.compress(
                            data, data_len, last,
                            [&](const char* compressed_data, size_t compressed_data_len) {
                                req.body.append(compressed_data, compressed_data_len);
                                return true;
                            });

                        if (ret) {
                            offset += data_len;
                        }
                        else {
                            ok = false;
                        }
                    }
                    return ok;
                };

                data_sink.is_writable = [&](void) { return ok && true; };

                while (ok && offset < content_length) {
                    if (!content_provider(offset, content_length - offset, data_sink)) {
                        error = Error::Canceled;
                        return nullptr;
                    }
                }
            }
            else {
                if (!compressor.compress(body, content_length, true,
                    [&](const char* data, size_t data_len) {
                        req.body.append(data, data_len);
                        return true;
                    })) {
                    error = Error::Compression;
                    return nullptr;
                }
            }
        }
        else
#endif
        {
            if (content_provider) {
                req.content_length_ = content_length;
                req.content_provider_ = std::move(content_provider);
                req.is_chunked_content_provider_ = false;
            }
            else if (content_provider_without_length) {
                req.content_length_ = 0;
                req.content_provider_ = detail::ContentProviderAdapter(
                    std::move(content_provider_without_length));
                req.is_chunked_content_provider_ = true;
                req.headers.emplace("Transfer-Encoding", "chunked");
            }
            else {
                req.body.assign(body, content_length);
                ;
            }
        }

        auto res = detail::make_unique<Response>();
        return send(req, *res, error) ? std::move(res) : nullptr;
    }

    Result ClientImpl::send_with_content_provider(
        const std::string& method, const std::string& path, const Headers& headers,
        const char* body, size_t content_length, ContentProvider content_provider,
        ContentProviderWithoutLength content_provider_without_length,
        const std::string& content_type) {
        Request req;
        req.method = method;
        req.headers = headers;
        req.path = path;

        auto error = Error::Success;

        auto res = send_with_content_provider(
            req, body, content_length, std::move(content_provider),
            std::move(content_provider_without_length), content_type, error);

        return Result{ std::move(res), error, std::move(req.headers) };
    }

    std::string
        ClientImpl::adjust_host_string(const std::string& host) const {
        if (host.find(':') != std::string::npos) { return "[" + host + "]"; }
        return host;
    }

    bool ClientImpl::process_request(Stream& strm, Request& req,
        Response& res, bool close_connection,
        Error& error) {
        // Send request
        if (!write_request(strm, req, close_connection, error)) { return false; }

        // Receive response and headers
        if (!read_response_line(strm, req, res) ||
            !detail::read_headers(strm, res.headers)) {
            error = Error::Read;
            return false;
        }

        // Body
        if ((res.status != 204) && req.method != "HEAD" && req.method != "CONNECT") {
            auto redirect = 300 < res.status && res.status < 400 && follow_location_;

            if (req.response_handler && !redirect) {
                if (!req.response_handler(res)) {
                    error = Error::Canceled;
                    return false;
                }
            }

            auto out =
                req.content_receiver
                ? static_cast<ContentReceiverWithProgress>(
                    [&](const char* buf, size_t n, uint64_t off, uint64_t len) {
                        if (redirect) { return true; }
                        auto ret = req.content_receiver(buf, n, off, len);
                        if (!ret) { error = Error::Canceled; }
                        return ret;
                    })
                : static_cast<ContentReceiverWithProgress>(
                    [&](const char* buf, size_t n, uint64_t /*off*/,
                        uint64_t /*len*/) {
                            if (res.body.size() + n > res.body.max_size()) {
                                return false;
                            }
                            res.body.append(buf, n);
                            return true;
                    });

                    auto progress = [&](uint64_t current, uint64_t total) {
                        if (!req.progress || redirect) { return true; }
                        auto ret = req.progress(current, total);
                        if (!ret) { error = Error::Canceled; }
                        return ret;
                    };

                    int dummy_status;
                    if (!detail::read_content(strm, res, (std::numeric_limits<size_t>::max)(),
                        dummy_status, std::move(progress), std::move(out),
                        decompress_)) {
                        if (error != Error::Canceled) { error = Error::Read; }
                        return false;
                    }
        }

        if (res.get_header_value("Connection") == "close" ||
            (res.version == "HTTP/1.0" && res.reason != "Connection established")) {
            // TODO this requires a not-entirely-obvious chain of calls to be correct
            // for this to be safe. Maybe a code refactor (such as moving this out to
            // the send function and getting rid of the recursiveness of the mutex)
            // could make this more obvious.

            // This is safe to call because process_request is only called by
            // handle_request which is only called by send, which locks the request
            // mutex during the process. It would be a bug to call it from a different
            // thread since it's a thread-safety issue to do these things to the socket
            // if another thread is using the socket.
            std::lock_guard<std::mutex> guard(socket_mutex_);
            shutdown_ssl(socket_, true);
            shutdown_socket(socket_);
            close_socket(socket_);
        }

        // Log
        if (logger_) { logger_(req, res); }

        return true;
    }

    bool
        ClientImpl::process_socket(const Socket& socket,
            std::function<bool(Stream& strm)> callback) {
        return detail::process_client_socket(
            socket.sock, read_timeout_sec_, read_timeout_usec_, write_timeout_sec_,
            write_timeout_usec_, std::move(callback));
    }

    bool ClientImpl::is_ssl() const { return false; }

    Result ClientImpl::Get(const std::string& path) {
        return Get(path, Headers(), Progress());
    }

    Result ClientImpl::Get(const std::string& path, Progress progress) {
        return Get(path, Headers(), std::move(progress));
    }

    Result ClientImpl::Get(const std::string& path, const Headers& headers) {
        return Get(path, headers, Progress());
    }

    Result ClientImpl::Get(const std::string& path, const Headers& headers,
        Progress progress) {
        Request req;
        req.method = "GET";
        req.path = path;
        req.headers = headers;
        req.progress = std::move(progress);

        return send_(std::move(req));
    }

    Result ClientImpl::Get(const std::string& path,
        ContentReceiver content_receiver) {
        return Get(path, Headers(), nullptr, std::move(content_receiver), nullptr);
    }

    Result ClientImpl::Get(const std::string& path,
        ContentReceiver content_receiver,
        Progress progress) {
        return Get(path, Headers(), nullptr, std::move(content_receiver),
            std::move(progress));
    }

    Result ClientImpl::Get(const std::string& path, const Headers& headers,
        ContentReceiver content_receiver) {
        return Get(path, headers, nullptr, std::move(content_receiver), nullptr);
    }

    Result ClientImpl::Get(const std::string& path, const Headers& headers,
        ContentReceiver content_receiver,
        Progress progress) {
        return Get(path, headers, nullptr, std::move(content_receiver),
            std::move(progress));
    }

    Result ClientImpl::Get(const std::string& path,
        ResponseHandler response_handler,
        ContentReceiver content_receiver) {
        return Get(path, Headers(), std::move(response_handler),
            std::move(content_receiver), nullptr);
    }

    Result ClientImpl::Get(const std::string& path, const Headers& headers,
        ResponseHandler response_handler,
        ContentReceiver content_receiver) {
        return Get(path, headers, std::move(response_handler),
            std::move(content_receiver), nullptr);
    }

    Result ClientImpl::Get(const std::string& path,
        ResponseHandler response_handler,
        ContentReceiver content_receiver,
        Progress progress) {
        return Get(path, Headers(), std::move(response_handler),
            std::move(content_receiver), std::move(progress));
    }

    Result ClientImpl::Get(const std::string& path, const Headers& headers,
        ResponseHandler response_handler,
        ContentReceiver content_receiver,
        Progress progress) {
        Request req;
        req.method = "GET";
        req.path = path;
        req.headers = headers;
        req.response_handler = std::move(response_handler);
        req.content_receiver =
            [content_receiver](const char* data, size_t data_length,
                uint64_t /*offset*/, uint64_t /*total_length*/) {
                    return content_receiver(data, data_length);
        };
        req.progress = std::move(progress);

        return send_(std::move(req));
    }

    Result ClientImpl::Get(const std::string& path, const Params& params,
        const Headers& headers, Progress progress) {
        if (params.empty()) { return Get(path, headers); }

        std::string path_with_query = append_query_params(path, params);
        return Get(path_with_query.c_str(), headers, progress);
    }

    Result ClientImpl::Get(const std::string& path, const Params& params,
        const Headers& headers,
        ContentReceiver content_receiver,
        Progress progress) {
        return Get(path, params, headers, nullptr, content_receiver, progress);
    }

    Result ClientImpl::Get(const std::string& path, const Params& params,
        const Headers& headers,
        ResponseHandler response_handler,
        ContentReceiver content_receiver,
        Progress progress) {
        if (params.empty()) {
            return Get(path, headers, response_handler, content_receiver, progress);
        }

        std::string path_with_query = append_query_params(path, params);
        return Get(path_with_query.c_str(), headers, response_handler,
            content_receiver, progress);
    }

    Result ClientImpl::Head(const std::string& path) {
        return Head(path, Headers());
    }

    Result ClientImpl::Head(const std::string& path,
        const Headers& headers) {
        Request req;
        req.method = "HEAD";
        req.headers = headers;
        req.path = path;

        return send_(std::move(req));
    }

    Result ClientImpl::Post(const std::string& path) {
        return Post(path, std::string(), std::string());
    }

    Result ClientImpl::Post(const std::string& path, const char* body,
        size_t content_length,
        const std::string& content_type) {
        return Post(path, Headers(), body, content_length, content_type);
    }

    Result ClientImpl::Post(const std::string& path, const Headers& headers,
        const char* body, size_t content_length,
        const std::string& content_type) {
        return send_with_content_provider("POST", path, headers, body, content_length,
            nullptr, nullptr, content_type);
    }

    Result ClientImpl::Post(const std::string& path, const std::string& body,
        const std::string& content_type) {
        return Post(path, Headers(), body, content_type);
    }

    Result ClientImpl::Post(const std::string& path, const Headers& headers,
        const std::string& body,
        const std::string& content_type) {
        return send_with_content_provider("POST", path, headers, body.data(),
            body.size(), nullptr, nullptr,
            content_type);
    }

    Result ClientImpl::Post(const std::string& path, const Params& params) {
        return Post(path, Headers(), params);
    }

    Result ClientImpl::Post(const std::string& path, size_t content_length,
        ContentProvider content_provider,
        const std::string& content_type) {
        return Post(path, Headers(), content_length, std::move(content_provider),
            content_type);
    }

    Result ClientImpl::Post(const std::string& path,
        ContentProviderWithoutLength content_provider,
        const std::string& content_type) {
        return Post(path, Headers(), std::move(content_provider), content_type);
    }

    Result ClientImpl::Post(const std::string& path, const Headers& headers,
        size_t content_length,
        ContentProvider content_provider,
        const std::string& content_type) {
        return send_with_content_provider("POST", path, headers, nullptr,
            content_length, std::move(content_provider),
            nullptr, content_type);
    }

    Result ClientImpl::Post(const std::string& path, const Headers& headers,
        ContentProviderWithoutLength content_provider,
        const std::string& content_type) {
        return send_with_content_provider("POST", path, headers, nullptr, 0, nullptr,
            std::move(content_provider), content_type);
    }

    Result ClientImpl::Post(const std::string& path, const Headers& headers,
        const Params& params) {
        auto query = detail::params_to_query_str(params);
        return Post(path, headers, query, "application/x-www-form-urlencoded");
    }

    Result ClientImpl::Post(const std::string& path,
        const MultipartFormDataItems& items) {
        return Post(path, Headers(), items);
    }

    Result ClientImpl::Post(const std::string& path, const Headers& headers,
        const MultipartFormDataItems& items) {
        std::string content_type;
        const auto& body = detail::serialize_multipart_formdata(
            items, detail::make_multipart_data_boundary(), content_type);
        return Post(path, headers, body, content_type.c_str());
    }

    Result ClientImpl::Post(const std::string& path, const Headers& headers,
        const MultipartFormDataItems& items,
        const std::string& boundary) {
        if (!detail::is_multipart_boundary_chars_valid(boundary)) {
            return Result{ nullptr, Error::UnsupportedMultipartBoundaryChars };
        }

        std::string content_type;
        const auto& body =
            detail::serialize_multipart_formdata(items, boundary, content_type);
        return Post(path, headers, body, content_type.c_str());
    }

    Result ClientImpl::Put(const std::string& path) {
        return Put(path, std::string(), std::string());
    }

    Result ClientImpl::Put(const std::string& path, const char* body,
        size_t content_length,
        const std::string& content_type) {
        return Put(path, Headers(), body, content_length, content_type);
    }

    Result ClientImpl::Put(const std::string& path, const Headers& headers,
        const char* body, size_t content_length,
        const std::string& content_type) {
        return send_with_content_provider("PUT", path, headers, body, content_length,
            nullptr, nullptr, content_type);
    }

    Result ClientImpl::Put(const std::string& path, const std::string& body,
        const std::string& content_type) {
        return Put(path, Headers(), body, content_type);
    }

    Result ClientImpl::Put(const std::string& path, const Headers& headers,
        const std::string& body,
        const std::string& content_type) {
        return send_with_content_provider("PUT", path, headers, body.data(),
            body.size(), nullptr, nullptr,
            content_type);
    }

    Result ClientImpl::Put(const std::string& path, size_t content_length,
        ContentProvider content_provider,
        const std::string& content_type) {
        return Put(path, Headers(), content_length, std::move(content_provider),
            content_type);
    }

    Result ClientImpl::Put(const std::string& path,
        ContentProviderWithoutLength content_provider,
        const std::string& content_type) {
        return Put(path, Headers(), std::move(content_provider), content_type);
    }

    Result ClientImpl::Put(const std::string& path, const Headers& headers,
        size_t content_length,
        ContentProvider content_provider,
        const std::string& content_type) {
        return send_with_content_provider("PUT", path, headers, nullptr,
            content_length, std::move(content_provider),
            nullptr, content_type);
    }

    Result ClientImpl::Put(const std::string& path, const Headers& headers,
        ContentProviderWithoutLength content_provider,
        const std::string& content_type) {
        return send_with_content_provider("PUT", path, headers, nullptr, 0, nullptr,
            std::move(content_provider), content_type);
    }

    Result ClientImpl::Put(const std::string& path, const Params& params) {
        return Put(path, Headers(), params);
    }

    Result ClientImpl::Put(const std::string& path, const Headers& headers,
        const Params& params) {
        auto query = detail::params_to_query_str(params);
        return Put(path, headers, query, "application/x-www-form-urlencoded");
    }

    Result ClientImpl::Put(const std::string& path,
        const MultipartFormDataItems& items) {
        return Put(path, Headers(), items);
    }

    Result ClientImpl::Put(const std::string& path, const Headers& headers,
        const MultipartFormDataItems& items) {
        std::string content_type;
        const auto& body = detail::serialize_multipart_formdata(
            items, detail::make_multipart_data_boundary(), content_type);
        return Put(path, headers, body, content_type);
    }

    Result ClientImpl::Put(const std::string& path, const Headers& headers,
        const MultipartFormDataItems& items,
        const std::string& boundary) {
        if (!detail::is_multipart_boundary_chars_valid(boundary)) {
            return Result{ nullptr, Error::UnsupportedMultipartBoundaryChars };
        }

        std::string content_type;
        const auto& body =
            detail::serialize_multipart_formdata(items, boundary, content_type);
        return Put(path, headers, body, content_type);
    }

    Result ClientImpl::Patch(const std::string& path) {
        return Patch(path, std::string(), std::string());
    }

    Result ClientImpl::Patch(const std::string& path, const char* body,
        size_t content_length,
        const std::string& content_type) {
        return Patch(path, Headers(), body, content_length, content_type);
    }

    Result ClientImpl::Patch(const std::string& path, const Headers& headers,
        const char* body, size_t content_length,
        const std::string& content_type) {
        return send_with_content_provider("PATCH", path, headers, body,
            content_length, nullptr, nullptr,
            content_type);
    }

    Result ClientImpl::Patch(const std::string& path,
        const std::string& body,
        const std::string& content_type) {
        return Patch(path, Headers(), body, content_type);
    }

    Result ClientImpl::Patch(const std::string& path, const Headers& headers,
        const std::string& body,
        const std::string& content_type) {
        return send_with_content_provider("PATCH", path, headers, body.data(),
            body.size(), nullptr, nullptr,
            content_type);
    }

    Result ClientImpl::Patch(const std::string& path, size_t content_length,
        ContentProvider content_provider,
        const std::string& content_type) {
        return Patch(path, Headers(), content_length, std::move(content_provider),
            content_type);
    }

    Result ClientImpl::Patch(const std::string& path,
        ContentProviderWithoutLength content_provider,
        const std::string& content_type) {
        return Patch(path, Headers(), std::move(content_provider), content_type);
    }

    Result ClientImpl::Patch(const std::string& path, const Headers& headers,
        size_t content_length,
        ContentProvider content_provider,
        const std::string& content_type) {
        return send_with_content_provider("PATCH", path, headers, nullptr,
            content_length, std::move(content_provider),
            nullptr, content_type);
    }

    Result ClientImpl::Patch(const std::string& path, const Headers& headers,
        ContentProviderWithoutLength content_provider,
        const std::string& content_type) {
        return send_with_content_provider("PATCH", path, headers, nullptr, 0, nullptr,
            std::move(content_provider), content_type);
    }

    Result ClientImpl::Delete(const std::string& path) {
        return Delete(path, Headers(), std::string(), std::string());
    }

    Result ClientImpl::Delete(const std::string& path,
        const Headers& headers) {
        return Delete(path, headers, std::string(), std::string());
    }

    Result ClientImpl::Delete(const std::string& path, const char* body,
        size_t content_length,
        const std::string& content_type) {
        return Delete(path, Headers(), body, content_length, content_type);
    }

    Result ClientImpl::Delete(const std::string& path,
        const Headers& headers, const char* body,
        size_t content_length,
        const std::string& content_type) {
        Request req;
        req.method = "DELETE";
        req.headers = headers;
        req.path = path;

        if (!content_type.empty()) {
            req.headers.emplace("Content-Type", content_type);
        }
        req.body.assign(body, content_length);

        return send_(std::move(req));
    }

    Result ClientImpl::Delete(const std::string& path,
        const std::string& body,
        const std::string& content_type) {
        return Delete(path, Headers(), body.data(), body.size(), content_type);
    }

    Result ClientImpl::Delete(const std::string& path,
        const Headers& headers,
        const std::string& body,
        const std::string& content_type) {
        return Delete(path, headers, body.data(), body.size(), content_type);
    }

    Result ClientImpl::Options(const std::string& path) {
        return Options(path, Headers());
    }

    Result ClientImpl::Options(const std::string& path,
        const Headers& headers) {
        Request req;
        req.method = "OPTIONS";
        req.headers = headers;
        req.path = path;

        return send_(std::move(req));
    }

    size_t ClientImpl::is_socket_open() const {
        std::lock_guard<std::mutex> guard(socket_mutex_);
        return socket_.is_open();
    }

    socket_t ClientImpl::socket() const { return socket_.sock; }

    void ClientImpl::stop() {
        std::lock_guard<std::mutex> guard(socket_mutex_);

        // If there is anything ongoing right now, the ONLY thread-safe thing we can
        // do is to shutdown_socket, so that threads using this socket suddenly
        // discover they can't read/write any more and error out. Everything else
        // (closing the socket, shutting ssl down) is unsafe because these actions are
        // not thread-safe.
        if (socket_requests_in_flight_ > 0) {
            shutdown_socket(socket_);

            // Aside from that, we set a flag for the socket to be closed when we're
            // done.
            socket_should_be_closed_when_request_is_done_ = true;
            return;
        }

        // Otherwise, sitll holding the mutex, we can shut everything down ourselves
        shutdown_ssl(socket_, true);
        shutdown_socket(socket_);
        close_socket(socket_);
    }

    void ClientImpl::set_connection_timeout(time_t sec, time_t usec) {
        connection_timeout_sec_ = sec;
        connection_timeout_usec_ = usec;
    }

    void ClientImpl::set_read_timeout(time_t sec, time_t usec) {
        read_timeout_sec_ = sec;
        read_timeout_usec_ = usec;
    }

    void ClientImpl::set_write_timeout(time_t sec, time_t usec) {
        write_timeout_sec_ = sec;
        write_timeout_usec_ = usec;
    }

    void ClientImpl::set_basic_auth(const std::string& username,
        const std::string& password) {
        basic_auth_username_ = username;
        basic_auth_password_ = password;
    }

    void ClientImpl::set_bearer_token_auth(const std::string& token) {
        bearer_token_auth_token_ = token;
    }

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    void ClientImpl::set_digest_auth(const std::string& username,
        const std::string& password) {
        digest_auth_username_ = username;
        digest_auth_password_ = password;
    }
#endif

    void ClientImpl::set_keep_alive(bool on) { keep_alive_ = on; }

    void ClientImpl::set_follow_location(bool on) { follow_location_ = on; }

    void ClientImpl::set_url_encode(bool on) { url_encode_ = on; }

    void
        ClientImpl::set_hostname_addr_map(std::map<std::string, std::string> addr_map) {
        addr_map_ = std::move(addr_map);
    }

    void ClientImpl::set_default_headers(Headers headers) {
        default_headers_ = std::move(headers);
    }

    void ClientImpl::set_address_family(int family) {
        address_family_ = family;
    }

    void ClientImpl::set_tcp_nodelay(bool on) { tcp_nodelay_ = on; }

    void ClientImpl::set_socket_options(SocketOptions socket_options) {
        socket_options_ = std::move(socket_options);
    }

    void ClientImpl::set_compress(bool on) { compress_ = on; }

    void ClientImpl::set_decompress(bool on) { decompress_ = on; }

    void ClientImpl::set_interface(const std::string& intf) {
        interface_ = intf;
    }

    void ClientImpl::set_proxy(const std::string& host, int port) {
        proxy_host_ = host;
        proxy_port_ = port;
    }

    void ClientImpl::set_proxy_basic_auth(const std::string& username,
        const std::string& password) {
        proxy_basic_auth_username_ = username;
        proxy_basic_auth_password_ = password;
    }

    void ClientImpl::set_proxy_bearer_token_auth(const std::string& token) {
        proxy_bearer_token_auth_token_ = token;
    }

    void ClientImpl::set_logger(Logger logger) {
        logger_ = std::move(logger);
    }

    //Universal

    Client::Client(const std::string& scheme_host_port)
        : Client(scheme_host_port, std::string(), std::string()) {}

    Client::Client(const std::string& scheme_host_port,
        const std::string& client_cert_path,
        const std::string& client_key_path) {
        const static std::regex re(
            R"((?:([a-z]+):\/\/)?(?:\[([\d:]+)\]|([^:/?#]+))(?::(\d+))?)");

        std::smatch m;
        if (std::regex_match(scheme_host_port, m, re)) {
            auto scheme = m[1].str();

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
            if (!scheme.empty() && (scheme != "http" && scheme != "https")) {
#else
            if (!scheme.empty() && scheme != "http") {
#endif
#ifndef CPPHTTPLIB_NO_EXCEPTIONS
                std::string msg = "'" + scheme + "' scheme is not supported.";
                throw std::invalid_argument(msg);
#endif
                return;
            }

            auto is_ssl = scheme == "https";

            auto host = m[2].str();
            if (host.empty()) { host = m[3].str(); }

            auto port_str = m[4].str();
            auto port = !port_str.empty() ? std::stoi(port_str) : (is_ssl ? 443 : 80);

            if (is_ssl) {
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
                cli_ = detail::make_unique<SSLClient>(host, port, client_cert_path,
                    client_key_path);
                is_ssl_ = is_ssl;
#endif
            }
            else {
                cli_ = detail::make_unique<ClientImpl>(host, port, client_cert_path,
                    client_key_path);
            }
            }
        else {
            cli_ = detail::make_unique<ClientImpl>(scheme_host_port, 80,
                client_cert_path, client_key_path);
        }
        }

    Client::Client(const std::string & host, int port)
        : cli_(detail::make_unique<ClientImpl>(host, port)) {}

    Client::Client(const std::string & host, int port,
        const std::string & client_cert_path,
        const std::string & client_key_path)
        : cli_(detail::make_unique<ClientImpl>(host, port, client_cert_path,
            client_key_path)) {}

    Client::~Client() {}

    bool Client::is_valid() const {
        return cli_ != nullptr && cli_->is_valid();
    }

    Result Client::Get(const std::string & path) { return cli_->Get(path); }
    Result Client::Get(const std::string & path, const Headers & headers) {
        return cli_->Get(path, headers);
    }
    Result Client::Get(const std::string & path, Progress progress) {
        return cli_->Get(path, std::move(progress));
    }
    Result Client::Get(const std::string & path, const Headers & headers,
        Progress progress) {
        return cli_->Get(path, headers, std::move(progress));
    }
    Result Client::Get(const std::string & path,
        ContentReceiver content_receiver) {
        return cli_->Get(path, std::move(content_receiver));
    }
    Result Client::Get(const std::string & path, const Headers & headers,
        ContentReceiver content_receiver) {
        return cli_->Get(path, headers, std::move(content_receiver));
    }
    Result Client::Get(const std::string & path,
        ContentReceiver content_receiver, Progress progress) {
        return cli_->Get(path, std::move(content_receiver), std::move(progress));
    }
    Result Client::Get(const std::string & path, const Headers & headers,
        ContentReceiver content_receiver, Progress progress) {
        return cli_->Get(path, headers, std::move(content_receiver),
            std::move(progress));
    }
    Result Client::Get(const std::string & path,
        ResponseHandler response_handler,
        ContentReceiver content_receiver) {
        return cli_->Get(path, std::move(response_handler),
            std::move(content_receiver));
    }
    Result Client::Get(const std::string & path, const Headers & headers,
        ResponseHandler response_handler,
        ContentReceiver content_receiver) {
        return cli_->Get(path, headers, std::move(response_handler),
            std::move(content_receiver));
    }
    Result Client::Get(const std::string & path,
        ResponseHandler response_handler,
        ContentReceiver content_receiver, Progress progress) {
        return cli_->Get(path, std::move(response_handler),
            std::move(content_receiver), std::move(progress));
    }
    Result Client::Get(const std::string & path, const Headers & headers,
        ResponseHandler response_handler,
        ContentReceiver content_receiver, Progress progress) {
        return cli_->Get(path, headers, std::move(response_handler),
            std::move(content_receiver), std::move(progress));
    }
    Result Client::Get(const std::string & path, const Params & params,
        const Headers & headers, Progress progress) {
        return cli_->Get(path, params, headers, progress);
    }
    Result Client::Get(const std::string & path, const Params & params,
        const Headers & headers,
        ContentReceiver content_receiver, Progress progress) {
        return cli_->Get(path, params, headers, content_receiver, progress);
    }
    Result Client::Get(const std::string & path, const Params & params,
        const Headers & headers,
        ResponseHandler response_handler,
        ContentReceiver content_receiver, Progress progress) {
        return cli_->Get(path, params, headers, response_handler, content_receiver,
            progress);
    }

    Result Client::Head(const std::string & path) { return cli_->Head(path); }
    Result Client::Head(const std::string & path, const Headers & headers) {
        return cli_->Head(path, headers);
    }

    Result Client::Post(const std::string & path) { return cli_->Post(path); }
    Result Client::Post(const std::string & path, const char* body,
        size_t content_length,
        const std::string & content_type) {
        return cli_->Post(path, body, content_length, content_type);
    }
    Result Client::Post(const std::string & path, const Headers & headers,
        const char* body, size_t content_length,
        const std::string & content_type) {
        return cli_->Post(path, headers, body, content_length, content_type);
    }
    Result Client::Post(const std::string & path, const std::string & body,
        const std::string & content_type) {
        return cli_->Post(path, body, content_type);
    }
    Result Client::Post(const std::string & path, const Headers & headers,
        const std::string & body,
        const std::string & content_type) {
        return cli_->Post(path, headers, body, content_type);
    }
    Result Client::Post(const std::string & path, size_t content_length,
        ContentProvider content_provider,
        const std::string & content_type) {
        return cli_->Post(path, content_length, std::move(content_provider),
            content_type);
    }
    Result Client::Post(const std::string & path,
        ContentProviderWithoutLength content_provider,
        const std::string & content_type) {
        return cli_->Post(path, std::move(content_provider), content_type);
    }
    Result Client::Post(const std::string & path, const Headers & headers,
        size_t content_length,
        ContentProvider content_provider,
        const std::string & content_type) {
        return cli_->Post(path, headers, content_length, std::move(content_provider),
            content_type);
    }
    Result Client::Post(const std::string & path, const Headers & headers,
        ContentProviderWithoutLength content_provider,
        const std::string & content_type) {
        return cli_->Post(path, headers, std::move(content_provider), content_type);
    }
    Result Client::Post(const std::string & path, const Params & params) {
        return cli_->Post(path, params);
    }
    Result Client::Post(const std::string & path, const Headers & headers,
        const Params & params) {
        return cli_->Post(path, headers, params);
    }
    Result Client::Post(const std::string & path,
        const MultipartFormDataItems & items) {
        return cli_->Post(path, items);
    }
    Result Client::Post(const std::string & path, const Headers & headers,
        const MultipartFormDataItems & items) {
        return cli_->Post(path, headers, items);
    }
    Result Client::Post(const std::string & path, const Headers & headers,
        const MultipartFormDataItems & items,
        const std::string & boundary) {
        return cli_->Post(path, headers, items, boundary);
    }
    Result Client::Put(const std::string & path) { return cli_->Put(path); }
    Result Client::Put(const std::string & path, const char* body,
        size_t content_length,
        const std::string & content_type) {
        return cli_->Put(path, body, content_length, content_type);
    }
    Result Client::Put(const std::string & path, const Headers & headers,
        const char* body, size_t content_length,
        const std::string & content_type) {
        return cli_->Put(path, headers, body, content_length, content_type);
    }
    Result Client::Put(const std::string & path, const std::string & body,
        const std::string & content_type) {
        return cli_->Put(path, body, content_type);
    }
    Result Client::Put(const std::string & path, const Headers & headers,
        const std::string & body,
        const std::string & content_type) {
        return cli_->Put(path, headers, body, content_type);
    }
    Result Client::Put(const std::string & path, size_t content_length,
        ContentProvider content_provider,
        const std::string & content_type) {
        return cli_->Put(path, content_length, std::move(content_provider),
            content_type);
    }
    Result Client::Put(const std::string & path,
        ContentProviderWithoutLength content_provider,
        const std::string & content_type) {
        return cli_->Put(path, std::move(content_provider), content_type);
    }
    Result Client::Put(const std::string & path, const Headers & headers,
        size_t content_length,
        ContentProvider content_provider,
        const std::string & content_type) {
        return cli_->Put(path, headers, content_length, std::move(content_provider),
            content_type);
    }
    Result Client::Put(const std::string & path, const Headers & headers,
        ContentProviderWithoutLength content_provider,
        const std::string & content_type) {
        return cli_->Put(path, headers, std::move(content_provider), content_type);
    }
    Result Client::Put(const std::string & path, const Params & params) {
        return cli_->Put(path, params);
    }
    Result Client::Put(const std::string & path, const Headers & headers,
        const Params & params) {
        return cli_->Put(path, headers, params);
    }
    Result Client::Put(const std::string & path,
        const MultipartFormDataItems & items) {
        return cli_->Put(path, items);
    }
    Result Client::Put(const std::string & path, const Headers & headers,
        const MultipartFormDataItems & items) {
        return cli_->Put(path, headers, items);
    }
    Result Client::Put(const std::string & path, const Headers & headers,
        const MultipartFormDataItems & items,
        const std::string & boundary) {
        return cli_->Put(path, headers, items, boundary);
    }
    Result Client::Patch(const std::string & path) {
        return cli_->Patch(path);
    }
    Result Client::Patch(const std::string & path, const char* body,
        size_t content_length,
        const std::string & content_type) {
        return cli_->Patch(path, body, content_length, content_type);
    }
    Result Client::Patch(const std::string & path, const Headers & headers,
        const char* body, size_t content_length,
        const std::string & content_type) {
        return cli_->Patch(path, headers, body, content_length, content_type);
    }
    Result Client::Patch(const std::string & path, const std::string & body,
        const std::string & content_type) {
        return cli_->Patch(path, body, content_type);
    }
    Result Client::Patch(const std::string & path, const Headers & headers,
        const std::string & body,
        const std::string & content_type) {
        return cli_->Patch(path, headers, body, content_type);
    }
    Result Client::Patch(const std::string & path, size_t content_length,
        ContentProvider content_provider,
        const std::string & content_type) {
        return cli_->Patch(path, content_length, std::move(content_provider),
            content_type);
    }
    Result Client::Patch(const std::string & path,
        ContentProviderWithoutLength content_provider,
        const std::string & content_type) {
        return cli_->Patch(path, std::move(content_provider), content_type);
    }
    Result Client::Patch(const std::string & path, const Headers & headers,
        size_t content_length,
        ContentProvider content_provider,
        const std::string & content_type) {
        return cli_->Patch(path, headers, content_length, std::move(content_provider),
            content_type);
    }
    Result Client::Patch(const std::string & path, const Headers & headers,
        ContentProviderWithoutLength content_provider,
        const std::string & content_type) {
        return cli_->Patch(path, headers, std::move(content_provider), content_type);
    }
    Result Client::Delete(const std::string & path) {
        return cli_->Delete(path);
    }
    Result Client::Delete(const std::string & path, const Headers & headers) {
        return cli_->Delete(path, headers);
    }
    Result Client::Delete(const std::string & path, const char* body,
        size_t content_length,
        const std::string & content_type) {
        return cli_->Delete(path, body, content_length, content_type);
    }
    Result Client::Delete(const std::string & path, const Headers & headers,
        const char* body, size_t content_length,
        const std::string & content_type) {
        return cli_->Delete(path, headers, body, content_length, content_type);
    }
    Result Client::Delete(const std::string & path, const std::string & body,
        const std::string & content_type) {
        return cli_->Delete(path, body, content_type);
    }
    Result Client::Delete(const std::string & path, const Headers & headers,
        const std::string & body,
        const std::string & content_type) {
        return cli_->Delete(path, headers, body, content_type);
    }
    Result Client::Options(const std::string & path) {
        return cli_->Options(path);
    }
    Result Client::Options(const std::string & path, const Headers & headers) {
        return cli_->Options(path, headers);
    }

    bool Client::send(Request & req, Response & res, Error & error) {
        return cli_->send(req, res, error);
    }

    Result Client::send(const Request & req) { return cli_->send(req); }

    size_t Client::is_socket_open() const { return cli_->is_socket_open(); }

    socket_t Client::socket() const { return cli_->socket(); }

    void Client::stop() { cli_->stop(); }

    void
        Client::set_hostname_addr_map(std::map<std::string, std::string> addr_map) {
        cli_->set_hostname_addr_map(std::move(addr_map));
    }

    void Client::set_default_headers(Headers headers) {
        cli_->set_default_headers(std::move(headers));
    }

    void Client::set_address_family(int family) {
        cli_->set_address_family(family);
    }

    void Client::set_tcp_nodelay(bool on) { cli_->set_tcp_nodelay(on); }

    void Client::set_socket_options(SocketOptions socket_options) {
        cli_->set_socket_options(std::move(socket_options));
    }

    void Client::set_connection_timeout(time_t sec, time_t usec) {
        cli_->set_connection_timeout(sec, usec);
    }

    void Client::set_read_timeout(time_t sec, time_t usec) {
        cli_->set_read_timeout(sec, usec);
    }

    void Client::set_write_timeout(time_t sec, time_t usec) {
        cli_->set_write_timeout(sec, usec);
    }

    void Client::set_basic_auth(const std::string & username,
        const std::string & password) {
        cli_->set_basic_auth(username, password);
    }
    void Client::set_bearer_token_auth(const std::string & token) {
        cli_->set_bearer_token_auth(token);
    }
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    void Client::set_digest_auth(const std::string & username,
        const std::string & password) {
        cli_->set_digest_auth(username, password);
    }
#endif

    void Client::set_keep_alive(bool on) { cli_->set_keep_alive(on); }
    void Client::set_follow_location(bool on) {
        cli_->set_follow_location(on);
    }

    void Client::set_url_encode(bool on) { cli_->set_url_encode(on); }

    void Client::set_compress(bool on) { cli_->set_compress(on); }

    void Client::set_decompress(bool on) { cli_->set_decompress(on); }

    void Client::set_interface(const std::string & intf) {
        cli_->set_interface(intf);
    }

    void Client::set_proxy(const std::string & host, int port) {
        cli_->set_proxy(host, port);
    }
    void Client::set_proxy_basic_auth(const std::string & username,
        const std::string & password) {
        cli_->set_proxy_basic_auth(username, password);
    }
    void Client::set_proxy_bearer_token_auth(const std::string & token) {
        cli_->set_proxy_bearer_token_auth(token);
    }

    void Client::set_logger(Logger logger) { cli_->set_logger(logger); }
} // namespace HTTP