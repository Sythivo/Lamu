#include "server.h"

namespace HTTP
{
    template <class Rep, class Period>
    Server&
        Server::set_read_timeout(const std::chrono::duration<Rep, Period>& duration) {
        httplib::detail::duration_to_sec_and_usec(
            duration, [&](time_t sec, time_t usec) { set_read_timeout(sec, usec); });
        return *this;
    }

    template <class Rep, class Period>
    Server&
        Server::set_write_timeout(const std::chrono::duration<Rep, Period>& duration) {
        httplib::detail::duration_to_sec_and_usec(
            duration, [&](time_t sec, time_t usec) { set_write_timeout(sec, usec); });
        return *this;
    }

    template <class Rep, class Period>
    Server&
        Server::set_idle_interval(const std::chrono::duration<Rep, Period>& duration) {
        httplib::detail::duration_to_sec_and_usec(
            duration, [&](time_t sec, time_t usec) { set_idle_interval(sec, usec); });
        return *this;
    }

    Server::Server()
        : new_task_queue(
            [] { return new httplib::ThreadPool(CPPHTTPLIB_THREAD_POOL_COUNT); }),
        svr_sock_(INVALID_SOCKET), is_running_(false) {
#ifndef _WIN32
        signal(SIGPIPE, SIG_IGN);
#endif
    }

    Server& Server::Get(const std::string& pattern, Handler handler) {
        get_handlers_.push_back(
            std::make_pair(std::regex(pattern), std::move(handler)));
        return *this;
    }

    Server& Server::Post(const std::string& pattern, Handler handler) {
        post_handlers_.push_back(
            std::make_pair(std::regex(pattern), std::move(handler)));
        return *this;
    }

    Server& Server::Post(const std::string& pattern,
        HandlerWithContentReader handler) {
        post_handlers_for_content_reader_.push_back(
            std::make_pair(std::regex(pattern), std::move(handler)));
        return *this;
    }

    Server& Server::Put(const std::string& pattern, Handler handler) {
        put_handlers_.push_back(
            std::make_pair(std::regex(pattern), std::move(handler)));
        return *this;
    }

    Server& Server::Put(const std::string& pattern,
        HandlerWithContentReader handler) {
        put_handlers_for_content_reader_.push_back(
            std::make_pair(std::regex(pattern), std::move(handler)));
        return *this;
    }

    Server& Server::Patch(const std::string& pattern, Handler handler) {
        patch_handlers_.push_back(
            std::make_pair(std::regex(pattern), std::move(handler)));
        return *this;
    }

    Server& Server::Patch(const std::string& pattern,
        HandlerWithContentReader handler) {
        patch_handlers_for_content_reader_.push_back(
            std::make_pair(std::regex(pattern), std::move(handler)));
        return *this;
    }

    Server& Server::Delete(const std::string& pattern, Handler handler) {
        delete_handlers_.push_back(
            std::make_pair(std::regex(pattern), std::move(handler)));
        return *this;
    }

    Server& Server::Delete(const std::string& pattern,
        HandlerWithContentReader handler) {
        delete_handlers_for_content_reader_.push_back(
            std::make_pair(std::regex(pattern), std::move(handler)));
        return *this;
    }

    Server& Server::Options(const std::string& pattern, Handler handler) {
        options_handlers_.push_back(
            std::make_pair(std::regex(pattern), std::move(handler)));
        return *this;
    }

    bool Server::set_base_dir(const std::string& dir,
        const std::string& mount_point) {
        return set_mount_point(mount_point, dir);
    }

    bool Server::set_mount_point(const std::string& mount_point,
        const std::string& dir, httplib::Headers headers) {
        if (httplib::detail::is_dir(dir)) {
            std::string mnt = !mount_point.empty() ? mount_point : "/";
            if (!mnt.empty() && mnt[0] == '/') {
                base_dirs_.push_back({ mnt, dir, std::move(headers) });
                return true;
            }
        }
        return false;
    }

    bool Server::remove_mount_point(const std::string& mount_point) {
        for (auto it = base_dirs_.begin(); it != base_dirs_.end(); ++it) {
            if (it->mount_point == mount_point) {
                base_dirs_.erase(it);
                return true;
            }
        }
        return false;
    }

    Server&
        Server::set_file_extension_and_mimetype_mapping(const std::string& ext,
            const std::string& mime) {
        file_extension_and_mimetype_map_[ext] = mime;
        return *this;
    }

    Server& Server::set_file_request_handler(Handler handler) {
        file_request_handler_ = std::move(handler);
        return *this;
    }

    Server& Server::set_error_handler(HandlerWithResponse handler) {
        error_handler_ = std::move(handler);
        return *this;
    }

    Server& Server::set_error_handler(Handler handler) {
        error_handler_ = [handler](const httplib::Request& req, httplib::Response& res) {
            handler(req, res);
            return HandlerResponse::Handled;
        };
        return *this;
    }

    Server& Server::set_exception_handler(ExceptionHandler handler) {
        exception_handler_ = std::move(handler);
        return *this;
    }

    Server& Server::set_pre_routing_handler(HandlerWithResponse handler) {
        pre_routing_handler_ = std::move(handler);
        return *this;
    }

    Server& Server::set_post_routing_handler(Handler handler) {
        post_routing_handler_ = std::move(handler);
        return *this;
    }

    Server& Server::set_logger(httplib::Logger logger) {
        logger_ = std::move(logger);
        return *this;
    }

    Server&
        Server::set_expect_100_continue_handler(Expect100ContinueHandler handler) {
        expect_100_continue_handler_ = std::move(handler);

        return *this;
    }

    Server& Server::set_address_family(int family) {
        address_family_ = family;
        return *this;
    }

    Server& Server::set_tcp_nodelay(bool on) {
        tcp_nodelay_ = on;
        return *this;
    }

    Server& Server::set_socket_options(httplib::SocketOptions socket_options) {
        socket_options_ = std::move(socket_options);
        return *this;
    }

    Server& Server::set_default_headers(httplib::Headers headers) {
        default_headers_ = std::move(headers);
        return *this;
    }

    Server& Server::set_keep_alive_max_count(size_t count) {
        keep_alive_max_count_ = count;
        return *this;
    }

    Server& Server::set_keep_alive_timeout(time_t sec) {
        keep_alive_timeout_sec_ = sec;
        return *this;
    }

    Server& Server::set_read_timeout(time_t sec, time_t usec) {
        read_timeout_sec_ = sec;
        read_timeout_usec_ = usec;
        return *this;
    }

    Server& Server::set_write_timeout(time_t sec, time_t usec) {
        write_timeout_sec_ = sec;
        write_timeout_usec_ = usec;
        return *this;
    }

    Server& Server::set_idle_interval(time_t sec, time_t usec) {
        idle_interval_sec_ = sec;
        idle_interval_usec_ = usec;
        return *this;
    }

    Server& Server::set_payload_max_length(size_t length) {
        payload_max_length_ = length;
        return *this;
    }

    bool Server::bind_to_port(const std::string& host, int port,
        int socket_flags) {
        if (bind_internal(host, port, socket_flags) < 0) return false;
        return true;
    }
    int Server::bind_to_any_port(const std::string& host, int socket_flags) {
        return bind_internal(host, 0, socket_flags);
    }

    bool Server::listen_after_bind() { return listen_internal(); }

    bool Server::listen(const std::string& host, int port,
        int socket_flags) {
        if (is_running_) {
            std::cout << "already running" << std::endl;
            return false;
        }

        return bind_to_port(host, port, socket_flags) && listen_internal();
    }

    bool Server::is_running() const { return is_running_; }

    void Server::stop() {
        if (is_running_) {
            assert(svr_sock_ != INVALID_SOCKET);
            std::atomic<socket_t> sock(svr_sock_.exchange(INVALID_SOCKET));
            httplib::detail::shutdown_socket(sock);
            httplib::detail::close_socket(sock);
        }
    }

    bool Server::parse_request_line(const char* s, httplib::Request& req) {
        auto len = strlen(s);
        if (len < 2 || s[len - 2] != '\r' || s[len - 1] != '\n') { return false; }
        len -= 2;

        {
            size_t count = 0;

            httplib::detail::split(s, s + len, ' ', [&](const char* b, const char* e) {
                switch (count) {
                case 0: req.method = std::string(b, e); break;
                case 1: req.target = std::string(b, e); break;
                case 2: req.version = std::string(b, e); break;
                default: break;
                }
                count++;
                });

            if (count != 3) { return false; }
        }

        static const std::set<std::string> methods{
            "GET",     "HEAD",    "POST",  "PUT",   "DELETE",
            "CONNECT", "OPTIONS", "TRACE", "PATCH", "PRI" };

        if (methods.find(req.method) == methods.end()) { return false; }

        if (req.version != "HTTP/1.1" && req.version != "HTTP/1.0") { return false; }

        {
            // Skip URL fragment
            for (size_t i = 0; i < req.target.size(); i++) {
                if (req.target[i] == '#') {
                    req.target.erase(i);
                    break;
                }
            }

            size_t count = 0;

            httplib::detail::split(req.target.data(), req.target.data() + req.target.size(), '?',
                [&](const char* b, const char* e) {
                    switch (count) {
                    case 0:
                        req.path = httplib::detail::decode_url(std::string(b, e), false);
                        break;
                    case 1: {
                        if (e - b > 0) {
                            httplib::detail::parse_query_text(std::string(b, e), req.params);
                        }
                        break;
                    }
                    default: break;
                    }
                    count++;
                });

            if (count > 2) { return false; }
        }

        return true;
    }

    bool Server::write_response(httplib::Stream& strm, bool close_connection,
        const httplib::Request& req, httplib::Response& res) {
        return write_response_core(strm, close_connection, req, res, false);
    }

    bool Server::write_response_with_content(httplib::Stream& strm,
        bool close_connection,
        const httplib::Request& req,
        httplib::Response& res) {
        return write_response_core(strm, close_connection, req, res, true);
    }

    bool Server::write_response_core(httplib::Stream& strm, bool close_connection,
        const httplib::Request& req, httplib::Response& res,
        bool need_apply_ranges) {
        assert(res.status != -1);

        if (400 <= res.status && error_handler_ &&
            error_handler_(req, res) == HandlerResponse::Handled) {
            need_apply_ranges = true;
        }

        std::string content_type;
        std::string boundary;
        if (need_apply_ranges) { apply_ranges(req, res, content_type, boundary); }

        // Prepare additional headers
        if (close_connection || req.get_header_value("Connection") == "close") {
            res.set_header("Connection", "close");
        }
        else {
            std::stringstream ss;
            ss << "timeout=" << keep_alive_timeout_sec_
                << ", max=" << keep_alive_max_count_;
            res.set_header("Keep-Alive", ss.str());
        }

        if (!res.has_header("Content-Type") &&
            (!res.body.empty() || res.content_length_ > 0 || res.content_provider_)) {
            res.set_header("Content-Type", "text/plain");
        }

        if (!res.has_header("Content-Length") && res.body.empty() &&
            !res.content_length_ && !res.content_provider_) {
            res.set_header("Content-Length", "0");
        }

        if (!res.has_header("Accept-Ranges") && req.method == "HEAD") {
            res.set_header("Accept-Ranges", "bytes");
        }

        if (post_routing_handler_) { post_routing_handler_(req, res); }

        // httplib::Response line and headers
        {
            httplib::detail::BufferStream bstrm;

            if (!bstrm.write_format("HTTP/1.1 %d %s\r\n", res.status,
                httplib::detail::status_message(res.status))) {
                return false;
            }

            if (!httplib::detail::write_headers(bstrm, res.headers)) { return false; }

            // Flush buffer
            auto& data = bstrm.get_buffer();
            httplib::detail::write_data(strm, data.data(), data.size());
        }

        // Body
        auto ret = true;
        if (req.method != "HEAD") {
            if (!res.body.empty()) {
                if (!httplib::detail::write_data(strm, res.body.data(), res.body.size())) {
                    ret = false;
                }
            }
            else if (res.content_provider_) {
                if (write_content_with_provider(strm, req, res, boundary, content_type)) {
                    res.content_provider_success_ = true;
                }
                else {
                    res.content_provider_success_ = false;
                    ret = false;
                }
            }
        }

        // Log
        if (logger_) { logger_(req, res); }

        return ret;
    }

    bool
        Server::write_content_with_provider(httplib::Stream& strm, const httplib::Request& req,
            httplib::Response& res, const std::string& boundary,
            const std::string& content_type) {
        auto is_shutting_down = [this]() {
            return this->svr_sock_ == INVALID_SOCKET;
        };

        if (res.content_length_ > 0) {
            if (req.ranges.empty()) {
                return httplib::detail::write_content(strm, res.content_provider_, 0,
                    res.content_length_, is_shutting_down);
            }
            else if (req.ranges.size() == 1) {
                auto offsets =
                    httplib::detail::get_range_offset_and_length(req, res.content_length_, 0);
                auto offset = offsets.first;
                auto length = offsets.second;
                return httplib::detail::write_content(strm, res.content_provider_, offset, length,
                    is_shutting_down);
            }
            else {
                return httplib::detail::write_multipart_ranges_data(
                    strm, req, res, boundary, content_type, is_shutting_down);
            }
        }
        else {
            if (res.is_chunked_content_provider_) {
                auto type = httplib::detail::encoding_type(req, res);

                std::unique_ptr<httplib::detail::compressor> compressor;
                if (type == httplib::detail::EncodingType::Gzip) {
#ifdef CPPHTTPLIB_ZLIB_SUPPORT
                    compressor = httplib::detail::make_unique<httplib::detail::gzip_compressor>();
#endif
                }
                else if (type == httplib::detail::EncodingType::Brotli) {
#ifdef CPPHTTPLIB_BROTLI_SUPPORT
                    compressor = httplib::detail::make_unique<httplib::detail::brotli_compressor>();
#endif
                }
                else {
                    compressor = httplib::detail::make_unique<httplib::detail::nocompressor>();
                }
                assert(compressor != nullptr);

                return httplib::detail::write_content_chunked(strm, res.content_provider_,
                    is_shutting_down, *compressor);
            }
            else {
                return httplib::detail::write_content_without_length(strm, res.content_provider_,
                    is_shutting_down);
            }
        }
    }

    bool Server::read_content(httplib::Stream& strm, httplib::Request& req, httplib::Response& res) {
        httplib::MultipartFormDataMap::iterator cur;
        auto file_count = 0;
        if (read_content_core(
            strm, req, res,
            // Regular
            [&](const char* buf, size_t n) {
                if (req.body.size() + n > req.body.max_size()) { return false; }
                req.body.append(buf, n);
                return true;
            },
            // Multipart
                [&](const httplib::MultipartFormData& file) {
                if (file_count++ == CPPHTTPLIB_MULTIPART_FORM_DATA_FILE_MAX_COUNT) {
                    return false;
                }
                cur = req.files.emplace(file.name, file);
                return true;
            },
                [&](const char* buf, size_t n) {
                auto& content = cur->second.content;
                if (content.size() + n > content.max_size()) { return false; }
                content.append(buf, n);
                return true;
            })) {
            const auto& content_type = req.get_header_value("Content-Type");
            if (!content_type.find("application/x-www-form-urlencoded")) {
                if (req.body.size() > CPPHTTPLIB_FORM_URL_ENCODED_PAYLOAD_MAX_LENGTH) {
                    res.status = 413; // NOTE: should be 414?
                    return false;
                }
                httplib::detail::parse_query_text(req.body, req.params);
            }
            return true;
        }
        return false;
    }

    bool Server::read_content_with_content_receiver(
        httplib::Stream& strm, httplib::Request& req, httplib::Response& res, httplib::ContentReceiver receiver,
        httplib::MultipartContentHeader multipart_header,
        httplib::ContentReceiver multipart_receiver) {
        return read_content_core(strm, req, res, std::move(receiver),
            std::move(multipart_header),
            std::move(multipart_receiver));
    }

    bool Server::read_content_core(httplib::Stream& strm, httplib::Request& req, httplib::Response& res,
        httplib::ContentReceiver receiver,
        httplib::MultipartContentHeader mulitpart_header,
        httplib::ContentReceiver multipart_receiver) {
        httplib::detail::MultipartFormDataParser multipart_form_data_parser;
        httplib::ContentReceiverWithProgress out;

        if (req.is_multipart_form_data()) {
            const auto& content_type = req.get_header_value("Content-Type");
            std::string boundary;
            if (!httplib::detail::parse_multipart_boundary(content_type, boundary)) {
                res.status = 400;
                return false;
            }

            multipart_form_data_parser.set_boundary(std::move(boundary));
            out = [&](const char* buf, size_t n, uint64_t /*off*/, uint64_t /*len*/) {
                /* For debug
                size_t pos = 0;
                while (pos < n) {
                  auto read_size = (std::min)<size_t>(1, n - pos);
                  auto ret = multipart_form_data_parser.parse(
                      buf + pos, read_size, multipart_receiver, mulitpart_header);
                  if (!ret) { return false; }
                  pos += read_size;
                }
                return true;
                */
                return multipart_form_data_parser.parse(buf, n, multipart_receiver,
                    mulitpart_header);
            };
        }
        else {
            out = [receiver](const char* buf, size_t n, uint64_t /*off*/,
                uint64_t /*len*/) { return receiver(buf, n); };
        }

        if (req.method == "DELETE" && !req.has_header("Content-Length")) {
            return true;
        }

        if (!httplib::detail::read_content(strm, req, payload_max_length_, res.status, nullptr,
            out, true)) {
            return false;
        }

        if (req.is_multipart_form_data()) {
            if (!multipart_form_data_parser.is_valid()) {
                res.status = 400;
                return false;
            }
        }

        return true;
    }

    bool Server::handle_file_request(const httplib::Request& req, httplib::Response& res,
        bool head) {
        for (const auto& entry : base_dirs_) {
            // Prefix match
            if (!req.path.compare(0, entry.mount_point.size(), entry.mount_point)) {
                std::string sub_path = "/" + req.path.substr(entry.mount_point.size());
                if (httplib::detail::is_valid_path(sub_path)) {
                    auto path = entry.base_dir + sub_path;
                    if (path.back() == '/') { path += "index.html"; }

                    if (httplib::detail::is_file(path)) {
                        httplib::detail::read_file(path, res.body);
                        auto type =
                            httplib::detail::find_content_type(path, file_extension_and_mimetype_map_);
                        if (type) { res.set_header("Content-Type", type); }
                        for (const auto& kv : entry.headers) {
                            res.set_header(kv.first.c_str(), kv.second);
                        }
                        res.status = req.has_header("Range") ? 206 : 200;
                        if (!head && file_request_handler_) {
                            file_request_handler_(req, res);
                        }
                        return true;
                    }
                }
            }
        }
        return false;
    }

    socket_t
        Server::create_server_socket(const std::string& host, int port,
            int socket_flags,
            httplib::SocketOptions socket_options) const {
        return httplib::detail::create_socket(
            host, std::string(), port, address_family_, socket_flags, tcp_nodelay_,
            std::move(socket_options),
            [](socket_t sock, struct addrinfo& ai) -> bool {
                if (::bind(sock, ai.ai_addr, static_cast<socklen_t>(ai.ai_addrlen))) {
                    return false;
                }
                if (::listen(sock, CPPHTTPLIB_LISTEN_BACKLOG)) { return false; }
                return true;
            });
    }

    int Server::bind_internal(const std::string& host, int port,
        int socket_flags) {
        if (!is_valid()) { return -1; }

        svr_sock_ = create_server_socket(host, port, socket_flags, socket_options_);
        if (svr_sock_ == INVALID_SOCKET) { return -1; }

        if (port == 0) {
            struct sockaddr_storage addr;
            socklen_t addr_len = sizeof(addr);
            if (getsockname(svr_sock_, reinterpret_cast<struct sockaddr*>(&addr),
                &addr_len) == -1) {
                return -1;
            }
            if (addr.ss_family == AF_INET) {
                return ntohs(reinterpret_cast<struct sockaddr_in*>(&addr)->sin_port);
            }
            else if (addr.ss_family == AF_INET6) {
                return ntohs(reinterpret_cast<struct sockaddr_in6*>(&addr)->sin6_port);
            }
            else {
                return -1;
            }
        }
        else {
            return port;
        }
    }

    bool Server::listen_internal() {
        auto ret = true;
        is_running_ = true;

        {
            std::unique_ptr<httplib::TaskQueue> task_queue(new_task_queue());

            while (svr_sock_ != INVALID_SOCKET) {
#ifndef _WIN32
                if (idle_interval_sec_ > 0 || idle_interval_usec_ > 0) {
#endif
                    auto val = httplib::detail::select_read(svr_sock_, idle_interval_sec_,
                        idle_interval_usec_);
                    if (val == 0) { // Timeout
                        task_queue->on_idle();
                        continue;
                    }
#ifndef _WIN32
                }
#endif
                socket_t sock = accept(svr_sock_, nullptr, nullptr);

                if (sock == INVALID_SOCKET) {
                    if (errno == EMFILE) {
                        // The per-process limit of open file descriptors has been reached.
                        // Try to accept new connections after a short sleep.
                        std::this_thread::sleep_for(std::chrono::milliseconds(1));
                        continue;
                    }
                    if (svr_sock_ != INVALID_SOCKET) {
                        httplib::detail::close_socket(svr_sock_);
                        ret = false;
                    }
                    else {
                        ; // The server socket was closed by user.
                    }
                    break;
                }

                {
#ifdef _WIN32
                    auto timeout = static_cast<uint32_t>(read_timeout_sec_ * 1000 +
                        read_timeout_usec_ / 1000);
                    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout,
                        sizeof(timeout));
#else
                    timeval tv;
                    tv.tv_sec = static_cast<long>(read_timeout_sec_);
                    tv.tv_usec = static_cast<decltype(tv.tv_usec)>(read_timeout_usec_);
                    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));
#endif
                }
                {

#ifdef _WIN32
                    auto timeout = static_cast<uint32_t>(write_timeout_sec_ * 1000 +
                        write_timeout_usec_ / 1000);
                    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout,
                        sizeof(timeout));
#else
                    timeval tv;
                    tv.tv_sec = static_cast<long>(write_timeout_sec_);
                    tv.tv_usec = static_cast<decltype(tv.tv_usec)>(write_timeout_usec_);
                    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&tv, sizeof(tv));
#endif
                }

#if __cplusplus > 201703L
                task_queue->enqueue([=, this]() { process_and_close_socket(sock); });
#else
                task_queue->enqueue([=]() { process_and_close_socket(sock); });
#endif
            }

            task_queue->shutdown();
        }

        is_running_ = false;
        return ret;
    }

    bool Server::routing(httplib::Request& req, httplib::Response& res, httplib::Stream& strm) {
        if (pre_routing_handler_ &&
            pre_routing_handler_(req, res) == HandlerResponse::Handled) {
            return true;
        }

        // File handler
        bool is_head_request = req.method == "HEAD";
        if ((req.method == "GET" || is_head_request) &&
            handle_file_request(req, res, is_head_request)) {
            return true;
        }

        if (httplib::detail::expect_content(req)) {
            // Content reader handler
            {
                httplib::ContentReader reader(
                    [&](httplib::ContentReceiver receiver) {
                        return read_content_with_content_receiver(
                            strm, req, res, std::move(receiver), nullptr, nullptr);
                    },
                    [&](httplib::MultipartContentHeader header, httplib::ContentReceiver receiver) {
                        return read_content_with_content_receiver(strm, req, res, nullptr,
                            std::move(header),
                            std::move(receiver));
                    });

                if (req.method == "POST") {
                    if (dispatch_request_for_content_reader(
                        req, res, std::move(reader),
                        post_handlers_for_content_reader_)) {
                        return true;
                    }
                }
                else if (req.method == "PUT") {
                    if (dispatch_request_for_content_reader(
                        req, res, std::move(reader),
                        put_handlers_for_content_reader_)) {
                        return true;
                    }
                }
                else if (req.method == "PATCH") {
                    if (dispatch_request_for_content_reader(
                        req, res, std::move(reader),
                        patch_handlers_for_content_reader_)) {
                        return true;
                    }
                }
                else if (req.method == "DELETE") {
                    if (dispatch_request_for_content_reader(
                        req, res, std::move(reader),
                        delete_handlers_for_content_reader_)) {
                        return true;
                    }
                }
            }

            // Read content into `req.body`
            if (!read_content(strm, req, res)) { return false; }
        }

        // Regular handler
        if (req.method == "GET" || req.method == "HEAD") {
            return dispatch_request(req, res, get_handlers_);
        }
        else if (req.method == "POST") {
            return dispatch_request(req, res, post_handlers_);
        }
        else if (req.method == "PUT") {
            return dispatch_request(req, res, put_handlers_);
        }
        else if (req.method == "DELETE") {
            return dispatch_request(req, res, delete_handlers_);
        }
        else if (req.method == "OPTIONS") {
            return dispatch_request(req, res, options_handlers_);
        }
        else if (req.method == "PATCH") {
            return dispatch_request(req, res, patch_handlers_);
        }

        res.status = 400;
        return false;
    }

    bool Server::dispatch_request(httplib::Request& req, httplib::Response& res,
        const Handlers& handlers) {
        for (const auto& x : handlers) {
            const auto& pattern = x.first;
            const auto& handler = x.second;

            if (std::regex_match(req.path, req.matches, pattern)) {
                handler(req, res);
                return true;
            }
        }
        return false;
    }

    void Server::apply_ranges(const httplib::Request& req, httplib::Response& res,
        std::string& content_type,
        std::string& boundary) {
        if (req.ranges.size() > 1) {
            boundary = httplib::detail::make_multipart_data_boundary();

            auto it = res.headers.find("Content-Type");
            if (it != res.headers.end()) {
                content_type = it->second;
                res.headers.erase(it);
            }

            res.headers.emplace("Content-Type",
                "multipart/byteranges; boundary=" + boundary);
        }

        auto type = httplib::detail::encoding_type(req, res);

        if (res.body.empty()) {
            if (res.content_length_ > 0) {
                size_t length = 0;
                if (req.ranges.empty()) {
                    length = res.content_length_;
                }
                else if (req.ranges.size() == 1) {
                    auto offsets =
                        httplib::detail::get_range_offset_and_length(req, res.content_length_, 0);
                    auto offset = offsets.first;
                    length = offsets.second;
                    auto content_range = httplib::detail::make_content_range_header_field(
                        offset, length, res.content_length_);
                    res.set_header("Content-Range", content_range);
                }
                else {
                    length = httplib::detail::get_multipart_ranges_data_length(req, res, boundary,
                        content_type);
                }
                res.set_header("Content-Length", std::to_string(length));
            }
            else {
                if (res.content_provider_) {
                    if (res.is_chunked_content_provider_) {
                        res.set_header("Transfer-Encoding", "chunked");
                        if (type == httplib::detail::EncodingType::Gzip) {
                            res.set_header("Content-Encoding", "gzip");
                        }
                        else if (type == httplib::detail::EncodingType::Brotli) {
                            res.set_header("Content-Encoding", "br");
                        }
                    }
                }
            }
        }
        else {
            if (req.ranges.empty()) {
                ;
            }
            else if (req.ranges.size() == 1) {
                auto offsets =
                    httplib::detail::get_range_offset_and_length(req, res.body.size(), 0);
                auto offset = offsets.first;
                auto length = offsets.second;
                auto content_range = httplib::detail::make_content_range_header_field(
                    offset, length, res.body.size());
                res.set_header("Content-Range", content_range);
                if (offset < res.body.size()) {
                    res.body = res.body.substr(offset, length);
                }
                else {
                    res.body.clear();
                    res.status = 416;
                }
            }
            else {
                std::string data;
                if (httplib::detail::make_multipart_ranges_data(req, res, boundary, content_type,
                    data)) {
                    res.body.swap(data);
                }
                else {
                    res.body.clear();
                    res.status = 416;
                }
            }

            if (type != httplib::detail::EncodingType::None) {
                std::unique_ptr<httplib::detail::compressor> compressor;
                std::string content_encoding;

                if (type == httplib::detail::EncodingType::Gzip) {
#ifdef CPPHTTPLIB_ZLIB_SUPPORT
                    compressor = httplib::detail::make_unique<httplib::detail::gzip_compressor>();
                    content_encoding = "gzip";
#endif
                }
                else if (type == httplib::detail::EncodingType::Brotli) {
#ifdef CPPHTTPLIB_BROTLI_SUPPORT
                    compressor = httplib::detail::make_unique<httplib::detail::brotli_compressor>();
                    content_encoding = "br";
#endif
                }

                if (compressor) {
                    std::string compressed;
                    if (compressor->compress(res.body.data(), res.body.size(), true,
                        [&](const char* data, size_t data_len) {
                            compressed.append(data, data_len);
                            return true;
                        })) {
                        res.body.swap(compressed);
                        res.set_header("Content-Encoding", content_encoding);
                    }
                }
            }

            auto length = std::to_string(res.body.size());
            res.set_header("Content-Length", length);
        }
    }

    bool Server::dispatch_request_for_content_reader(
        httplib::Request& req, httplib::Response& res, httplib::ContentReader content_reader,
        const HandlersForContentReader& handlers) {
        for (const auto& x : handlers) {
            const auto& pattern = x.first;
            const auto& handler = x.second;

            if (std::regex_match(req.path, req.matches, pattern)) {
                handler(req, res, content_reader);
                return true;
            }
        }
        return false;
    }

    bool
        Server::process_request(httplib::Stream& strm, bool close_connection,
            bool& connection_closed,
            const std::function<void(httplib::Request&)>& setup_request) {
        std::array<char, 2048> buf{};

        httplib::detail::stream_line_reader line_reader(strm, buf.data(), buf.size());

        // Connection has been closed on client
        if (!line_reader.getline()) { return false; }

        httplib::Request req;
        httplib::Response res;

        res.version = "HTTP/1.1";

        for (const auto& header : default_headers_) {
            if (res.headers.find(header.first) == res.headers.end()) {
                res.headers.insert(header);
            }
        }

#ifdef _WIN32
        // TODO: Increase FD_SETSIZE statically (libzmq), dynamically (MySQL).
#else
#ifndef CPPHTTPLIB_USE_POLL
        // Socket file descriptor exceeded FD_SETSIZE...
        if (strm.socket() >= FD_SETSIZE) {
            httplib::Headers dummy;
            httplib::detail::read_headers(strm, dummy);
            res.status = 500;
            return write_response(strm, close_connection, req, res);
        }
#endif
#endif

        // Check if the request URI doesn't exceed the limit
        if (line_reader.size() > CPPHTTPLIB_REQUEST_URI_MAX_LENGTH) {
            httplib::Headers dummy;
            httplib::detail::read_headers(strm, dummy);
            res.status = 414;
            return write_response(strm, close_connection, req, res);
        }

        // httplib::Request line and headers
        if (!parse_request_line(line_reader.ptr(), req) ||
            !httplib::detail::read_headers(strm, req.headers)) {
            res.status = 400;
            return write_response(strm, close_connection, req, res);
        }

        if (req.get_header_value("Connection") == "close") {
            connection_closed = true;
        }

        if (req.version == "HTTP/1.0" &&
            req.get_header_value("Connection") != "Keep-Alive") {
            connection_closed = true;
        }

        strm.get_remote_ip_and_port(req.remote_addr, req.remote_port);
        req.set_header("REMOTE_ADDR", req.remote_addr);
        req.set_header("REMOTE_PORT", std::to_string(req.remote_port));

        if (req.has_header("Range")) {
            const auto& range_header_value = req.get_header_value("Range");
            if (!httplib::detail::parse_range_header(range_header_value, req.ranges)) {
                res.status = 416;
                return write_response(strm, close_connection, req, res);
            }
        }

        if (setup_request) { setup_request(req); }

        if (req.get_header_value("Expect") == "100-continue") {
            auto status = 100;
            if (expect_100_continue_handler_) {
                status = expect_100_continue_handler_(req, res);
            }
            switch (status) {
            case 100:
            case 417:
                strm.write_format("HTTP/1.1 %d %s\r\n\r\n", status,
                    httplib::detail::status_message(status));
                break;
            default: return write_response(strm, close_connection, req, res);
            }
        }

        // Rounting
        bool routed = false;
#ifdef CPPHTTPLIB_NO_EXCEPTIONS
        routed = routing(req, res, strm);
#else
        try {
            routed = routing(req, res, strm);
        }
        catch (std::exception& e) {
            if (exception_handler_) {
                auto ep = std::current_exception();
                exception_handler_(req, res, ep);
                routed = true;
            }
            else {
                res.status = 500;
                res.set_header("EXCEPTION_WHAT", e.what());
            }
        }
        catch (...) {
            if (exception_handler_) {
                auto ep = std::current_exception();
                exception_handler_(req, res, ep);
                routed = true;
            }
            else {
                res.status = 500;
                res.set_header("EXCEPTION_WHAT", "UNKNOWN");
            }
        }
#endif

        if (routed) {
            if (res.status == -1) { res.status = req.ranges.empty() ? 200 : 206; }
            return write_response_with_content(strm, close_connection, req, res);
        }
        else {
            if (res.status == -1) { res.status = 404; }
            return write_response(strm, close_connection, req, res);
        }
    }

    bool Server::is_valid() const { return true; }

    bool Server::process_and_close_socket(socket_t sock) {
        auto ret = httplib::detail::process_server_socket(
            svr_sock_, sock, keep_alive_max_count_, keep_alive_timeout_sec_,
            read_timeout_sec_, read_timeout_usec_, write_timeout_sec_,
            write_timeout_usec_,
            [this](httplib::Stream& strm, bool close_connection, bool& connection_closed) {
                return process_request(strm, close_connection, connection_closed,
                    nullptr);
            });
        httplib::detail::shutdown_socket(sock);
        httplib::detail::close_socket(sock);
        return ret;
    }
} // namespace HTTP