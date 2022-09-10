#pragma once

#include "../lib.h"

namespace HTTP {
    class Server {
    public:
        using Handler = std::function<void(const httplib::Request&, httplib::Response&)>;

        using ExceptionHandler =
            std::function<void(const httplib::Request&, httplib::Response&, std::exception_ptr ep)>;

        enum class HandlerResponse {
            Handled,
            Unhandled,
        };
        using HandlerWithResponse =
            std::function<HandlerResponse(const httplib::Request&, httplib::Response&)>;

        using HandlerWithContentReader = std::function<void(
            const httplib::Request&, httplib::Response&, const httplib::ContentReader& content_reader)>;

        using Expect100ContinueHandler =
            std::function<int(const httplib::Request&, httplib::Response&)>;

        Server();

        virtual ~Server() {};

        virtual bool is_valid() const;

        Server& Get(const std::string& pattern, Handler handler);
        Server& Post(const std::string& pattern, Handler handler);
        Server& Post(const std::string& pattern, HandlerWithContentReader handler);
        Server& Put(const std::string& pattern, Handler handler);
        Server& Put(const std::string& pattern, HandlerWithContentReader handler);
        Server& Patch(const std::string& pattern, Handler handler);
        Server& Patch(const std::string& pattern, HandlerWithContentReader handler);
        Server& Delete(const std::string& pattern, Handler handler);
        Server& Delete(const std::string& pattern, HandlerWithContentReader handler);
        Server& Options(const std::string& pattern, Handler handler);

        bool set_base_dir(const std::string& dir,
            const std::string& mount_point = std::string());
        bool set_mount_point(const std::string& mount_point, const std::string& dir,
            httplib::Headers headers = httplib::Headers());
        bool remove_mount_point(const std::string& mount_point);
        Server& set_file_extension_and_mimetype_mapping(const std::string& ext,
            const std::string& mime);
        Server& set_file_request_handler(Handler handler);

        Server& set_error_handler(HandlerWithResponse handler);
        Server& set_error_handler(Handler handler);
        Server& set_exception_handler(ExceptionHandler handler);
        Server& set_pre_routing_handler(HandlerWithResponse handler);
        Server& set_post_routing_handler(Handler handler);

        Server& set_expect_100_continue_handler(Expect100ContinueHandler handler);
        Server& set_logger(httplib::Logger logger);

        Server& set_address_family(int family);
        Server& set_tcp_nodelay(bool on);
        Server& set_socket_options(httplib::SocketOptions socket_options);

        Server& set_default_headers(httplib::Headers headers);

        Server& set_keep_alive_max_count(size_t count);
        Server& set_keep_alive_timeout(time_t sec);

        Server& set_read_timeout(time_t sec, time_t usec = 0);
        template <class Rep, class Period>
        Server& set_read_timeout(const std::chrono::duration<Rep, Period>& duration);

        Server& set_write_timeout(time_t sec, time_t usec = 0);
        template <class Rep, class Period>
        Server& set_write_timeout(const std::chrono::duration<Rep, Period>& duration);

        Server& set_idle_interval(time_t sec, time_t usec = 0);
        template <class Rep, class Period>
        Server& set_idle_interval(const std::chrono::duration<Rep, Period>& duration);

        Server& set_payload_max_length(size_t length);

        bool bind_to_port(const std::string& host, int port, int socket_flags = 0);
        int bind_to_any_port(const std::string& host, int socket_flags = 0);
        bool listen_after_bind();

        bool listen(const std::string& host, int port, int socket_flags = 0);

        bool is_running() const;
        void stop();

        std::function<httplib::TaskQueue* (void)> new_task_queue;

    protected:
        bool process_request(httplib::Stream& strm, bool close_connection,
            bool& connection_closed,
            const std::function<void(httplib::Request&)>& setup_request);

        std::atomic<socket_t> svr_sock_;
        size_t keep_alive_max_count_ = CPPHTTPLIB_KEEPALIVE_MAX_COUNT;
        time_t keep_alive_timeout_sec_ = CPPHTTPLIB_KEEPALIVE_TIMEOUT_SECOND;
        time_t read_timeout_sec_ = CPPHTTPLIB_READ_TIMEOUT_SECOND;
        time_t read_timeout_usec_ = CPPHTTPLIB_READ_TIMEOUT_USECOND;
        time_t write_timeout_sec_ = CPPHTTPLIB_WRITE_TIMEOUT_SECOND;
        time_t write_timeout_usec_ = CPPHTTPLIB_WRITE_TIMEOUT_USECOND;
        time_t idle_interval_sec_ = CPPHTTPLIB_IDLE_INTERVAL_SECOND;
        time_t idle_interval_usec_ = CPPHTTPLIB_IDLE_INTERVAL_USECOND;
        size_t payload_max_length_ = CPPHTTPLIB_PAYLOAD_MAX_LENGTH;

    private:
        using Handlers = std::vector<std::pair<std::regex, Handler>>;
        using HandlersForContentReader =
            std::vector<std::pair<std::regex, HandlerWithContentReader>>;

        socket_t create_server_socket(const std::string& host, int port,
            int socket_flags,
            httplib::SocketOptions socket_options) const;
        int bind_internal(const std::string& host, int port, int socket_flags);
        bool listen_internal();

        bool routing(httplib::Request& req, httplib::Response& res, httplib::Stream& strm);
        bool handle_file_request(const httplib::Request& req, httplib::Response& res,
            bool head = false);
        bool dispatch_request(httplib::Request& req, httplib::Response& res, const Handlers& handlers);
        bool
            dispatch_request_for_content_reader(httplib::Request& req, httplib::Response& res,
                httplib::ContentReader content_reader,
                const HandlersForContentReader& handlers);

        bool parse_request_line(const char* s, httplib::Request& req);
        void apply_ranges(const httplib::Request& req, httplib::Response& res,
            std::string& content_type, std::string& boundary);
        bool write_response(httplib::Stream& strm, bool close_connection, const httplib::Request& req,
            httplib::Response& res);
        bool write_response_with_content(httplib::Stream& strm, bool close_connection,
            const httplib::Request& req, httplib::Response& res);
        bool write_response_core(httplib::Stream& strm, bool close_connection,
            const httplib::Request& req, httplib::Response& res,
            bool need_apply_ranges);
        bool write_content_with_provider(httplib::Stream& strm, const httplib::Request& req,
            httplib::Response& res, const std::string& boundary,
            const std::string& content_type);
        bool read_content(httplib::Stream& strm, httplib::Request& req, httplib::Response& res);
        bool
            read_content_with_content_receiver(httplib::Stream& strm, httplib::Request& req, httplib::Response& res,
                httplib::ContentReceiver receiver,
                httplib::MultipartContentHeader multipart_header,
                httplib::ContentReceiver multipart_receiver);
        bool read_content_core(httplib::Stream& strm, httplib::Request& req, httplib::Response& res,
            httplib::ContentReceiver receiver,
            httplib::MultipartContentHeader mulitpart_header,
            httplib::ContentReceiver multipart_receiver);

        virtual bool process_and_close_socket(socket_t sock);

        struct MountPointEntry {
            std::string mount_point;
            std::string base_dir;
            httplib::Headers headers;
        };
        std::vector<MountPointEntry> base_dirs_;

        std::atomic<bool> is_running_;
        std::map<std::string, std::string> file_extension_and_mimetype_map_;
        Handler file_request_handler_;
        Handlers get_handlers_;
        Handlers post_handlers_;
        HandlersForContentReader post_handlers_for_content_reader_;
        Handlers put_handlers_;
        HandlersForContentReader put_handlers_for_content_reader_;
        Handlers patch_handlers_;
        HandlersForContentReader patch_handlers_for_content_reader_;
        Handlers delete_handlers_;
        HandlersForContentReader delete_handlers_for_content_reader_;
        Handlers options_handlers_;
        HandlerWithResponse error_handler_;
        ExceptionHandler exception_handler_;
        HandlerWithResponse pre_routing_handler_;
        Handler post_routing_handler_;
        httplib::Logger logger_;
        Expect100ContinueHandler expect_100_continue_handler_;

        int address_family_ = AF_UNSPEC;
        bool tcp_nodelay_ = CPPHTTPLIB_TCP_NODELAY;
        httplib::SocketOptions socket_options_ = httplib::default_socket_options;

        httplib::Headers default_headers_;
    };
} // namespace HTTP