#pragma once

#include "../lib.h"

using namespace httplib;

namespace HTTP
{
    class ClientImpl {
    public:
        explicit ClientImpl(const std::string& host);

        explicit ClientImpl(const std::string& host, int port);

        explicit ClientImpl(const std::string& host, int port,
            const std::string& client_cert_path,
            const std::string& client_key_path);

        virtual ~ClientImpl();

        virtual bool is_valid() const;

        Result Get(const std::string& path);
        Result Get(const std::string& path, const Headers& headers);
        Result Get(const std::string& path, Progress progress);
        Result Get(const std::string& path, const Headers& headers,
            Progress progress);
        Result Get(const std::string& path, ContentReceiver content_receiver);
        Result Get(const std::string& path, const Headers& headers,
            ContentReceiver content_receiver);
        Result Get(const std::string& path, ContentReceiver content_receiver,
            Progress progress);
        Result Get(const std::string& path, const Headers& headers,
            ContentReceiver content_receiver, Progress progress);
        Result Get(const std::string& path, ResponseHandler response_handler,
            ContentReceiver content_receiver);
        Result Get(const std::string& path, const Headers& headers,
            ResponseHandler response_handler,
            ContentReceiver content_receiver);
        Result Get(const std::string& path, ResponseHandler response_handler,
            ContentReceiver content_receiver, Progress progress);
        Result Get(const std::string& path, const Headers& headers,
            ResponseHandler response_handler, ContentReceiver content_receiver,
            Progress progress);

        Result Get(const std::string& path, const Params& params,
            const Headers& headers, Progress progress = nullptr);
        Result Get(const std::string& path, const Params& params,
            const Headers& headers, ContentReceiver content_receiver,
            Progress progress = nullptr);
        Result Get(const std::string& path, const Params& params,
            const Headers& headers, ResponseHandler response_handler,
            ContentReceiver content_receiver, Progress progress = nullptr);

        Result Head(const std::string& path);
        Result Head(const std::string& path, const Headers& headers);

        Result Post(const std::string& path);
        Result Post(const std::string& path, const char* body, size_t content_length,
            const std::string& content_type);
        Result Post(const std::string& path, const Headers& headers, const char* body,
            size_t content_length, const std::string& content_type);
        Result Post(const std::string& path, const std::string& body,
            const std::string& content_type);
        Result Post(const std::string& path, const Headers& headers,
            const std::string& body, const std::string& content_type);
        Result Post(const std::string& path, size_t content_length,
            ContentProvider content_provider,
            const std::string& content_type);
        Result Post(const std::string& path,
            ContentProviderWithoutLength content_provider,
            const std::string& content_type);
        Result Post(const std::string& path, const Headers& headers,
            size_t content_length, ContentProvider content_provider,
            const std::string& content_type);
        Result Post(const std::string& path, const Headers& headers,
            ContentProviderWithoutLength content_provider,
            const std::string& content_type);
        Result Post(const std::string& path, const Params& params);
        Result Post(const std::string& path, const Headers& headers,
            const Params& params);
        Result Post(const std::string& path, const MultipartFormDataItems& items);
        Result Post(const std::string& path, const Headers& headers,
            const MultipartFormDataItems& items);
        Result Post(const std::string& path, const Headers& headers,
            const MultipartFormDataItems& items, const std::string& boundary);

        Result Put(const std::string& path);
        Result Put(const std::string& path, const char* body, size_t content_length,
            const std::string& content_type);
        Result Put(const std::string& path, const Headers& headers, const char* body,
            size_t content_length, const std::string& content_type);
        Result Put(const std::string& path, const std::string& body,
            const std::string& content_type);
        Result Put(const std::string& path, const Headers& headers,
            const std::string& body, const std::string& content_type);
        Result Put(const std::string& path, size_t content_length,
            ContentProvider content_provider, const std::string& content_type);
        Result Put(const std::string& path,
            ContentProviderWithoutLength content_provider,
            const std::string& content_type);
        Result Put(const std::string& path, const Headers& headers,
            size_t content_length, ContentProvider content_provider,
            const std::string& content_type);
        Result Put(const std::string& path, const Headers& headers,
            ContentProviderWithoutLength content_provider,
            const std::string& content_type);
        Result Put(const std::string& path, const Params& params);
        Result Put(const std::string& path, const Headers& headers,
            const Params& params);
        Result Put(const std::string& path, const MultipartFormDataItems& items);
        Result Put(const std::string& path, const Headers& headers,
            const MultipartFormDataItems& items);
        Result Put(const std::string& path, const Headers& headers,
            const MultipartFormDataItems& items, const std::string& boundary);

        Result Patch(const std::string& path);
        Result Patch(const std::string& path, const char* body, size_t content_length,
            const std::string& content_type);
        Result Patch(const std::string& path, const Headers& headers,
            const char* body, size_t content_length,
            const std::string& content_type);
        Result Patch(const std::string& path, const std::string& body,
            const std::string& content_type);
        Result Patch(const std::string& path, const Headers& headers,
            const std::string& body, const std::string& content_type);
        Result Patch(const std::string& path, size_t content_length,
            ContentProvider content_provider,
            const std::string& content_type);
        Result Patch(const std::string& path,
            ContentProviderWithoutLength content_provider,
            const std::string& content_type);
        Result Patch(const std::string& path, const Headers& headers,
            size_t content_length, ContentProvider content_provider,
            const std::string& content_type);
        Result Patch(const std::string& path, const Headers& headers,
            ContentProviderWithoutLength content_provider,
            const std::string& content_type);

        Result Delete(const std::string& path);
        Result Delete(const std::string& path, const Headers& headers);
        Result Delete(const std::string& path, const char* body,
            size_t content_length, const std::string& content_type);
        Result Delete(const std::string& path, const Headers& headers,
            const char* body, size_t content_length,
            const std::string& content_type);
        Result Delete(const std::string& path, const std::string& body,
            const std::string& content_type);
        Result Delete(const std::string& path, const Headers& headers,
            const std::string& body, const std::string& content_type);

        Result Options(const std::string& path);
        Result Options(const std::string& path, const Headers& headers);

        bool send(Request& req, Response& res, Error& error);
        Result send(const Request& req);

        size_t is_socket_open() const;

        socket_t socket() const;

        void stop();

        void set_hostname_addr_map(std::map<std::string, std::string> addr_map);

        void set_default_headers(Headers headers);

        void set_address_family(int family);
        void set_tcp_nodelay(bool on);
        void set_socket_options(SocketOptions socket_options);

        void set_connection_timeout(time_t sec, time_t usec = 0);
        template <class Rep, class Period>
        void
            set_connection_timeout(const std::chrono::duration<Rep, Period>& duration);

        void set_read_timeout(time_t sec, time_t usec = 0);
        template <class Rep, class Period>
        void set_read_timeout(const std::chrono::duration<Rep, Period>& duration);

        void set_write_timeout(time_t sec, time_t usec = 0);
        template <class Rep, class Period>
        void set_write_timeout(const std::chrono::duration<Rep, Period>& duration);

        void set_basic_auth(const std::string& username, const std::string& password);
        void set_bearer_token_auth(const std::string& token);
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        void set_digest_auth(const std::string& username,
            const std::string& password);
#endif

        void set_keep_alive(bool on);
        void set_follow_location(bool on);

        void set_url_encode(bool on);

        void set_compress(bool on);

        void set_decompress(bool on);

        void set_interface(const std::string& intf);

        void set_proxy(const std::string& host, int port);
        void set_proxy_basic_auth(const std::string& username,
            const std::string& password);
        void set_proxy_bearer_token_auth(const std::string& token);
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        void set_proxy_digest_auth(const std::string& username,
            const std::string& password);
#endif

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        void set_ca_cert_path(const std::string& ca_cert_file_path,
            const std::string& ca_cert_dir_path = std::string());
        void set_ca_cert_store(X509_STORE* ca_cert_store);
#endif

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        void enable_server_certificate_verification(bool enabled);
#endif

        void set_logger(Logger logger);

    protected:
        struct Socket {
            socket_t sock = INVALID_SOCKET;
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
            SSL* ssl = nullptr;
#endif

            bool is_open() const { return sock != INVALID_SOCKET; }
        };

        Result send_(Request&& req);

        virtual bool create_and_connect_socket(Socket& socket, Error& error);

        // All of:
        //   shutdown_ssl
        //   shutdown_socket
        //   close_socket
        // should ONLY be called when socket_mutex_ is locked.
        // Also, shutdown_ssl and close_socket should also NOT be called concurrently
        // with a DIFFERENT thread sending requests using that socket.
        virtual void shutdown_ssl(Socket& socket, bool shutdown_gracefully);
        void shutdown_socket(Socket& socket);
        void close_socket(Socket& socket);

        bool process_request(Stream& strm, Request& req, Response& res,
            bool close_connection, Error& error);

        bool write_content_with_provider(Stream& strm, const Request& req,
            Error& error);

        void copy_settings(const ClientImpl& rhs);

        // Socket endoint information
        const std::string host_;
        const int port_;
        const std::string host_and_port_;

        // Current open socket
        Socket socket_;
        mutable std::mutex socket_mutex_;
        std::recursive_mutex request_mutex_;

        // These are all protected under socket_mutex
        size_t socket_requests_in_flight_ = 0;
        std::thread::id socket_requests_are_from_thread_ = std::thread::id();
        bool socket_should_be_closed_when_request_is_done_ = false;

        // Hostname-IP map
        std::map<std::string, std::string> addr_map_;

        // Default headers
        Headers default_headers_;

        // Settings
        std::string client_cert_path_;
        std::string client_key_path_;

        time_t connection_timeout_sec_ = CPPHTTPLIB_CONNECTION_TIMEOUT_SECOND;
        time_t connection_timeout_usec_ = CPPHTTPLIB_CONNECTION_TIMEOUT_USECOND;
        time_t read_timeout_sec_ = CPPHTTPLIB_READ_TIMEOUT_SECOND;
        time_t read_timeout_usec_ = CPPHTTPLIB_READ_TIMEOUT_USECOND;
        time_t write_timeout_sec_ = CPPHTTPLIB_WRITE_TIMEOUT_SECOND;
        time_t write_timeout_usec_ = CPPHTTPLIB_WRITE_TIMEOUT_USECOND;

        std::string basic_auth_username_;
        std::string basic_auth_password_;
        std::string bearer_token_auth_token_;
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        std::string digest_auth_username_;
        std::string digest_auth_password_;
#endif

        bool keep_alive_ = false;
        bool follow_location_ = false;

        bool url_encode_ = true;

        int address_family_ = AF_UNSPEC;
        bool tcp_nodelay_ = CPPHTTPLIB_TCP_NODELAY;
        SocketOptions socket_options_ = nullptr;

        bool compress_ = false;
        bool decompress_ = true;

        std::string interface_;

        std::string proxy_host_;
        int proxy_port_ = -1;

        std::string proxy_basic_auth_username_;
        std::string proxy_basic_auth_password_;
        std::string proxy_bearer_token_auth_token_;
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        std::string proxy_digest_auth_username_;
        std::string proxy_digest_auth_password_;
#endif

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        std::string ca_cert_file_path_;
        std::string ca_cert_dir_path_;

        X509_STORE* ca_cert_store_ = nullptr;
#endif

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        bool server_certificate_verification_ = true;
#endif

        Logger logger_;

    private:
        socket_t create_client_socket(Error& error) const;
        bool read_response_line(Stream& strm, const Request& req, Response& res);
        bool write_request(Stream& strm, Request& req, bool close_connection,
            Error& error);
        bool redirect(Request& req, Response& res, Error& error);
        bool handle_request(Stream& strm, Request& req, Response& res,
            bool close_connection, Error& error);
        std::unique_ptr<Response> send_with_content_provider(
            Request& req, const char* body, size_t content_length,
            ContentProvider content_provider,
            ContentProviderWithoutLength content_provider_without_length,
            const std::string& content_type, Error& error);
        Result send_with_content_provider(
            const std::string& method, const std::string& path,
            const Headers& headers, const char* body, size_t content_length,
            ContentProvider content_provider,
            ContentProviderWithoutLength content_provider_without_length,
            const std::string& content_type);

        std::string adjust_host_string(const std::string& host) const;

        virtual bool process_socket(const Socket& socket,
            std::function<bool(Stream& strm)> callback);
        virtual bool is_ssl() const;
    };

    class Client {
    public:
        // Universal interface
        explicit Client(const std::string& scheme_host_port);

        explicit Client(const std::string& scheme_host_port,
            const std::string& client_cert_path,
            const std::string& client_key_path);

        // HTTP only interface
        explicit Client(const std::string& host, int port);

        explicit Client(const std::string& host, int port,
            const std::string& client_cert_path,
            const std::string& client_key_path);

        Client(Client&&) = default;

        ~Client();

        bool is_valid() const;

        Result Get(const std::string& path);
        Result Get(const std::string& path, const Headers& headers);
        Result Get(const std::string& path, Progress progress);
        Result Get(const std::string& path, const Headers& headers,
            Progress progress);
        Result Get(const std::string& path, ContentReceiver content_receiver);
        Result Get(const std::string& path, const Headers& headers,
            ContentReceiver content_receiver);
        Result Get(const std::string& path, ContentReceiver content_receiver,
            Progress progress);
        Result Get(const std::string& path, const Headers& headers,
            ContentReceiver content_receiver, Progress progress);
        Result Get(const std::string& path, ResponseHandler response_handler,
            ContentReceiver content_receiver);
        Result Get(const std::string& path, const Headers& headers,
            ResponseHandler response_handler,
            ContentReceiver content_receiver);
        Result Get(const std::string& path, const Headers& headers,
            ResponseHandler response_handler, ContentReceiver content_receiver,
            Progress progress);
        Result Get(const std::string& path, ResponseHandler response_handler,
            ContentReceiver content_receiver, Progress progress);

        Result Get(const std::string& path, const Params& params,
            const Headers& headers, Progress progress = nullptr);
        Result Get(const std::string& path, const Params& params,
            const Headers& headers, ContentReceiver content_receiver,
            Progress progress = nullptr);
        Result Get(const std::string& path, const Params& params,
            const Headers& headers, ResponseHandler response_handler,
            ContentReceiver content_receiver, Progress progress = nullptr);

        Result Head(const std::string& path);
        Result Head(const std::string& path, const Headers& headers);

        Result Post(const std::string& path);
        Result Post(const std::string& path, const char* body, size_t content_length,
            const std::string& content_type);
        Result Post(const std::string& path, const Headers& headers, const char* body,
            size_t content_length, const std::string& content_type);
        Result Post(const std::string& path, const std::string& body,
            const std::string& content_type);
        Result Post(const std::string& path, const Headers& headers,
            const std::string& body, const std::string& content_type);
        Result Post(const std::string& path, size_t content_length,
            ContentProvider content_provider,
            const std::string& content_type);
        Result Post(const std::string& path,
            ContentProviderWithoutLength content_provider,
            const std::string& content_type);
        Result Post(const std::string& path, const Headers& headers,
            size_t content_length, ContentProvider content_provider,
            const std::string& content_type);
        Result Post(const std::string& path, const Headers& headers,
            ContentProviderWithoutLength content_provider,
            const std::string& content_type);
        Result Post(const std::string& path, const Params& params);
        Result Post(const std::string& path, const Headers& headers,
            const Params& params);
        Result Post(const std::string& path, const MultipartFormDataItems& items);
        Result Post(const std::string& path, const Headers& headers,
            const MultipartFormDataItems& items);
        Result Post(const std::string& path, const Headers& headers,
            const MultipartFormDataItems& items, const std::string& boundary);
        Result Put(const std::string& path);
        Result Put(const std::string& path, const char* body, size_t content_length,
            const std::string& content_type);
        Result Put(const std::string& path, const Headers& headers, const char* body,
            size_t content_length, const std::string& content_type);
        Result Put(const std::string& path, const std::string& body,
            const std::string& content_type);
        Result Put(const std::string& path, const Headers& headers,
            const std::string& body, const std::string& content_type);
        Result Put(const std::string& path, size_t content_length,
            ContentProvider content_provider, const std::string& content_type);
        Result Put(const std::string& path,
            ContentProviderWithoutLength content_provider,
            const std::string& content_type);
        Result Put(const std::string& path, const Headers& headers,
            size_t content_length, ContentProvider content_provider,
            const std::string& content_type);
        Result Put(const std::string& path, const Headers& headers,
            ContentProviderWithoutLength content_provider,
            const std::string& content_type);
        Result Put(const std::string& path, const Params& params);
        Result Put(const std::string& path, const Headers& headers,
            const Params& params);
        Result Put(const std::string& path, const MultipartFormDataItems& items);
        Result Put(const std::string& path, const Headers& headers,
            const MultipartFormDataItems& items);
        Result Put(const std::string& path, const Headers& headers,
            const MultipartFormDataItems& items, const std::string& boundary);
        Result Patch(const std::string& path);
        Result Patch(const std::string& path, const char* body, size_t content_length,
            const std::string& content_type);
        Result Patch(const std::string& path, const Headers& headers,
            const char* body, size_t content_length,
            const std::string& content_type);
        Result Patch(const std::string& path, const std::string& body,
            const std::string& content_type);
        Result Patch(const std::string& path, const Headers& headers,
            const std::string& body, const std::string& content_type);
        Result Patch(const std::string& path, size_t content_length,
            ContentProvider content_provider,
            const std::string& content_type);
        Result Patch(const std::string& path,
            ContentProviderWithoutLength content_provider,
            const std::string& content_type);
        Result Patch(const std::string& path, const Headers& headers,
            size_t content_length, ContentProvider content_provider,
            const std::string& content_type);
        Result Patch(const std::string& path, const Headers& headers,
            ContentProviderWithoutLength content_provider,
            const std::string& content_type);

        Result Delete(const std::string& path);
        Result Delete(const std::string& path, const Headers& headers);
        Result Delete(const std::string& path, const char* body,
            size_t content_length, const std::string& content_type);
        Result Delete(const std::string& path, const Headers& headers,
            const char* body, size_t content_length,
            const std::string& content_type);
        Result Delete(const std::string& path, const std::string& body,
            const std::string& content_type);
        Result Delete(const std::string& path, const Headers& headers,
            const std::string& body, const std::string& content_type);

        Result Options(const std::string& path);
        Result Options(const std::string& path, const Headers& headers);

        bool send(Request& req, Response& res, Error& error);
        Result send(const Request& req);

        size_t is_socket_open() const;

        socket_t socket() const;

        void stop();

        void set_hostname_addr_map(std::map<std::string, std::string> addr_map);

        void set_default_headers(Headers headers);

        void set_address_family(int family);
        void set_tcp_nodelay(bool on);
        void set_socket_options(SocketOptions socket_options);

        void set_connection_timeout(time_t sec, time_t usec = 0);
        template <class Rep, class Period>
        void
            set_connection_timeout(const std::chrono::duration<Rep, Period>& duration);

        void set_read_timeout(time_t sec, time_t usec = 0);
        template <class Rep, class Period>
        void set_read_timeout(const std::chrono::duration<Rep, Period>& duration);

        void set_write_timeout(time_t sec, time_t usec = 0);
        template <class Rep, class Period>
        void set_write_timeout(const std::chrono::duration<Rep, Period>& duration);

        void set_basic_auth(const std::string& username, const std::string& password);
        void set_bearer_token_auth(const std::string& token);
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        void set_digest_auth(const std::string& username,
            const std::string& password);
#endif

        void set_keep_alive(bool on);
        void set_follow_location(bool on);

        void set_url_encode(bool on);

        void set_compress(bool on);

        void set_decompress(bool on);

        void set_interface(const std::string& intf);

        void set_proxy(const std::string& host, int port);
        void set_proxy_basic_auth(const std::string& username,
            const std::string& password);
        void set_proxy_bearer_token_auth(const std::string& token);
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        void set_proxy_digest_auth(const std::string& username,
            const std::string& password);
#endif

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        void enable_server_certificate_verification(bool enabled);
#endif

        void set_logger(Logger logger);

        // SSL
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        void set_ca_cert_path(const std::string& ca_cert_file_path,
            const std::string& ca_cert_dir_path = std::string());

        void set_ca_cert_store(X509_STORE* ca_cert_store);

        long get_openssl_verify_result() const;

        SSL_CTX* ssl_context() const;
#endif

    private:
        std::unique_ptr<ClientImpl> cli_;

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        bool is_ssl_ = false;
#endif
    };
} // namespace HTTP

