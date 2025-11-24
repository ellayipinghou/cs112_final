#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include <zlib.h>
#include <brotli/decode.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 32768
#define HTML_BUFFER_SIZE 262144

// phases describing proxy state machine
enum ReadPhase {
    // shared states
    READING_REQUEST,
    CONNECTING_TO_SERVER,
    FORWARDING_REQUEST,
    READING_RESPONSE_HEADER,
    READING_RESPONSE_BODY,

    // HTTPS states
    TLS_HANDSHAKE_SERVER,
    TLS_HANDSHAKE_CLIENT,
    HTTPS_TUNNEL
};

// state machine for parsing HTTP responses in HTTPS tunnel
enum TunnelState {
    TUNNEL_EXPECT_RESPONSE_HEADERS,
    TUNNEL_READING_RESPONSE_BODY_KNOWN_LENGTH,
    TUNNEL_READING_CHUNKED_RESPONSE,
    TUNNEL_PASSTHROUGH  // fallback, until connection closed
};

// represents a single client-server connection pair
struct Connection {
    int client_fd;
    int server_fd;

    SSL *client_ssl;
    SSL *server_ssl;
    SSL_CTX *client_ctx;
    SSL_CTX *server_ctx;
    char *hostname;
    char *target_port;

    char buf[BUFFER_SIZE];
    unsigned int offset;
    bool is_https;
    int content_length;
    int body_bytes_read;
    enum ReadPhase phase;
    bool header_injected;
    
    // tunnel parsing state
    enum TunnelState tunnel_state;
    int tunnel_body_remaining;  // bytes remaining in current response body
    char tunnel_buf[BUFFER_SIZE];
    int tunnel_buf_offset;

    // accumulating buffer for LLM
    char *LLM_buf;
    unsigned int html_offset;
    unsigned int LLM_buf_capacity;
    bool is_html;

    // for chunked decoding
    char *chunked_decode_buf;
    int chunked_decode_capacity;
    int chunked_decode_offset;
    bool is_compressed;
};

// global mapping from file descriptors to connections
struct Connection *fd_to_connection[FD_SETSIZE];

// function declarations
void buffer_append(struct Connection *conn, char *to_add, int len);
// void buffer_reserve(char *buf, size_t need);
void create_server_struct(struct sockaddr_in *server_addr, int listen_port);
struct Connection *Connection_create(int client_fd);
bool execute(int fd, fd_set *all_fds, X509 *ca_cert, EVP_PKEY *ca_key, int llm_fd);
bool read_request(int fd, fd_set *all_fds);
bool setup_get_request(int fd, char *host, char *port, char *path, fd_set *all_fds);
bool connect_to_server(int fd, fd_set *all_fds);
bool forward_request(int fd, fd_set *all_fds);
bool read_response_header(int fd, fd_set *all_fds, int llm_fd);
bool parse_response_header(char *header_buf, int *content_len, bool *is_chunked, bool *is_html, bool *is_compressed);
bool read_response_body(int fd, fd_set *all_fds, int llm_fd);
bool parse_request(char *req, bool *is_connect, char **host, char **port, char **path);
void close_connection(struct Connection **conn_ptr, fd_set *all_fds);
bool setup_connect_request(int fd, char *host, char *port, fd_set *all_fds);
X509 *load_ca_cert(char *path);
EVP_PKEY *load_ca_key(char *path);
X509 *generate_cert(char *hostname, X509 *ca_cert, EVP_PKEY *ca_key, EVP_PKEY **out_pkey);
bool handle_tls_handshake_client(int fd, fd_set *all_fds, X509 *ca_cert, EVP_PKEY *ca_key);
bool handle_tls_handshake_server(int fd, fd_set *all_fds);
int ssl_read_with_retry(SSL *ssl, void *buf, int num, bool *should_retry);
int ssl_write_with_retry(SSL *ssl, const void *buf, int num, bool *should_retry);
bool handle_https_tunnel(int fd, fd_set *all_fds, int llm_fd);
char *find_header_end(char *buf, int len);
int parse_chunk_size(char *buf, int len);
bool decompress_and_store(struct Connection *conn);
void send_and_reset_html(struct Connection *conn, int llm_fd);
int decode_chunked_data(char *input, int input_len, char **output, int *output_capacity);
bool send_to_llm(struct Connection *conn, int llm_port);
// int get_LLM_fd(); 

int main(int argc, char *argv[]) {
    assert(argc == 4);
    int listen_port = atoi(argv[1]);
    char *ca_cert_path = argv[2];
    char *ca_key_path = argv[3];

    // ignore SIGPIPE to prevent crashes on broken connections
    signal(SIGPIPE, SIG_IGN);

    // create listening socket
    int main_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (main_fd < 0) {
        perror("ERROR opening socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr;
    create_server_struct(&server_addr, listen_port);

    // allow socket reuse to avoid "address already in use" errors
    int optval = 1;
    setsockopt(main_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    if (bind(main_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        perror("ERROR on binding");
        return -1;
    }

    listen(main_fd, SOMAXCONN);
    printf("Listening on port %d\n", listen_port);

    // int llm_fd = get_LLM_fd();

    int llm_fd = -1;

    // initialize file descriptor set with listening socket
    fd_set all_fds;
    FD_ZERO(&all_fds);
    FD_SET(main_fd, &all_fds);
    // FD_SET(llm_fd, &all_fds);

    // initialize OpenSSL library
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // load CA certificate and key for HTTPS interception
    X509 *ca_cert = load_ca_cert(ca_cert_path);
    EVP_PKEY *ca_key = load_ca_key(ca_key_path);
    if (!ca_cert || !ca_key) {
        fprintf(stderr, "Failed to load CA certificate or key\n");
        exit(EXIT_FAILURE);
    }

    srand(time(NULL));

    // main event loop
    while (true) {
        fd_set read_fds = all_fds;
        fd_set write_fds;
        FD_ZERO(&write_fds);

        // determine which file descriptors need to be monitored for writing
        int max_fd = main_fd;
        for (int fd = 0; fd < FD_SETSIZE; fd++) {
            if (FD_ISSET(fd, &all_fds)) {
                if (fd > max_fd) max_fd = fd;
                struct Connection *conn = fd_to_connection[fd];
                if (!conn) continue;

                // monitor server connection for writability during connection phase
                if (conn->phase == CONNECTING_TO_SERVER && fd == conn->server_fd) {
                    FD_SET(fd, &write_fds);
                    FD_CLR(fd, &read_fds);
                }

                // monitor both directions for writability in HTTPS tunnel mode
                if (conn->phase == HTTPS_TUNNEL) {
                    if (fd == conn->client_fd && conn->server_fd != -1) {
                        FD_SET(fd, &write_fds);
                    } else if (fd == conn->server_fd && conn->client_fd != -1) {
                        FD_SET(fd, &write_fds);
                    }
                }

                // monitor server socket for writability when forwarding request
                if (conn->phase == FORWARDING_REQUEST && fd == conn->server_fd && conn->offset > 0) {
                    FD_SET(fd, &write_fds);
                    FD_CLR(fd, &read_fds);
                }
            }
        }

        // wait for I/O events
        int fd_ready = select(max_fd + 1, &read_fds, &write_fds, NULL, NULL);
        if (fd_ready <= 0) continue;

        // process write events first
        for (int fd = 0; fd <= max_fd; fd++) {
            if (fd < 0 || fd >= FD_SETSIZE) continue;

            if (FD_ISSET(fd, &write_fds)) {
                struct Connection *conn = fd_to_connection[fd];
                if (!conn) continue;
                
                bool success = execute(fd, &all_fds, ca_cert, ca_key, llm_fd);
                if (!success) {
                    conn = fd_to_connection[fd];
                    if (conn) {
                        close_connection(&conn, &all_fds);
                    } else {
                        FD_CLR(fd, &all_fds);
                    }
                    continue;
                }
            }

            // process read events
            if (FD_ISSET(fd, &read_fds)) {
                // handle new client connections
                if (fd == main_fd) {
                    struct sockaddr_in client_addr;
                    socklen_t client_len = sizeof(client_addr);

                    int client_fd = accept(fd, (struct sockaddr *)&client_addr, &client_len);
                    if (client_fd < 0) {
                        perror("Accept failed");
                        continue;
                    }

                    if (client_fd >= FD_SETSIZE) {
                        fprintf(stderr, "ERROR: Accepted fd=%d exceeds FD_SETSIZE\n", client_fd);
                        close(client_fd);
                        continue;
                    }

                    // clean up any stale connection using this fd
                    if (fd_to_connection[client_fd] != NULL) {
                        struct Connection *old_conn = fd_to_connection[client_fd];
                        close_connection(&old_conn, &all_fds);
                    }

                    FD_SET(client_fd, &all_fds);
                    struct Connection *new_conn = Connection_create(client_fd);
                    fd_to_connection[client_fd] = new_conn;
                    continue;
                }

                // handle existing connection
                struct Connection *conn = fd_to_connection[fd];
                if (!conn) continue;
                
                bool success = execute(fd, &all_fds, ca_cert, ca_key, llm_fd);
                if (!success) {
                    conn = fd_to_connection[fd];
                    if (conn) {
                        close_connection(&conn, &all_fds);
                    } else {
                        FD_CLR(fd, &all_fds);
                    }
                    continue;
                }
            }
        }
    }

    return 0;
}

bool send_to_llm(struct Connection *conn, int llm_port) {
    if (!conn->is_html || conn->html_offset == 0) {
        return true;
    }

    // Decompress if needed
    if (conn->is_compressed) {
        if (!decompress_and_store(conn)) {
            fprintf(stderr, "ERROR: Failed to decompress HTML\n");
            return false;
        }
    }
    
    // Create a NEW socket for EACH request
    int llm_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (llm_fd < 0) {
        perror("Failed to create LLM socket");
        return false;
    }
    
    // Connect to Flask (localhost:9450)
    struct sockaddr_in llm_addr;
    memset(&llm_addr, 0, sizeof(llm_addr));
    llm_addr.sin_family = AF_INET;
    llm_addr.sin_port = htons(llm_port);
    llm_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    
    if (connect(llm_fd, (struct sockaddr *)&llm_addr, sizeof(llm_addr)) < 0) {
        perror("Failed to connect to Flask");
        close(llm_fd);
        return false;
    }
    
    // Build JSON payload
    char json_payload[BUFFER_SIZE * 2];
    snprintf(json_payload, sizeof(json_payload),
             "{\"html\":\"%.*s\"}",
             conn->html_offset, conn->LLM_buf);
    
    // Build HTTP POST request
    char request[BUFFER_SIZE * 3];
    int content_len = strlen(json_payload);
    snprintf(request, sizeof(request),
             "POST /upload_html HTTP/1.1\r\n"
             "Host: 127.0.0.1:%d\r\n"
             "Client-FD: %d\r\n"
             "Content-Type: application/json\r\n"
             "Content-Length: %d\r\n"
             "Connection: close\r\n"
             "\r\n"
             "%s",
             llm_port, conn->client_fd, content_len, json_payload);
    
    // Send the request
    int sent = write(llm_fd, request, strlen(request));
    if (sent < 0) {
        perror("Failed to send to Flask");
        close(llm_fd);
        return false;
    }
    
    fprintf(stderr, "Sent %d bytes to Flask\n", sent);
    
    close(llm_fd);
    return true;
}

// int get_LLM_fd() {
//     // create listening socket
//     int llm_fd = socket(AF_INET, SOCK_STREAM, 0);
//     if (llm_fd < 0) {
//         perror("ERROR opening socket");
//         exit(EXIT_FAILURE);
//     }

//     struct sockaddr_in server_addr;
//     create_server_struct(&server_addr, 9450);

//     if (bind(llm_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
//         perror("ERROR on binding");
//         return -1;
//     }

//     return llm_fd;
// }

void buffer_append(struct Connection *conn, char *to_add, int len) {
    char *buf = conn->LLM_buf;

    if (len + conn->html_offset >= conn->LLM_buf_capacity) {
        // double until required capacity is reached
        int new_capacity = conn->LLM_buf_capacity;
        while (len + conn->html_offset >= conn->LLM_buf_capacity) {
            new_capacity *= 2;
        }

        // reallocate and copy
        unsigned char *tmp = realloc(buf, new_capacity);
        if (!tmp) {
            fprintf(stderr, "realloc failed\n");
            exit(EXIT_FAILURE);
        }  

        conn->LLM_buf_capacity = new_capacity;
        conn->LLM_buf = tmp;
    }

    memcpy(conn->LLM_buf + conn->html_offset, to_add, len);
    conn->html_offset += len;
}

// execute the appropriate handler based on connection phase
bool execute(int fd, fd_set *all_fds, X509 *ca_cert, EVP_PKEY *ca_key, int llm_fd) {
    struct Connection *conn = fd_to_connection[fd];
    if (!conn) return false;

    bool success;
    switch (conn->phase) {
        case READING_REQUEST:
            success = read_request(fd, all_fds);
            break;
        case CONNECTING_TO_SERVER:
            success = connect_to_server(fd, all_fds);
            break;
        case FORWARDING_REQUEST:
            success = forward_request(fd, all_fds);
            break;
        case READING_RESPONSE_HEADER:
            success = read_response_header(fd, all_fds, llm_fd);
            break;
        case READING_RESPONSE_BODY:
            success = read_response_body(fd, all_fds, llm_fd);
            break;
        case TLS_HANDSHAKE_CLIENT:
            success = handle_tls_handshake_client(fd, all_fds, ca_cert, ca_key);
            break;
        case TLS_HANDSHAKE_SERVER:
            success = handle_tls_handshake_server(fd, all_fds);
            break;
        case HTTPS_TUNNEL:
            success = handle_https_tunnel(fd, all_fds, llm_fd);
            break;
        default:
            fprintf(stderr, "Unknown phase for fd %d\n", fd);
            success = false;
            break;
    }

    return success;
}

// read HTTP request from client
bool read_request(int fd, fd_set *all_fds) {
    struct Connection *conn = fd_to_connection[fd];
    if (!conn) {
        FD_CLR(fd, all_fds);
        close(fd);
        return false;
    }

    // read from SSL or plain socket depending on connection type
    int n;
    if (conn->is_https) {
        bool should_retry;
        n = ssl_read_with_retry(conn->client_ssl, conn->buf + conn->offset,
                                BUFFER_SIZE - conn->offset, &should_retry);
        if (should_retry) return true;
    } else {
        n = read(fd, conn->buf + conn->offset, BUFFER_SIZE - conn->offset);
    }

    if (n <= 0) return false;

    conn->offset += n;
   
    // check if we have complete headers
    char *end_of_headers = strstr(conn->buf, "\r\n\r\n");
    if (!end_of_headers) return true;

    // null-terminate the request buffer
    if (conn->offset < BUFFER_SIZE) {
        conn->buf[conn->offset] = '\0';
    } else {
        return false;
    }

    // parse the HTTP request
    bool is_connect = false;
    char *host = NULL, *port = NULL, *path = NULL;
    bool success = parse_request(conn->buf, &is_connect, &host, &port, &path);

    // for HTTPS requests inside tunnel, extract target from request line
    if (conn->is_https && conn->hostname && !is_connect) {
        char method[16], target[512], version[16];
        if (sscanf(conn->buf, "%15s %511s %15s", method, target, version) == 3) {
            host = conn->hostname;
            port = conn->target_port;
            path = strdup(target);
            success = true;
            is_connect = false;
        }
    }

    if (!success) return false;

    // handle CONNECT requests (HTTPS) differently from GET requests (HTTP)
    if (is_connect) {
        conn->is_https = true;
        success = setup_connect_request(fd, host, port, all_fds);
    } else {
        success = setup_get_request(fd, host, port, path, all_fds);
    }

    return success;
}

// set up HTTPS tunnel for CONNECT requests
bool setup_connect_request(int fd, char *host, char *port, fd_set *all_fds) {
    struct Connection *conn = fd_to_connection[fd];
    if (!conn) return false;

    // save hostname and port for later use
    conn->hostname = strdup(host);
    conn->target_port = strdup(port);

    // send 200 Connection Established response
    char *response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    write(conn->client_fd, response, strlen(response));

    // prepare for TLS handshake with client
    conn->offset = 0;
    conn->phase = TLS_HANDSHAKE_CLIENT;
   
    return true;
}

// load CA certificate from file
X509 *load_ca_cert(char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        perror("ERROR: failed to open ca_cert path");
        return NULL;
    }

    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!cert) {
        ERR_print_errors_fp(stderr);
    }

    return cert;
}

// load CA private key from file
EVP_PKEY *load_ca_key(char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        perror("ERROR: failed to open ca_key path");
        return NULL;
    }

    EVP_PKEY *key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!key) {
        ERR_print_errors_fp(stderr);
    }

    return key;
}

// perform TLS handshake with client (proxy acts as server)
bool handle_tls_handshake_client(int fd, fd_set *all_fds, X509 *ca_cert, EVP_PKEY *ca_key) {
    struct Connection *conn = fd_to_connection[fd];
    if (!conn) return false;

    // initialize SSL context and certificate on first call
    if (!conn->client_ssl) {
        // generate certificate for target hostname
        EVP_PKEY *new_pkey = NULL;
        X509 *new_cert = generate_cert(conn->hostname, ca_cert, ca_key, &new_pkey);
        if (!new_cert || !new_pkey) return false;

        SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
        if (!ctx) {
            X509_free(new_cert);
            EVP_PKEY_free(new_pkey);
            return false;
        }

        // set ALPN protocol to HTTP/1.1
        const unsigned char alpn_proto[] = { 8, 'h','t','t','p','/','1','.','1' };
        SSL_CTX_set_alpn_protos(ctx, alpn_proto, sizeof(alpn_proto));

        SSL_CTX_set_security_level(ctx, 0);  // allow older/weaker crypto
        SSL_CTX_set_options(ctx, SSL_OP_LEGACY_SERVER_CONNECT);

        if (!SSL_CTX_use_certificate(ctx, new_cert) || !SSL_CTX_use_PrivateKey(ctx, new_pkey)) {
            SSL_CTX_free(ctx);
            X509_free(new_cert);
            EVP_PKEY_free(new_pkey);
            return false;
        }

        SSL *ssl = SSL_new(ctx);
        if (!ssl) {
            SSL_CTX_free(ctx);
            X509_free(new_cert);
            EVP_PKEY_free(new_pkey);
            return false;
        }
       
        // set socket to non-blocking mode
        fcntl(fd, F_SETFL, O_NONBLOCK);
        SSL_set_fd(ssl, fd);

        conn->client_ssl = ssl;
        conn->client_ctx = ctx;

        X509_free(new_cert);
        EVP_PKEY_free(new_pkey);
    }

    // perform SSL accept (non-blocking)
    int ret = SSL_accept(conn->client_ssl);
    if (ret <= 0) {
        int err = SSL_get_error(conn->client_ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            return true;
        }
        ERR_print_errors_fp(stderr);
        return false;
    }

    // if server SSL connection already established, enter tunnel mode
    if (conn->server_ssl) {
        conn->phase = HTTPS_TUNNEL;
        conn->tunnel_state = TUNNEL_EXPECT_RESPONSE_HEADERS;
        FD_SET(conn->server_fd, all_fds);
        return true;
    } else {
        conn->phase = TLS_HANDSHAKE_SERVER;
    }

    return true;
}

// dynamically generate certificate for hostname signed by CA
X509 *generate_cert(char *hostname, X509 *ca_cert, EVP_PKEY *ca_key, EVP_PKEY **out_pkey) {
    // generate RSA key pair
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    if (!rsa || !bn || !BN_set_word(bn, RSA_F4)) {
        RSA_free(rsa);
        BN_free(bn);
        return NULL;
    }
    if (RSA_generate_key_ex(rsa, 2048, bn, NULL) != 1) {
        RSA_free(rsa);
        BN_free(bn);
        return NULL;
    }
    BN_free(bn);

    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey || EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
        RSA_free(rsa);
        EVP_PKEY_free(pkey);
        return NULL;
    }

    // create X509 certificate structure
    X509 *x509 = X509_new();
    if (!x509) {
        EVP_PKEY_free(pkey);
        return NULL;
    }

    // set certificate properties
    X509_set_version(x509, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x509), (long)rand());
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 7L * 24 * 60 * 60);
    X509_set_pubkey(x509, pkey);

    // set subject name to hostname
    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)hostname, -1, -1, 0);
    X509_set_issuer_name(x509, X509_get_subject_name(ca_cert));

    // add subject alternative name (SAN) extension
    X509_EXTENSION *ext = NULL;
    char san_string[512];
    snprintf(san_string, sizeof(san_string), "DNS:%s", hostname);
   
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, ca_cert, x509, NULL, NULL, 0);
   
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_alt_name, san_string);
    if (!ext) {
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return NULL;
    }
   
    X509_add_ext(x509, ext, -1);
    X509_EXTENSION_free(ext);

    // sign certificate with CA key
    if (!X509_sign(x509, ca_key, EVP_sha256())) {
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return NULL;
    }

    *out_pkey = pkey;
    return x509;
}

// perform TLS handshake with server (proxy acts as client)
bool handle_tls_handshake_server(int fd, fd_set *all_fds) {
    struct Connection *conn = fd_to_connection[fd];
    if (!conn) return false;

    char *host = conn->hostname;
    char *port = conn->target_port;

    // create and connect socket to server if not already done
    if (conn->server_fd == -1) {
        int server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd < 0) return false;
       
        fcntl(server_fd, F_SETFL, O_NONBLOCK);
       
        struct hostent *server = gethostbyname(host);
        if (!server) {
            close(server_fd);
            return false;
        }

        struct sockaddr_in serv_addr;
        serv_addr.sin_family = AF_INET;
        memmove(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
        serv_addr.sin_port = htons(atoi(port));

        int result = connect(server_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
        if (result < 0 && errno != EINPROGRESS) {
            close(server_fd);
            return false;
        }

        conn->server_fd = server_fd;

        if (fd_to_connection[server_fd] != NULL && fd_to_connection[server_fd] != conn) {
            fd_to_connection[server_fd] = NULL;
        }

        fd_to_connection[server_fd] = conn;
        FD_SET(server_fd, all_fds);
       
        // if connection is still in progress, return and wait
        if (result < 0 && errno == EINPROGRESS) {
            return true;
        }
    }

    // initialize SSL connection to server
    if (!conn->server_ssl) {
        // check if socket connection has completed
        int err;
        socklen_t len = sizeof(err);
        if (getsockopt(conn->server_fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0) {
            return false;
        }
       
        if (err == EINPROGRESS || err == EALREADY) return true;
        if (err != 0) return false;

        SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) return false;

        SSL_CTX_set_security_level(ctx, 0);

        // set ALPN protocol to HTTP/1.1
        const unsigned char alpn_proto2[] = { 8, 'h','t','t','p','/','1','.','1' };
        SSL_CTX_set_alpn_protos(ctx, alpn_proto2, sizeof(alpn_proto2));

        SSL_CTX_set_default_verify_paths(ctx);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

        SSL *ssl = SSL_new(ctx);
        if (!ssl) {
            SSL_CTX_free(ctx);
            return false;
        }

        SSL_set_fd(ssl, conn->server_fd);
        SSL_set_tlsext_host_name(ssl, host);

        conn->server_ssl = ssl;
        conn->server_ctx = ctx;
    }

    // perform SSL connect (non-blocking)
    int ret = SSL_connect(conn->server_ssl);
    if (ret <= 0) {
        int err = SSL_get_error(conn->server_ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            return true;
        }
        return false;
    }

    // if client SSL connection already established, enter tunnel mode
    if (conn->client_ssl) {
        conn->phase = HTTPS_TUNNEL;
        conn->tunnel_state = TUNNEL_EXPECT_RESPONSE_HEADERS;
        FD_SET(conn->server_fd, all_fds);
        return true;
    } else {
        conn->phase = TLS_HANDSHAKE_CLIENT;
    }

    return true;
}

// set up connection to server for HTTP GET requests
bool setup_get_request(int fd, char *host, char *port, char *path, fd_set *all_fds) {
    struct Connection *conn = fd_to_connection[fd];
    if (!conn) return false;

    // for HTTPS requests in tunnel, server is already connected
    if (conn->is_https && conn->server_ssl) {
        conn->phase = FORWARDING_REQUEST;
        return true;
    }
   
    // create socket and connect to server
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) return false;
    
    struct hostent *server = gethostbyname(host);
    if (!server) {
        close(server_fd);
        return false;
    }

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    memmove(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    serv_addr.sin_port = htons(atoi(port));

    fcntl(server_fd, F_SETFL, O_NONBLOCK);

    int result = connect(server_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
   
    // determine next phase based on connection result
    if (result == 0) {
        conn->phase = FORWARDING_REQUEST;
    } else if (result < 0 && errno == EINPROGRESS) {
        conn->phase = CONNECTING_TO_SERVER;
    } else {
        close(server_fd);
        return false;
    }

    conn->server_fd = server_fd;

    if (fd_to_connection[server_fd] != NULL && fd_to_connection[server_fd] != conn) {
        fd_to_connection[server_fd] = NULL;
    }

    FD_SET(server_fd, all_fds);
    fd_to_connection[server_fd] = conn;
   
    // if connection completed immediately, forward request
    if (result == 0) {
        return forward_request(server_fd, all_fds);
    }
   
    return true;
}

// complete non-blocking connection to server
bool connect_to_server(int fd, fd_set *all_fds) {
    struct Connection *conn = fd_to_connection[fd];
    if (!conn) return false;

    // check if connection completed successfully
    int err;
    socklen_t len = sizeof(err);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err != 0) {
        return false;
    }

    // proceed to appropriate next phase
    if (!conn->is_https) {
        conn->phase = FORWARDING_REQUEST;
        return forward_request(fd, all_fds);
    } else {
        conn->phase = TLS_HANDSHAKE_SERVER;
    }

    return true;
}

// search for end of HTTP headers (\r\n\r\n)
char *find_header_end(char *buf, int len) {
    for (int i = 0; i <= len - 4; i++) {
        if (buf[i] == '\r' && buf[i+1] == '\n' &&
            buf[i+2] == '\r' && buf[i+3] == '\n') {
            return buf + i;
        }
    }
    return NULL;
}

// read HTTP response headers from server
bool read_response_header(int fd, fd_set *all_fds, int llm_fd) {
    struct Connection *conn = fd_to_connection[fd];
    if (!conn) return false;

    // read from SSL or plain socket
    int n;
    if (conn->is_https) {
        bool should_retry;
        n = ssl_read_with_retry(conn->server_ssl, conn->buf + conn->offset,
                                 BUFFER_SIZE - conn->offset, &should_retry);
        if (should_retry) return true;
        if (n < 0) return false;
    } else {
        n = read(fd, conn->buf + conn->offset, BUFFER_SIZE - conn->offset);

        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return true;
            return false;
        }
       
        if (n == 0) return false;
    }

    conn->offset += n;

    // check if we have complete headers
    char *end_of_headers = find_header_end(conn->buf, conn->offset);
    if (!end_of_headers) return true;

    int headers_len = end_of_headers - conn->buf + 4;
    int body_offset = headers_len;
    int remaining_body = conn->offset - body_offset;

    // inject X-Proxy header into response
    if (!conn->header_injected) {
        const char *injection = "X-Proxy:CS112\r\n\r\n";
        int injection_len = strlen(injection);
        int inject_point = headers_len - 2;

        if (conn->is_https) {
            bool should_retry;
            if (ssl_write_with_retry(conn->client_ssl, conn->buf, inject_point, &should_retry) < 0) return false;
            if (should_retry) return true;
           
            if (ssl_write_with_retry(conn->client_ssl, injection, injection_len, &should_retry) < 0) return false;
            if (should_retry) return true;
           
            if (remaining_body > 0) {
                if (ssl_write_with_retry(conn->client_ssl, conn->buf + body_offset, remaining_body, &should_retry) < 0) return false;
                if (should_retry) return true;
            }
        } else {
            write(conn->client_fd, conn->buf, inject_point);
            write(conn->client_fd, injection, injection_len);
           
            if (remaining_body > 0) {
                write(conn->client_fd, conn->buf + body_offset, remaining_body);
            }
        }

        conn->header_injected = true;
       
        // parse headers to determine body length
        char original_char = conn->buf[headers_len];
        conn->buf[headers_len] = '\0';
        char *header_copy = strdup(conn->buf);
        bool is_chunked = false;

        bool is_html = false;
        bool is_compressed = false;
        parse_response_header(header_copy, &conn->content_length, &is_chunked, &is_html, &is_compressed);
        conn->is_html = is_html;
        conn->is_compressed = is_compressed;

        free(header_copy);
        conn->buf[headers_len] = original_char;
        conn->body_bytes_read = remaining_body;

        if (conn->is_html && remaining_body > 0){
            buffer_append(conn, conn->buf + body_offset, remaining_body);
        }
        conn->offset = 0;        
    }

    // for HTTPS, enter tunnel mode; for HTTP, read body
    if (conn->is_https) {
        if (conn->offset > 0) {
            bool should_retry;
            if (ssl_write_with_retry(conn->client_ssl, conn->buf, conn->offset, &should_retry) < 0) return false;
        }
        conn->offset = 0;
        conn->phase = HTTPS_TUNNEL;
    } else {
        // if (conn->content_length > 0 && conn->body_bytes_read >= conn->content_length) {
        //     // if finish body, print LLM buffer
        //     send_and_reset_html(conn, llm_fd);

        //     return false;
        // }
        conn->phase = READING_RESPONSE_BODY;
    }

    return true;
}

// read HTTP response body from server
bool read_response_body(int fd, fd_set *all_fds, int llm_fd) {
    struct Connection *conn = fd_to_connection[fd];
    if (!conn) return false;

    int n;
    if (conn->is_https) {
        bool should_retry;
        n = ssl_read_with_retry(conn->server_ssl, conn->buf, BUFFER_SIZE, &should_retry);
        if (should_retry) return true;
        if (n < 0) return false;
    } else {
        n = read(fd, conn->buf, BUFFER_SIZE);
       
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return true;
            return false;
        }
    }

    if (n == 0) return false;
       
    conn->body_bytes_read += n;

    // forward body data to client
    if (conn->is_https) {
        bool should_retry;
        int written = ssl_write_with_retry(conn->client_ssl, conn->buf, n, &should_retry);
        if (should_retry) return true;
        if (written < 0) return false;
    } else {
        int written = write(conn->client_fd, conn->buf, n);
        if (written < 0) return false;
    }

    if (conn->is_html) {
        buffer_append(conn, conn->buf, n);
    }

    // check if response body is complete
    if (conn->content_length > 0 && conn->body_bytes_read >= conn->content_length) {
        send_and_reset_html(conn, llm_fd);
        return false;
    }

    return true;
}

// parse HTTP response headers to extract content-length and transfer-encoding
bool parse_response_header(char *header_buf, int *content_len, bool *is_chunked, bool *is_html, bool *is_compressed) {
    *is_html = false;
    *is_compressed = false;
    *content_len = -1;
    *is_chunked = false;
    
    char *line = strtok(header_buf, "\r\n");
    while (line != NULL) {
        if (strncasecmp(line, "Content-Length:", 15) == 0) {
            char *value = line + 15;
            while (*value == ' ' || *value == '\t') value++;
            *content_len = atoi(value);
        } else if (strncasecmp(line, "Transfer-Encoding:", 18) == 0) {
            if (strstr(line, "chunked")) {
                *is_chunked = true;
            }
        } else if (strncasecmp(line, "Content-Type:", 13) == 0) {
            if (strstr(line, "text/html")) {
                // fprintf(stderr, "in parse response, html is true\n");
                *is_html = true;
            }
        } else if (strncasecmp(line, "Content-Encoding:", 17) == 0) {  // ADD THIS
            if (strstr(line, "gzip") || strstr(line, "deflate") || strstr(line, "br")) {
                *is_compressed = true;
                // fprintf(stderr, "in parse, is_compressed is true");
            }
        }
        line = strtok(NULL, "\r\n");
    }
    return true;
}

// Decode chunked transfer encoding, extracting only the actual data (no size markers, \r\n)
// Returns the size of decoded data, or -1 on error
/* Example:
    1a3f\r\n
    <compressed gzip data here - 6719 bytes>\r\n
    2b4c\r\n
    <more compressed data - 11084 bytes>\r\n
    0\r\n
    \r\n
*/
int decode_chunked_data(char *input, int input_len, char **output, int *output_capacity) {
    int decoded_offset = 0;
    int input_offset = 0;
    
    // Allocate output buffer if needed
    if (*output == NULL || *output_capacity == 0) {
        *output_capacity = input_len; // Start with same size
        *output = malloc(*output_capacity);
        if (!*output) return -1;
    }
    
    while (input_offset < input_len) {
        // Parse chunk size (hex number followed by \r\n)
        int chunk_size = -1;
        int size_line_end = -1;
        
        for (int i = input_offset; i < input_len - 1; i++) {
            if (input[i] == '\r' && input[i+1] == '\n') {
                // Found end of size line
                char size_str[32];
                int size_len = i - input_offset;
                if (size_len >= 32) return -1; // Size line too long
                
                memcpy(size_str, input + input_offset, size_len);
                size_str[size_len] = '\0';
                
                // Handle chunk extensions (ignore anything after ;)
                char *semicolon = strchr(size_str, ';');
                if (semicolon) *semicolon = '\0';
                
                chunk_size = (int)strtol(size_str, NULL, 16);
                size_line_end = i + 2; // After \r\n
                break;
            }
        }
        
        if (chunk_size < 0 || size_line_end < 0) {
            // Incomplete chunk in buffer
            break;
        }
        
        if (chunk_size == 0) {
            // Last chunk - we're done
            break;
        }
        
        // Check if we have the full chunk data + trailing \r\n
        if (size_line_end + chunk_size + 2 > input_len) {
            // Don't have full chunk yet
            break;
        }
        
        // Expand output buffer if needed
        if (decoded_offset + chunk_size > *output_capacity) {
            *output_capacity *= 2;
            char *tmp = realloc(*output, *output_capacity);
            if (!tmp) return -1;
            *output = tmp;
        }
        
        // Copy chunk data to output
        memcpy(*output + decoded_offset, input + size_line_end, chunk_size);
        decoded_offset += chunk_size;
        
        // Move past this chunk (size line + data + \r\n)
        input_offset = size_line_end + chunk_size + 2;
    }
    
    return decoded_offset;
}

// Decompress gzip/brotli data and store in LLM buffer
bool decompress_and_store(struct Connection *conn) {
    if (conn->html_offset == 0) return true;
    
    // Check first bytes to determine compression type
    unsigned char *data = (unsigned char *)conn->LLM_buf;
    bool is_gzip = (conn->html_offset >= 2 && data[0] == 0x1f && data[1] == 0x8b);
        
    if (is_gzip) {
        // GZIP decompression
        size_t decompressed_size = conn->html_offset * 10;
        char *decompressed = malloc(decompressed_size);
        if (!decompressed) return false;
        
        z_stream stream = {0};
        stream.next_in = (unsigned char *)conn->LLM_buf;
        stream.avail_in = conn->html_offset;
        stream.next_out = (unsigned char *)decompressed;
        stream.avail_out = decompressed_size;
        
        // Initialize with gzip flag (16 + MAX_WBITS)
        if (inflateInit2(&stream, 16 + MAX_WBITS) != Z_OK) {
            free(decompressed);
            fprintf(stderr, "ERROR: inflateInit2 failed\n");
            return false;
        }
        
        int ret = inflate(&stream, Z_FINISH);
        if (ret != Z_STREAM_END && ret != Z_OK) {
            fprintf(stderr, "ERROR: inflate failed with code %d\n", ret);
            inflateEnd(&stream);
            free(decompressed);
            return false;
        }
        
        size_t actual_size = stream.total_out;
        inflateEnd(&stream);
        
        fprintf(stderr, "DEBUG: Gzip decompressed to %zu bytes\n", actual_size);
        
        // Replace compressed data with decompressed data
        free(conn->LLM_buf);
        conn->LLM_buf = decompressed;
        conn->html_offset = actual_size;
        conn->LLM_buf_capacity = decompressed_size;
        
        return true;
        
    } else {
        // BROTLI decompression
        size_t decompressed_size = conn->html_offset * 10;
        char *decompressed = malloc(decompressed_size);
        if (!decompressed) return false;
        
        size_t actual_size = decompressed_size;
        BrotliDecoderResult result = BrotliDecoderDecompress(
            conn->html_offset,
            (const uint8_t *)conn->LLM_buf,
            &actual_size,
            (uint8_t *)decompressed
        );
        
        if (result != BROTLI_DECODER_RESULT_SUCCESS) {
            fprintf(stderr, "ERROR: Brotli decompression failed with code %d\n", result);
            free(decompressed);
            return false;
        }
        
        fprintf(stderr, "DEBUG: Brotli decompressed to %zu bytes\n", actual_size);
        
        // Replace compressed data with decompressed data
        free(conn->LLM_buf);
        conn->LLM_buf = decompressed;
        conn->html_offset = actual_size;
        conn->LLM_buf_capacity = decompressed_size;
        
        return true;
    }
}

// read from SSL with proper error handling for non-blocking operations
int ssl_read_with_retry(SSL *ssl, void *buf, int num, bool *should_retry) {
    *should_retry = false;
    int n = SSL_read(ssl, buf, num);
    if (n <= 0) {
        int err = SSL_get_error(ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            *should_retry = true;
            return 0;
        } else if (err == SSL_ERROR_ZERO_RETURN) {
            return 0;
        }
        ERR_print_errors_fp(stderr);
        return -1;
    }
    return n;
}

// write to SSL with proper error handling for non-blocking operations
int ssl_write_with_retry(SSL *ssl, const void *buf, int num, bool *should_retry) {
    *should_retry = false;
    int n = SSL_write(ssl, buf, num);
    if (n <= 0) {
        int err = SSL_get_error(ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            *should_retry = true;
            return 0;
        }
        ERR_print_errors_fp(stderr);
        return -1;
    }
    return n;
}

// parse HTTP request to extract method, host, port, and path
bool parse_request(char *req, bool *is_connect, char **host, char **port, char **path) {
    char method[16], target[512], version[16];
    int n = sscanf(req, "%15s %511s %15s", method, target, version);
    if (n != 3) return false;

    if (strcmp(method, "CONNECT") == 0) {
        *is_connect = true;

        // parse host:port from target
        char *colon = strchr(target, ':');
        if (!colon) return false;

        *colon = '\0';
        *host = strdup(target);
        *port = strdup(colon + 1);
        *path = NULL;
    } else if (strcmp(method, "GET") == 0) {
        *is_connect = false;
        // handle absolute URI format (http://host:port/path)
        if (strncmp(target, "http://", 7) == 0) {
            char *host_start = target + 7;
            char *path_start = strchr(host_start, '/');
            if (!path_start) return false;

            *path = strdup(path_start);

            *path_start = '\0';
            char *colon = strchr(host_start, ':');
            if (colon) {
                *colon = '\0';
                *host = strdup(host_start);
                *port = strdup(colon + 1);
            } else {
                *host = strdup(host_start);
                *port = strdup("80");
            }
        }
    } else {
        // for other methods, extract host from Host header
        *path = strdup(target);
       
        char *host_line = strstr(req, "\r\nHost: ");
        if (!host_line) {
            host_line = strstr(req, "\nHost: ");
            if (!host_line) return false;
            host_line += 7;
        } else {
            host_line += 9;
        }
       
        char *host_end = strstr(host_line, "\r\n");
        if (!host_end) host_end = strstr(host_line, "\n");
        if (!host_end) return false;
       
        int host_len = host_end - host_line;
        char host_buf[512];
        strncpy(host_buf, host_line, host_len);
        host_buf[host_len] = '\0';
       
        char *colon = strchr(host_buf, ':');
        if (colon) {
            *colon = '\0';
            *host = strdup(host_buf);
            *port = strdup(colon + 1);
        } else {
            *host = strdup(host_buf);
            *port = strdup("443");
        }
    }
    return true;
}

// forward buffered request to server
bool forward_request(int fd, fd_set *all_fds) {
    struct Connection *conn = fd_to_connection[fd];
    if (!conn) return false;

    int remaining = conn->offset;
    int written = write(fd, conn->buf, remaining);

    if (written < 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) return true;
        return false;
    }

    // handle partial writes
    if (written < remaining) {
        memmove(conn->buf, conn->buf + written, remaining - written);
        conn->offset = remaining - written;
        return true;
    }

    // request fully sent, prepare to read response
    conn->offset = 0;
    conn->phase = READING_RESPONSE_HEADER;
   
    return true;
}

// create and initialize a new connection structure
struct Connection *Connection_create(int client_fd) {
    struct Connection *new_conn = malloc(sizeof(struct Connection));
    new_conn->client_fd = client_fd;
    new_conn->server_fd = -1;
    new_conn->offset = 0;
    new_conn->phase = READING_REQUEST;
    new_conn->content_length = -1;
    new_conn->body_bytes_read = 0;

    new_conn->is_https = false;
    new_conn->client_ssl = NULL;
    new_conn->server_ssl = NULL;
    new_conn->client_ctx = NULL;
    new_conn->server_ctx = NULL;
    new_conn->hostname = NULL;
    new_conn->target_port = NULL;
    new_conn->header_injected = false;
    
    new_conn->tunnel_state = TUNNEL_EXPECT_RESPONSE_HEADERS;
    new_conn->tunnel_body_remaining = 0;
    new_conn->tunnel_buf_offset = 0;

    new_conn->LLM_buf = malloc(HTML_BUFFER_SIZE);
    new_conn->html_offset = 0;
    new_conn->LLM_buf_capacity = HTML_BUFFER_SIZE;
    new_conn->is_html = false;
    
    new_conn->is_compressed = false;
    new_conn->chunked_decode_buf = NULL;
    new_conn->chunked_decode_capacity = 0;
    new_conn->chunked_decode_offset = 0;
    
    return new_conn;
}

// initialize server address structure for binding
void create_server_struct(struct sockaddr_in *server_addr, int listen_port) {
    memset(server_addr, 0, sizeof(*server_addr));
    server_addr->sin_family = AF_INET;
    server_addr->sin_addr.s_addr = INADDR_ANY;
    server_addr->sin_port = htons(listen_port);
}

// parse chunk size from chunked encoding (returns -1 if incomplete, -2 on error)
int parse_chunk_size(char *buf, int len) {
    // look for \r\n to find end of chunk size line
    for (int i = 0; i < len - 1; i++) {
        if (buf[i] == '\r' && buf[i+1] == '\n') {
            // parse hex number
            char size_str[32];
            int copy_len = (i < 31) ? i : 31;
            memcpy(size_str, buf, copy_len);
            size_str[copy_len] = '\0';
            
            // find semicolon (chunk extensions) if present
            char *semi = strchr(size_str, ';');
            if (semi) *semi = '\0';
            
            return (int)strtol(size_str, NULL, 16);
        }
    }
    return -1; // incomplete chunk size line
}

// handle bidirectional HTTPS tunnel with HTTP response parsing
bool handle_https_tunnel(int fd, fd_set *all_fds, int llm_fd) {
    struct Connection *conn = fd_to_connection[fd];
    if (!conn) {
        FD_CLR(fd, all_fds);
        return false;
    }

    bool from_client = (fd == conn->client_fd);
    
    if (from_client) {
        // client -> server: forward requests without modification
        char temp_buf[BUFFER_SIZE];
        bool should_retry;
        
        int n = ssl_read_with_retry(conn->client_ssl, temp_buf, sizeof(temp_buf), &should_retry);
        if (should_retry) return true;
        if (n <= 0) return false;
        
        if (!conn->server_ssl) return true;
        
        int written = ssl_write_with_retry(conn->server_ssl, temp_buf, n, &should_retry);
        if (written < 0) return false;
        
        return true;
        
    } else {
        // server -> client: parse HTTP responses and inject headers
        bool should_retry;
        
        if (!conn->server_ssl) return true;
        
        // read from server into tunnel buffer
        int space_left = BUFFER_SIZE - conn->tunnel_buf_offset;
        if (space_left <= 0) {
            // buffer full, fall back to passthrough mode
            fprintf(stderr, "WARNING: Tunnel buffer full, switching to passthrough\n");
            conn->tunnel_state = TUNNEL_PASSTHROUGH;
            
            int written = ssl_write_with_retry(conn->client_ssl, conn->tunnel_buf, 
                                                conn->tunnel_buf_offset, &should_retry);
            if (written < 0) return false;
            conn->tunnel_buf_offset = 0;
            return true;
        }
        
        int n = ssl_read_with_retry(conn->server_ssl,
                                     conn->tunnel_buf + conn->tunnel_buf_offset,
                                     space_left,
                                     &should_retry);
        if (should_retry) return true;
        if (n <= 0) return false;
        
        conn->tunnel_buf_offset += n;

        // bool is_html = false;
        
        // process based on current tunnel state
        switch (conn->tunnel_state) {
            case TUNNEL_EXPECT_RESPONSE_HEADERS: {
                // look for end of headers
                char *end_of_headers = find_header_end(conn->tunnel_buf, conn->tunnel_buf_offset);
                
                if (end_of_headers) {
                    // found complete headers
                    int headers_len = end_of_headers - conn->tunnel_buf + 4;
                    
                    // parse Content-Length and Transfer-Encoding
                    char temp_copy[BUFFER_SIZE];
                    int copy_len = (headers_len < BUFFER_SIZE - 1) ? headers_len : BUFFER_SIZE - 1;
                    memcpy(temp_copy, conn->tunnel_buf, copy_len);
                    temp_copy[copy_len] = '\0';
                    
                    int content_length = -1;
                    bool is_chunked = false;

                    bool is_html = false;
                    bool is_compressed = false;
                    parse_response_header(temp_copy, &content_length, &is_chunked, &is_html, &is_compressed);   
                    conn->is_html = is_html;
                    conn->is_compressed = is_compressed;
                    
                    // inject X-Proxy header
                    const char *injection = "X-Proxy:CS112\r\n\r\n";
                    int injection_len = strlen(injection);
                    int inject_point = headers_len - 2;
                    
                    // send headers with injection
                    int written = ssl_write_with_retry(conn->client_ssl, conn->tunnel_buf, 
                                                        inject_point, &should_retry);
                    if (written < 0) return false;
                    
                    written = ssl_write_with_retry(conn->client_ssl, injection, 
                                                    injection_len, &should_retry);
                    if (written < 0) return false;
                    
                    // fprintf(stderr, "DEBUG: Injected header (CL=%d, chunked=%d)\n", 
                    //         content_length, is_chunked);
                    
                    // send any body data we already have
                    int body_in_buffer = conn->tunnel_buf_offset - headers_len;
                    if (body_in_buffer > 0) {
                        written = ssl_write_with_retry(conn->client_ssl,
                                                        conn->tunnel_buf + headers_len,
                                                        body_in_buffer, &should_retry);
                        if (written < 0) return false;
                    }

                    if (conn->is_html) {
                        // add to LLM buffer
                        buffer_append(conn, conn->tunnel_buf + headers_len, body_in_buffer);
                    }
                    
                    // update state for body reading
                    if (is_chunked) {
                        conn->tunnel_state = TUNNEL_READING_CHUNKED_RESPONSE;
                        conn->tunnel_buf_offset = 0;
                    } else if (content_length >= 0) {
                        conn->tunnel_state = TUNNEL_READING_RESPONSE_BODY_KNOWN_LENGTH;
                        conn->tunnel_body_remaining = content_length - body_in_buffer;
                        conn->tunnel_buf_offset = 0;
                        
                        if (conn->tunnel_body_remaining <= 0) {
                            // response complete, expect next response
                            conn->tunnel_state = TUNNEL_EXPECT_RESPONSE_HEADERS;
                            send_and_reset_html(conn, llm_fd);
                        }
                    } else {
                        // no content-length, no chunked - passthrough until connection closes
                        conn->tunnel_state = TUNNEL_PASSTHROUGH;
                        conn->tunnel_buf_offset = 0;
                    }
                }
                // else: keep buffering until we have complete headers
                break;
            }
            
            case TUNNEL_READING_RESPONSE_BODY_KNOWN_LENGTH: {
                // get length of body data to forward
                int to_forward = conn->tunnel_buf_offset;
                if (to_forward > conn->tunnel_body_remaining) {
                    to_forward = conn->tunnel_body_remaining;
                }
                
                int written = ssl_write_with_retry(conn->client_ssl, conn->tunnel_buf,
                                                    to_forward, &should_retry);
                if (written < 0) return false;

                if (conn->is_html) {
                    // add to LLM buffer
                    buffer_append(conn, conn->tunnel_buf, to_forward);
                }
                
                conn->tunnel_body_remaining -= to_forward;
                
                // move any excess data to start of buffer
                if (to_forward < conn->tunnel_buf_offset) {
                    memmove(conn->tunnel_buf, conn->tunnel_buf + to_forward,
                            conn->tunnel_buf_offset - to_forward);
                    conn->tunnel_buf_offset -= to_forward;
                } else {
                    conn->tunnel_buf_offset = 0;
                }
                
                // check if body is complete
                if (conn->tunnel_body_remaining <= 0) {
                    fprintf(stderr, "DEBUG: Response body complete, expecting next response\n");
                    conn->tunnel_state = TUNNEL_EXPECT_RESPONSE_HEADERS;
                    send_and_reset_html(conn, llm_fd);
                }
                break;
            }

            case TUNNEL_READING_CHUNKED_RESPONSE: {                
                // forward all data to client (still chunked-encoded)
                int written = ssl_write_with_retry(conn->client_ssl, conn->tunnel_buf,
                                                    conn->tunnel_buf_offset, &should_retry);
                if (written < 0) return false;

                // for HTML, accumulate RAW chunked data (with chunk framing)
                if (conn->is_html) {                    
                    // append the raw chunked data
                    buffer_append(conn, conn->tunnel_buf, conn->tunnel_buf_offset);
                }
                
                // check for end of chunked encoding
                if (conn->tunnel_buf_offset >= 5) {
                    char *last_chunk = strstr(conn->tunnel_buf, "0\r\n\r\n");
                    if (last_chunk) {
                        fprintf(stderr, "DEBUG: Chunked response complete\n");
                        
                        if (conn->is_html && conn->html_offset > 0) {
                            char *decoded_output = NULL;
                            int decoded_capacity = 0;
                            int decoded_len = decode_chunked_data(conn->LLM_buf, conn->html_offset,
                                &decoded_output, &decoded_capacity
                            );
                                                    
                            if (decoded_len > 0) {
                                // replace chunked data with decoded data
                                free(conn->LLM_buf);
                                conn->LLM_buf = decoded_output;
                                conn->html_offset = decoded_len;
                                conn->LLM_buf_capacity = decoded_capacity;
                            } else {
                                // decode failed, clean up
                                if (decoded_output) free(decoded_output);
                                conn->html_offset = 0;
                            }
                        }
                        
                        conn->tunnel_state = TUNNEL_EXPECT_RESPONSE_HEADERS;
                        send_and_reset_html(conn, llm_fd);
                    }
                }
                
                conn->tunnel_buf_offset = 0;
                break;
            }
            
            case TUNNEL_PASSTHROUGH: {
                // forward everything
                int written = ssl_write_with_retry(conn->client_ssl, conn->tunnel_buf,
                                                    conn->tunnel_buf_offset, &should_retry);
                if (written < 0) return false;

                if (conn->is_html) {
                    // add to LLM buffer
                    buffer_append(conn, conn->tunnel_buf, conn->tunnel_buf_offset);
                }
                
                conn->tunnel_buf_offset = 0;
                break;
            }
        }
    }
    
    return true;
}

// send HTML buffer, decompressing if needed, then reset state
void send_and_reset_html(struct Connection *conn, int llm_fd) {
    if (!conn->is_html || conn->html_offset == 0) {
        return;
    }

    send_to_llm(conn, 9450);
    
    // // decompress if needed
    // if (conn->is_compressed) {
    //     if (!decompress_and_store(conn)) {
    //         fprintf(stderr, "ERROR: Failed to decompress HTML\n");
    //         conn->html_offset = 0;
    //         conn->is_html = false;
    //         conn->is_compressed = false;
    //         return;
    //     }
    //     fprintf(stderr, "DEBUG: Decompression successful, new size=%d\n", conn->html_offset);
    // }
    
    // // null terminate and print -> TODO: SEND TO LLM
    // buffer_append(conn, "\0", 1);
    // char request[BUFFER_SIZE];
    // snprintf(request, sizeof(request),
    //          "POST /upload_html HTTP/1.1\r\n"
    //          "Client fd: %d\r\n"
    //          "Host: %s:%d\r\n"
    //          "Content-Type: application/json\r\n"
    //          "Content-Length: %zu\r\n"
    //          "Connection: close\r\n"
    //          "\r\n"
    //          "%s",
    //          conn->client_fd, conn->hostname, conn->target_port, conn->html_offset, conn->LLM_buf);
    
    // write(llm_fd, request, strlen(request));

    // clean up
    conn->html_offset = 0;
    conn->is_html = false;
    conn->is_compressed = false;

    fprintf(stderr, "LLM BODY:\n");
    fprintf(stderr, "%s\n", conn->LLM_buf);

}

// clean up and close a connection
void close_connection(struct Connection **conn_ptr, fd_set *all_fds) {
    if (!conn_ptr || !*conn_ptr) return;
    
    struct Connection *conn = *conn_ptr;
    
    int client_fd = conn->client_fd;
    int server_fd = conn->server_fd;
    
    if (client_fd < 0 && server_fd < 0) {
        free(conn);
        *conn_ptr = NULL;
        return;
    }

    // remove fd mappings
    if (client_fd >= 0 && client_fd < FD_SETSIZE) {
        fd_to_connection[client_fd] = NULL;
    }
    if (server_fd >= 0 && server_fd < FD_SETSIZE) {
        fd_to_connection[server_fd] = NULL;
    }

    // close sockets
    if (client_fd >= 0) {
        FD_CLR(client_fd, all_fds);
        close(client_fd);
    }
    if (server_fd >= 0) {
        FD_CLR(server_fd, all_fds);
        close(server_fd);
    }

    // clean up SSL resources
    if (conn->client_ssl) {
        SSL_shutdown(conn->client_ssl);
        SSL_free(conn->client_ssl);
    }
    if (conn->server_ssl) {
        SSL_shutdown(conn->server_ssl);
        SSL_free(conn->server_ssl);
    }
    if (conn->client_ctx) {
        SSL_CTX_free(conn->client_ctx);
    }
    if (conn->server_ctx) {
        SSL_CTX_free(conn->server_ctx);
    }

    free(conn->hostname);
    free(conn->target_port);
    free(conn->chunked_decode_buf);

    free(conn);
    *conn_ptr = NULL;
}