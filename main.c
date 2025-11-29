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
#define HTML_BUFFER_SIZE 524288
#define TUNNEL_BUFFER_SIZE 262144

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
    char tunnel_buf[TUNNEL_BUFFER_SIZE];
    int tunnel_buf_offset;

    // accumulating buffer for LLM
    char *LLM_buf;
    unsigned int html_offset;
    unsigned int LLM_buf_capacity;
    bool is_html;

    // store original headers for HTML (to recalculate Content-Length)
    char *response_headers;
    int response_headers_len;
    bool header_sent_to_client;

    // for chunked decoding
    char *chunked_decode_buf;
    int chunked_decode_capacity;
    int chunked_decode_offset;
    bool is_compressed;

    char *url;
    bool chatbot_injected;

    // For streaming decompression
    z_stream *gzip_stream;          // For gzip decompression
    BrotliDecoderState *brotli_state; // For brotli decompression
    bool decompression_initialized;
    char decompress_buffer[BUFFER_SIZE]; // Temporary buffer for decompressed chunks
    int compressed_bytes_consumed;
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
int decompress_chunk(struct Connection *conn, char *input, int input_len, char *output, int output_size);
char *find_body_tag(char *buf, int len);
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

// Generate chatbot snippet with actual client FD
char *generate_chatbot_snippet(int client_fd) {
    // Allocate buffer - should be plenty for the HTML + script
    char *snippet = malloc(2048);
    if (!snippet) return NULL;
    
    snprintf(snippet, 2048,
"<div id=\"mitm-chatbot-box\" style=\"\n"
" position: fixed;\n"
" bottom: 20px;\n"
" right: 20px;\n"
" width: 260px;\n"
" background: white;\n"
" border: 2px solid #333;\n"
" padding: 10px;\n"
" z-index: 999999;\n"
" box-shadow: 0px 0px 10px rgba(0,0,0,0.4);\n"
" font-family: sans-serif;\">\n"
" <div style=\"font-weight: bold; margin-bottom: 8px;\">Chatbot</div>\n"
" <div id=\"mitm-chatbot-reply\" style=\"height: 80px; overflow-y: auto; border: 1px solid #ccc; padding: 6px; margin-bottom: 8px;\"></div>\n"
" <input id=\"mitm-chatbot-input\" type=\"text\" style=\"width: 100%%; padding: 6px; box-sizing: border-box;\" placeholder=\"Ask a question about the page...\"/>\n"
"</div>\n"
"\n"
"<script>\n"
"document.getElementById(\"mitm-chatbot-input\").addEventListener(\"keydown\", async function(e) {\n"
" if (e.key !== \"Enter\") return;\n"
" let msg = this.value;\n"
" this.value = \"\";\n"
" let box = document.getElementById(\"mitm-chatbot-reply\");\n"
" box.innerHTML += \"<div><b>You:</b> \" + msg + \"</div>\";\n"
"\n"
" let resp = await fetch(\"http://localhost:9450/query\", {\n"
"  method: \"POST\",\n"
"  headers: { \"Content-Type\": \"application/json\", \"Client-FD\": \"%d\" },\n"
"  body: JSON.stringify({ query: msg })\n"
" });\n"
" let data = await resp.json();\n"
" box.innerHTML += \"<div><b>Bot:</b> \" + data.text + \"</div>\";\n"
" box.scrollTop = box.scrollHeight;\n"
"});\n"
"</script>\n",
    client_fd);
    
    return snippet;
}


// Update Content-Length header in stored response headers
// Removes compressed header field
// Returns modified headers string (caller must free)
char *update_content_length_header(const char *headers, int headers_len, int new_content_len) {
    char *temp = malloc(headers_len + 100);  // Extra space for safety
    memcpy(temp, headers, headers_len);
    temp[headers_len] = '\0';
    
    int current_len = headers_len;
    
    // Remove Content-Encoding line if present
    char *ce_start = strstr(temp, "Content-Encoding:");
    if (ce_start) {
        char *ce_end = strstr(ce_start, "\r\n");
        if (ce_end) {
            // Calculate how much to remove (including \r\n)
            int remove_len = (ce_end + 2) - ce_start;
            // Move everything after this line forward
            memmove(ce_start, ce_end + 2, strlen(ce_end + 2) + 1);
            current_len -= remove_len;
            temp[current_len] = '\0';
        }
    }

    // Remove Transfer-Encoding line if present (since we are sending raw body with Content-Length)
    char *te_start = strstr(temp, "Transfer-Encoding:");
    if (te_start) {
        char *te_end = strstr(te_start, "\r\n");
        if (te_end) {
            int remove_len = (te_end + 2) - te_start;
            memmove(te_start, te_end + 2, strlen(te_end + 2) + 1);
            current_len -= remove_len;
            temp[current_len] = '\0';
        }
    }
    
    // Change "Connection: close" to "Connection: keep-alive" if present
    char *conn_close = strstr(temp, "Connection: close");
    if (conn_close) {
        memcpy(conn_close + 12, "keep-alive", 10);  // Overwrite "close" with "keep-alive"
    }
    
    // Find and update Content-Length line
    char *cl_start = strstr(temp, "Content-Length:");
    if (!cl_start) {
        free(temp);
        return strdup(headers);
    }
    
    // Find the end of the Content-Length line
    char *cl_end = strstr(cl_start, "\r\n");
    if (!cl_end) {
        free(temp);
        return strdup(headers);
    }
    
    // Build new header with updated Content-Length
    int before_len = cl_start - temp;
    char *after_cl = cl_end;  // Start of what comes after CL line
    
    char new_cl_line[128];
    snprintf(new_cl_line, sizeof(new_cl_line), "Content-Length: %d", new_content_len);
    
    // Calculate new total length
    int after_len = current_len - (cl_end - temp);
    int new_headers_len = before_len + strlen(new_cl_line) + after_len;
    
    char *new_headers = malloc(new_headers_len + 1);
    
    // Copy: before CL line + new CL line + after CL line
    memcpy(new_headers, temp, before_len);
    memcpy(new_headers + before_len, new_cl_line, strlen(new_cl_line));
    memcpy(new_headers + before_len + strlen(new_cl_line), after_cl, after_len);
    new_headers[new_headers_len] = '\0';
    
    free(temp);
    return new_headers;
}

// inject CHATBOT_SNIPPET after <body tag in HTML content
// returns allocated buffer with injected content, or NULL on failure
// caller must free the returned buffer
char *inject_chatbot_into_html(const char *html, int html_len, int *out_len, int client_fd) {
    // Generate snippet with actual FD
    char *CHATBOT_SNIPPET = generate_chatbot_snippet(client_fd);
    if (!CHATBOT_SNIPPET) return NULL;
    
    // find <body tag (case-insensitive, could be <body>, <body attr="...">)
    const char *body_tag = NULL;
    for (int i = 0; i < html_len - 5; i++) {
        if (html[i] == '<' &&
            (html[i+1] == 'b' || html[i+1] == 'B') &&
            (html[i+2] == 'o' || html[i+2] == 'O') &&
            (html[i+3] == 'd' || html[i+3] == 'D') &&
            (html[i+4] == 'y' || html[i+4] == 'Y') &&
            (html[i+5] == '>' || html[i+5] == ' ' || html[i+5] == '\t' || html[i+5] == '\n' || html[i+5] == '\r')) {
            body_tag = html + i;
            break;
        }
    }
    
    const char *insert_point = NULL;
    int snippet_insert_offset = -1;
    
    if (body_tag) {
        insert_point = strchr(body_tag, '>');
        if (!insert_point) {
            fprintf(stderr, "ERROR: Malformed <body> tag\n");
            free(CHATBOT_SNIPPET);
            return NULL;
        }
        snippet_insert_offset = insert_point - html + 1;
        fprintf(stderr, "DEBUG: Found <body> tag at offset %ld\n", body_tag - html);
    } else {
        for (int i = html_len - 10; i >= 0; i--) {
            if ((html[i] == '<' || html[i] == '<') &&
                (html[i+1] == '/' || html[i+1] == '/') &&
                (html[i+2] == 'h' || html[i+2] == 'H') &&
                (html[i+3] == 't' || html[i+3] == 'T') &&
                (html[i+4] == 'm' || html[i+4] == 'M') &&
                (html[i+5] == 'l' || html[i+5] == 'L') &&
                (html[i+6] == '>' || html[i+6] == '>')) {
                snippet_insert_offset = i;
                fprintf(stderr, "DEBUG: Found </html> tag at offset %d, injecting before it\n", i);
                break;
            }
        }
    }
    
    if (snippet_insert_offset < 0) {
        fprintf(stderr, "DEBUG: No <body> or </html> tag found, appending at end\n");
        snippet_insert_offset = html_len;
    }
    
    int snippet_len = strlen(CHATBOT_SNIPPET);
    int before_len = snippet_insert_offset;
    int after_len = html_len - snippet_insert_offset;
    
    int new_len = before_len + snippet_len + after_len;
    char *injected = malloc(new_len + 1);
    if (!injected) {
        fprintf(stderr, "ERROR: malloc failed for injected HTML\n");
        free(CHATBOT_SNIPPET);
        return NULL;
    }
    
    memcpy(injected, html, before_len);
    memcpy(injected + before_len, CHATBOT_SNIPPET, snippet_len);
    memcpy(injected + before_len + snippet_len, html + snippet_insert_offset, after_len);
    injected[new_len] = '\0';
    
    fprintf(stderr, "DEBUG: Injected chatbot (original=%d, injected=%d, insert_offset=%d, client_fd=%d)\n", 
            html_len, new_len, snippet_insert_offset, client_fd);

    free(CHATBOT_SNIPPET);  // Free the generated snippet
    *out_len = new_len;
    return injected;
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
    
    // Create socket
    int llm_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (llm_fd < 0) {
        perror("Failed to create LLM socket");
        return false;
    }
    
    // Connect to Flask
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
    
    // Build HTTP POST request header (send raw HTML, not JSON)
    char header[1024];
    snprintf(header, sizeof(header),
             "POST /upload_html HTTP/1.1\r\n"
             "Host: 127.0.0.1:%d\r\n"
             "Client-FD: %d\r\n"
             "Page-URL: %s\r\n"
             "Content-Type: text/html\r\n"
             "Content-Length: %d\r\n"
             "Connection: close\r\n"
             "\r\n",
             llm_port, conn->client_fd, conn->url, conn->html_offset); // TODO: change to client_fd
    
    // Send header
    int sent = write(llm_fd, header, strlen(header));
    if (sent < 0) {
        perror("Failed to send header to Flask");
        close(llm_fd);
        return false;
    }
    
    // Send HTML body directly (no JSON encoding needed!)
    sent = write(llm_fd, conn->LLM_buf, conn->html_offset);
    if (sent < 0) {
        perror("Failed to send body to Flask");
        close(llm_fd);
        return false;
    }
    
    fprintf(stderr, "Sent %d bytes HTML to Flask (fd=%d)\n", conn->html_offset, conn->client_fd);
    
    close(llm_fd);
    return true;
}

void buffer_append(struct Connection *conn, char *to_add, int len) {
    char *buf = conn->LLM_buf;

    if (len + conn->html_offset >= conn->LLM_buf_capacity) {
        // double until required capacity is reached
        int new_capacity = conn->LLM_buf_capacity;
        while (len + conn->html_offset >= new_capacity) {
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

        // create url for HTTPS requests inside tunnel
        if (conn->url) free(conn->url);
        conn->url = malloc(strlen(host) + strlen(path) + 20);
        sprintf(conn->url, "https://%s%s", host, path);
    }

    if (!success) return false;

    // Construct full URL for HTTP/HTTPS, give to LLM for context
    if (!is_connect && host && path) {
        if (conn->url) free(conn->url);
        
        // Determine scheme
        const char *scheme = conn->is_https ? "https" : "http";
        
        // Construct URL
        conn->url = malloc(strlen(scheme) + strlen(host) + strlen(path) + 20);
        if (strcmp(port, "80") == 0 || strcmp(port, "443") == 0) {
            // Omit default ports
            sprintf(conn->url, "%s://%s%s", scheme, host, path);
        } else {
            sprintf(conn->url, "%s://%s:%s%s", scheme, host, port, path);
        }
        
        fprintf(stderr, "DEBUG: Request URL: %s\n", conn->url);
    }

    // handle CONNECT requests (HTTPS) differently from GET requests (HTTP)
    if (is_connect) {
        conn->is_https = true;
        success = setup_connect_request(fd, host, port, all_fds);
    } else {
        success = setup_get_request(fd, host, port, path, all_fds);
    }

    return success;
}

bool setup_connect_request(int fd, char *host, char *port, fd_set *all_fds) {
    struct Connection *conn = fd_to_connection[fd];
    if (!conn) return false;

    // save hostname and port for later use
    conn->hostname = strdup(host);
    conn->target_port = strdup(port);
    
    // Create initial URL for the host
    if (conn->url) free(conn->url);
    if (strcmp(port, "443") == 0) {
        // Default HTTPS port - omit from URL
        conn->url = malloc(strlen(host) + 20);
        sprintf(conn->url, "https://%s", host);
    } else {
        conn->url = malloc(strlen(host) + strlen(port) + 20);
        sprintf(conn->url, "https://%s:%s", host, port);
    }
    
    fprintf(stderr, "DEBUG: Set initial URL for CONNECT: %s\n", conn->url);

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
    static unsigned long serial_counter = 0;
    ASN1_INTEGER_set(X509_get_serialNumber(x509), (long)(time(NULL) * 1000 + (serial_counter++)));
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

        fprintf(stderr, "DEBUG: Parsed headers - is_html=%d, content_length=%d, is_chunked=%d, is_compressed=%d\n",
        is_html, conn->content_length, is_chunked, is_compressed);

        free(header_copy);
        conn->buf[headers_len] = original_char;

        const char *injection = "\r\nX-Proxy:CS112\r\n\r\n";
        int injection_len = strlen(injection);
        int inject_point = headers_len - 2;

        // For HTML responses, don't send headers yet - we'll send them when we inject the chatbot
        // For other responses, send headers immediately
        if (!conn->is_html) {
            // Already marked as non-HTML, just inject and forward
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
        } else {
            // HTML response - check if we should skip chatbot injection
            if (conn->url && (strstr(conn->url, "detectportal") || 
                            strstr(conn->url, "push.services.mozilla") ||
                            strstr(conn->url, "safebrowsing") ||
                            strstr(conn->url, "telemetry"))) {
                fprintf(stderr, "DEBUG: Skipping chatbot for background HTML: %s\n", conn->url);
                conn->is_html = false;  // Treat as non-HTML
                
                // Forward headers and body immediately
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
            } else {
                // Real HTML - store headers for later
                if (conn->response_headers) {
                    free(conn->response_headers);
                }
                conn->response_headers = malloc(headers_len + 1);
                memcpy(conn->response_headers, conn->buf, headers_len);
                conn->response_headers_len = headers_len;
                conn->response_headers[headers_len] = '\0';
                fprintf(stderr, "DEBUG: Stored headers for HTML response (len=%d), is_chunked=%d\n", headers_len, is_chunked);
                
                // For HTML, buffer the initial body data, don't forward yet
                if (remaining_body > 0) {
                    buffer_append(conn, conn->buf + body_offset, remaining_body);
                    fprintf(stderr, "DEBUG: Buffered initial body chunk (%d bytes)\n", remaining_body);
                }
            }
        }

        conn->header_injected = true;
        conn->body_bytes_read = remaining_body;

        // If HTML, store headers so we can update Content-Length later
        if (conn->is_html) {
            // Free old headers if they exist
            if (conn->response_headers) {
                free(conn->response_headers);
            }
            conn->response_headers = malloc(headers_len + 1);
            memcpy(conn->response_headers, conn->buf, headers_len);
            conn->response_headers_len = headers_len;
            conn->response_headers[headers_len] = '\0';
            fprintf(stderr, "DEBUG: Stored headers for HTML response (len=%d), is_chunked=%d\n", headers_len, is_chunked);
            
            // For HTML, buffer the initial body data, don't forward yet
            if (remaining_body > 0) {
                buffer_append(conn, conn->buf + body_offset, remaining_body);
                fprintf(stderr, "DEBUG: Buffered initial body chunk (%d bytes)\n", remaining_body);
            }
        } else {
            // For non-HTML, forward body immediately
            if (remaining_body > 0) {
                write(conn->client_fd, conn->buf + body_offset, remaining_body);
            }
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

    // At the very end of read_response_header, after setting conn->phase

    // Check if body is already complete
    if (conn->content_length > 0 && conn->body_bytes_read >= conn->content_length) {
        fprintf(stderr, "DEBUG: Body already complete in header phase!\n");
        
        if (conn->is_html && conn->html_offset > 0) {
            // Do injection immediately
            fprintf(stderr, "DEBUG: Doing immediate injection from header phase\n");
            
            // Decompress if needed
            if (conn->is_compressed) {
                if (!decompress_and_store(conn)) {
                    fprintf(stderr, "ERROR: Failed to decompress HTML\n");
                } else {
                    conn->is_compressed = false;
                }
            }
            
            // Inject chatbot
            int injected_len = 0;
            char *injected_html = inject_chatbot_into_html(conn->LLM_buf, conn->html_offset, &injected_len, conn->client_fd);
            
            if (injected_html && conn->response_headers) {
                char *updated_headers = update_content_length_header(conn->response_headers, conn->response_headers_len, injected_len);
                const char *injection = "X-Proxy:CS112\r\n\r\n";
                int headers_without_end = strlen(updated_headers) - 2;
                
                int written = write(conn->client_fd, updated_headers, headers_without_end);
                fprintf(stderr, "DEBUG: Wrote headers: %d bytes (expected %d)\n", written, headers_without_end);
                if (written < 0) {
                    fprintf(stderr, "ERROR: Failed to write headers: %s\n", strerror(errno));
                }
                
                written = write(conn->client_fd, injection, strlen(injection));
                fprintf(stderr, "DEBUG: Wrote injection: %d bytes\n", written);
                if (written < 0) {
                    fprintf(stderr, "ERROR: Failed to write injection: %s\n", strerror(errno));
                }
                
                written = write(conn->client_fd, injected_html, injected_len);
                fprintf(stderr, "DEBUG: Wrote body: %d bytes (expected %d)\n", written, injected_len);
                if (written < 0) {
                    fprintf(stderr, "ERROR: Failed to write body: %s\n", strerror(errno));
                }
                
                // ADD THIS: Verify total bytes sent
                fprintf(stderr, "DEBUG: Total sent should be: %d + %zu + %d = %d bytes\n",
                        headers_without_end, strlen(injection), injected_len,
                        headers_without_end + (int)strlen(injection) + injected_len);
                
                fprintf(stderr, "DEBUG: Injected chatbot from header phase\n");
                
                free(updated_headers);
                free(injected_html);
                
                send_to_llm(conn, 9450);
                
                // Reset
                conn->html_offset = 0;
                conn->is_html = false;
                return false;  // Close connection
            }
        }
    }

    return true;
}

// Helper: Initialize streaming decompressor
bool init_streaming_decompressor(struct Connection *conn, unsigned char *first_bytes, int len) {
    if (conn->decompression_initialized) return true;
    
    // Check compression type from magic bytes
    bool is_gzip = (len >= 2 && first_bytes[0] == 0x1f && first_bytes[1] == 0x8b);
    
    if (is_gzip) {
        // Initialize gzip streaming
        conn->gzip_stream = malloc(sizeof(z_stream));
        memset(conn->gzip_stream, 0, sizeof(z_stream));
        
        if (inflateInit2(conn->gzip_stream, 16 + MAX_WBITS) != Z_OK) {
            fprintf(stderr, "ERROR: inflateInit2 failed\n");
            free(conn->gzip_stream);
            conn->gzip_stream = NULL;
            return false;
        }
        
        fprintf(stderr, "DEBUG: Initialized gzip streaming decompressor\n");
    } else {
        // Initialize brotli streaming
        conn->brotli_state = BrotliDecoderCreateInstance(NULL, NULL, NULL);
        if (!conn->brotli_state) {
            fprintf(stderr, "ERROR: BrotliDecoderCreateInstance failed\n");
            return false;
        }
        fprintf(stderr, "DEBUG: Initialized brotli streaming decompressor\n");
    }
    
    conn->decompression_initialized = true;
    return true;
}

// Helper: Decompress a chunk of data
int decompress_chunk(struct Connection *conn, char *input, int input_len, char *output, int output_size) {
    if (conn->gzip_stream) {
        // Gzip streaming decompression
        conn->gzip_stream->next_in = (unsigned char *)input;
        conn->gzip_stream->avail_in = input_len;
        conn->gzip_stream->next_out = (unsigned char *)output;
        conn->gzip_stream->avail_out = output_size;
        
        int ret = inflate(conn->gzip_stream, Z_NO_FLUSH);
        if (ret != Z_OK && ret != Z_STREAM_END) {
            fprintf(stderr, "ERROR: inflate failed with code %d\n", ret);
            return -1;
        }
        
        int decompressed = output_size - conn->gzip_stream->avail_out;
        return decompressed;
        
    } else if (conn->brotli_state) {
        // Brotli streaming decompression
        size_t available_in = input_len;
        const uint8_t *next_in = (const uint8_t *)input;
        size_t available_out = output_size;
        uint8_t *next_out = (uint8_t *)output;
        
        BrotliDecoderResult result = BrotliDecoderDecompressStream(
            conn->brotli_state,
            &available_in,
            &next_in,
            &available_out,
            &next_out,
            NULL
        );
        
        if (result == BROTLI_DECODER_RESULT_ERROR) {
            fprintf(stderr, "ERROR: Brotli decompression failed\n");
            return -1;
        }
        
        int decompressed = output_size - available_out;
        return decompressed;
    }
    
    return -1;
}

// Find <body> tag in buffer, return pointer to it or NULL
// Returns pointer to the '>' character after <body
char *find_body_tag(char *buf, int len) {
    for (int i = 0; i < len - 5; i++) {
        if (buf[i] == '<' &&
            (buf[i+1] == 'b' || buf[i+1] == 'B') &&
            (buf[i+2] == 'o' || buf[i+2] == 'O') &&
            (buf[i+3] == 'd' || buf[i+3] == 'D') &&
            (buf[i+4] == 'y' || buf[i+4] == 'Y') &&
            (buf[i+5] == '>' || buf[i+5] == ' ' || buf[i+5] == '\t' || 
             buf[i+5] == '\n' || buf[i+5] == '\r')) {
            // Found <body, now find the closing >
            for (int j = i + 5; j < len; j++) {
                if (buf[j] == '>') {
                    return buf + j + 1;  // Return position right after >
                }
            }
        }
    }
    return NULL;
}

// Find the closing </head> tag and return a pointer to the '<' character.
// If </head> is not found, return NULL.
char *find_head_close_tag(char *buf, int len) {
    // Search for "</head>" (case-insensitive)
    for (int i = 0; i < len - 7; i++) {
        if (buf[i] == '<' && buf[i+1] == '/' &&
            (buf[i+2] == 'h' || buf[i+2] == 'H') &&
            (buf[i+3] == 'e' || buf[i+3] == 'E') &&
            (buf[i+4] == 'a' || buf[i+4] == 'A') &&
            (buf[i+5] == 'd' || buf[i+5] == 'D') &&
            buf[i+6] == '>') 
        {
            // Found </head>
            return buf + i; // Return pointer to the '<' character of "</head>"
        }
    }
    return NULL;
}

bool read_response_body(int fd, fd_set *all_fds, int llm_fd) {
    struct Connection *conn = fd_to_connection[fd];
    if (!conn) return false;

    int n;
    bool should_retry = false;
    
    if (conn->is_https) {
        n = ssl_read_with_retry(conn->server_ssl, conn->buf, BUFFER_SIZE, &should_retry);
        if (should_retry) return true;
        if (n < 0) return false;
    } else {
        int to_read = BUFFER_SIZE;
        if (conn->content_length > 0) {
            int remaining = conn->content_length - conn->body_bytes_read;
            if (remaining < to_read) {
                to_read = remaining;
            }
        }
        
        n = read(fd, conn->buf, to_read);
    
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return true;
            return false;
        }
    }

    if (n == 0) {
        // Connection closed - handle buffered data
        if (conn->is_html && conn->html_offset > 0) {
            // Decompress if needed
            if (conn->is_compressed) {
                fprintf(stderr, "DEBUG: Decompressing at connection close (%d bytes)\n", conn->html_offset);
                if (!decompress_and_store(conn)) {
                    fprintf(stderr, "ERROR: Failed to decompress HTML\n");
                } else {
                    conn->is_compressed = false;
                }
            }
            
            // Inject chatbot if we haven't sent headers yet
            if (conn->response_headers && !conn->header_sent_to_client) {
                char *body_pos = find_body_tag(conn->LLM_buf, conn->html_offset);
                
                int injected_len = 0;
                char *final_html = NULL;
                
                if (body_pos) {
                    fprintf(stderr, "DEBUG: Found <body>, injecting at connection close\n");
                    final_html = inject_chatbot_into_html(conn->LLM_buf, conn->html_offset, 
                                                         &injected_len, conn->client_fd);
                    if (!final_html) {
                        final_html = conn->LLM_buf;
                        injected_len = conn->html_offset;
                    }
                } else {
                    fprintf(stderr, "DEBUG: No <body> found at connection close\n");
                    final_html = conn->LLM_buf;
                    injected_len = conn->html_offset;
                }
                
                // Send headers
                char *updated_headers = update_content_length_header(conn->response_headers,
                                                                     conn->response_headers_len,
                                                                     injected_len);
                const char *injection = "X-Proxy:CS112\r\n\r\n";
                int headers_without_end = strlen(updated_headers) - 2;
                
                write(conn->client_fd, updated_headers, headers_without_end);
                write(conn->client_fd, injection, strlen(injection));
                write(conn->client_fd, final_html, injected_len);
                
                free(updated_headers);
                if (final_html != conn->LLM_buf) {
                    free(conn->LLM_buf);
                    conn->LLM_buf = final_html;
                    conn->html_offset = injected_len;
                }
            } else if (conn->header_sent_to_client) {
                // Headers already sent, just send body
                write(conn->client_fd, conn->LLM_buf, conn->html_offset);
            }
            
            // Send to LLM
            send_to_llm(conn, 9450);
        }
        
        // Cleanup decompressor
        if (conn->gzip_stream) {
            inflateEnd(conn->gzip_stream);
            free(conn->gzip_stream);
            conn->gzip_stream = NULL;
        }
        if (conn->brotli_state) {
            BrotliDecoderDestroyInstance(conn->brotli_state);
            conn->brotli_state = NULL;
        }
        
        return false;
    }
       
    conn->body_bytes_read += n;

    // === NEW APPROACH: Just accumulate everything ===
    if (conn->is_html) {
        // Just buffer the data (compressed or not)
        buffer_append(conn, conn->buf, n);
        fprintf(stderr, "DEBUG: Accumulated %d bytes (total: %d, body_read: %d, content_length: %d)\n",
                n, conn->html_offset, conn->body_bytes_read, conn->content_length);
    } else {
        // Non-HTML: forward immediately
        if (conn->is_https) {
            ssl_write_with_retry(conn->client_ssl, conn->buf, n, &should_retry);
        } else {
            write(conn->client_fd, conn->buf, n);
        }
    }

    // Check if response is complete
    if (conn->content_length > 0 && conn->body_bytes_read >= conn->content_length) {
        fprintf(stderr, "DEBUG: Response complete - processing accumulated data\n");
        
        if (conn->is_html && conn->html_offset > 0) {
            // === STEP 1: DECOMPRESS IF NEEDED ===
            if (conn->is_compressed) {
                fprintf(stderr, "DEBUG: Decompressing %d bytes...\n", conn->html_offset);
                
                if (!decompress_and_store(conn)) {
                    fprintf(stderr, "ERROR: Final decompression failed\n");
                    return false;
                }
                
                fprintf(stderr, "DEBUG: Decompressed to %d bytes\n", conn->html_offset);
                conn->is_compressed = false;
            }
            
            // === STEP 2: SEARCH FOR <BODY> AND INJECT ===
            char *body_pos = find_body_tag(conn->LLM_buf, conn->html_offset);
            
            int injected_len = 0;
            char *final_html = NULL;
            
            if (body_pos) {
                fprintf(stderr, "DEBUG: Found <body> tag, injecting chatbot\n");
                
                final_html = inject_chatbot_into_html(conn->LLM_buf, conn->html_offset, 
                                                     &injected_len, conn->client_fd);
                
                if (!final_html) {
                    fprintf(stderr, "ERROR: Chatbot injection failed\n");
                    final_html = conn->LLM_buf;
                    injected_len = conn->html_offset;
                }
            } else {
                fprintf(stderr, "DEBUG: No <body> found, sending without injection\n");
                final_html = conn->LLM_buf;
                injected_len = conn->html_offset;
            }
            
            // === STEP 3: SEND HEADERS WITH UPDATED CONTENT-LENGTH ===
            if (conn->response_headers) {
                char *updated_headers = update_content_length_header(conn->response_headers,
                                                                     conn->response_headers_len,
                                                                     injected_len);
                const char *injection = "X-Proxy:CS112\r\n\r\n";
                int headers_without_end = strlen(updated_headers) - 2;
                
                if (conn->is_https) {
                    ssl_write_with_retry(conn->client_ssl, updated_headers,
                                headers_without_end, &should_retry);
                    ssl_write_with_retry(conn->client_ssl, injection,
                                strlen(injection), &should_retry);
                } else {
                    write(conn->client_fd, updated_headers, headers_without_end);
                    write(conn->client_fd, injection, strlen(injection));
                }
                
                free(updated_headers);
            }
            
            // === STEP 4: SEND ENTIRE HTML TO CLIENT ===
            if (conn->is_https) {
                ssl_write_with_retry(conn->client_ssl, final_html, 
                                    injected_len, &should_retry);
            } else {
                write(conn->client_fd, final_html, injected_len);
            }
            
            fprintf(stderr, "DEBUG: Sent %d bytes to client\n", injected_len);
            
            // === STEP 5: SEND TO LLM ===
            if (final_html != conn->LLM_buf) {
                free(conn->LLM_buf);
                conn->LLM_buf = final_html;
                conn->html_offset = injected_len;
                conn->LLM_buf_capacity = injected_len + 1;
            }
            
            send_to_llm(conn, 9450);
            
            // === CLEANUP ===
            if (conn->gzip_stream) {
                inflateEnd(conn->gzip_stream);
                free(conn->gzip_stream);
                conn->gzip_stream = NULL;
            }
            if (conn->brotli_state) {
                BrotliDecoderDestroyInstance(conn->brotli_state);
                conn->brotli_state = NULL;
            }
        }
        
        conn->html_offset = 0;
        conn->is_html = false;
        conn->chatbot_injected = false;
        conn->decompression_initialized = false;
        conn->header_sent_to_client = false;
        
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
    
    new_conn->response_headers = NULL;
    new_conn->response_headers_len = 0;
    new_conn->header_sent_to_client = false;
    
    new_conn->is_compressed = false;
    new_conn->chunked_decode_buf = NULL;
    new_conn->chunked_decode_capacity = 0;
    new_conn->chunked_decode_offset = 0;

    new_conn->url = NULL;
    new_conn->chatbot_injected = false;

    new_conn->gzip_stream = NULL;
    new_conn->brotli_state = NULL;
    new_conn->decompression_initialized = false;
    new_conn->compressed_bytes_consumed = 0;
    
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
        int space_left = TUNNEL_BUFFER_SIZE - conn->tunnel_buf_offset;
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
                    
                    // === PARSE HEADERS FIRST ===
                    char temp_copy[BUFFER_SIZE];
                    int copy_len = (headers_len < BUFFER_SIZE - 1) ? headers_len : BUFFER_SIZE - 1;
                    memcpy(temp_copy, conn->tunnel_buf, copy_len);
                    temp_copy[copy_len] = '\0';
                    
                    int content_length = -1;
                    bool is_chunked = false;
                    bool is_html = false;
                    bool is_compressed = false;
                    parse_response_header(temp_copy, &content_length, &is_chunked, &is_html, &is_compressed);   
                    
                    fprintf(stderr, "DEBUG: Parsed HTTPS headers - is_html=%d, content_length=%d, is_chunked=%d, is_compressed=%d\n",
                            is_html, content_length, is_chunked, is_compressed);
                    
                    // === STORE HEADERS FOR HTML RESPONSES (with Content-Encoding removed) ===
                    if (is_html) {
                        
                        if (conn->response_headers) {
                            free(conn->response_headers);
                        }
                        
                        // Start with a copy of the headers for modification
                        char *modified_headers = strdup(temp_copy);

                        // 1. Remove Content-Encoding (since you decompress before sending to client)
                        char *ce_start = strstr(modified_headers, "Content-Encoding:");
                        if (ce_start) {
                            char *ce_end = strstr(ce_start, "\r\n");
                            if (ce_end) {
                                // Remove the Content-Encoding line
                                memmove(ce_start, ce_end + 2, strlen(ce_end + 2) + 1);
                            }
                        }

                        // 2. Remove Content-Length (since the length will change after decompression/modification)
                        char *cl_start = strstr(modified_headers, "Content-Length:");
                        if (cl_start) {
                            char *cl_end = strstr(cl_start, "\r\n");
                            if (cl_end) {
                                // Remove the Content-Length line
                                memmove(cl_start, cl_end + 2, strlen(cl_end + 2) + 1);
                            }
                        }
                        
                        // Note: If 'Transfer-Encoding: chunked' was present, it remains. 
                        // This is what forces your proxy to re-chunk the body later.

                        conn->response_headers = modified_headers;
                        conn->response_headers_len = strlen(modified_headers);
                        conn->header_sent_to_client = false;

                        fprintf(stderr, "DEBUG: Stored HTTPS headers (removed Content-Encoding/Length, len=%d)\n", 
                                conn->response_headers_len);
                                
                    } else {
                        // For non-HTML, just clear the stored headers since we passthrough immediately
                        if (conn->response_headers) {
                            free(conn->response_headers);
                            conn->response_headers = NULL;
                            conn->response_headers_len = 0;
                        }
                    }
                                        
                    // === UPDATE CONN STATE ===
                    conn->is_html = is_html;
                    conn->is_compressed = is_compressed; // Still useful for decompression logic later
                    conn->content_length = content_length; // Original CL, may not be used if we chunk
                    conn->body_bytes_read = 0;
                    
                    // === NOW DECIDE WHAT TO DO WITH BODY ===
                    if (!conn->is_html) {
                        // For non-HTML, inject X-Proxy header and forward (no decompression/decoding needed)
                        const char *injection = "X-Proxy:CS112\r\n";
                        int inject_point = headers_len - 2;  // Before final \r\n\r\n
                        
                        int written = ssl_write_with_retry(conn->client_ssl, conn->tunnel_buf, 
                                                            inject_point, &should_retry);
                        if (written < 0) return false;
                        
                        written = ssl_write_with_retry(conn->client_ssl, injection, 
                                                        strlen(injection), &should_retry);
                        if (written < 0) return false;
                        
                        written = ssl_write_with_retry(conn->client_ssl, "\r\n", 2, &should_retry);
                        if (written < 0) return false;
                        
                        // Forward any body data we already have
                        int body_in_buffer = conn->tunnel_buf_offset - headers_len;
                        if (body_in_buffer > 0) {
                            written = ssl_write_with_retry(conn->client_ssl,
                                                            conn->tunnel_buf + headers_len,
                                                            body_in_buffer, &should_retry);
                            if (written < 0) return false;
                        }
                        
                        conn->tunnel_buf_offset = 0;
                    } else {
                        // For HTML, move the body data to the start of tunnel_buf for chunk processing
                        int body_in_buffer = conn->tunnel_buf_offset - headers_len;
                        if (body_in_buffer > 0) {
                            memmove(conn->tunnel_buf, conn->tunnel_buf + headers_len, body_in_buffer);
                            conn->tunnel_buf_offset = body_in_buffer;
                            fprintf(stderr, "DEBUG: Moved %d bytes of body to tunnel_buf for chunk processing\n", body_in_buffer);
                        } else {
                            conn->tunnel_buf_offset = 0;
                        }
                    }

                    // === NOW DETERMINE STATE BASED ON RESPONSE TYPE ===
                    if (is_chunked) {
                        if (is_html) {
                            conn->tunnel_state = TUNNEL_READING_CHUNKED_RESPONSE;
                            // tunnel_buf_offset already set above - contains start of first chunk
                            fprintf(stderr, "DEBUG: Entering CHUNKED mode for HTML (compressed=%d, buf_offset=%d)\n", 
                                    is_compressed, conn->tunnel_buf_offset);
                        } else {
                            conn->tunnel_state = TUNNEL_PASSTHROUGH;
                            conn->tunnel_buf_offset = 0;
                            fprintf(stderr, "DEBUG: Entering PASSTHROUGH for non-HTML chunked\n");
                        }
                    } else {
                        // No content-length, no chunked - passthrough until connection closes
                        conn->tunnel_state = TUNNEL_PASSTHROUGH;
                        conn->tunnel_buf_offset = 0;
                        fprintf(stderr, "DEBUG: Entering PASSTHROUGH (no length info)\n");
                    }
                }
                // else: keep buffering until we have complete headers
                break;
            }

            case TUNNEL_READING_RESPONSE_BODY_KNOWN_LENGTH: {
                int to_forward = conn->tunnel_buf_offset;
                if (to_forward > conn->tunnel_body_remaining) {
                    to_forward = conn->tunnel_body_remaining;
                }
                
                fprintf(stderr, "DEBUG: Processing body - to_forward=%d, remaining=%d, buf_offset=%d, compressed=%d, html=%d\n",
                        to_forward, conn->tunnel_body_remaining, conn->tunnel_buf_offset, 
                        conn->is_compressed, conn->is_html);
                
                if (conn->is_html) {
                    char *data_to_process = conn->tunnel_buf;
                    int data_len = to_forward;
                    
                    // === ONLY DECOMPRESS IF ACTUALLY COMPRESSED ===
                    if (conn->is_compressed) {
                        if (!conn->decompression_initialized) {
                            if (!init_streaming_decompressor(conn, (unsigned char *)conn->tunnel_buf, to_forward)) {
                                fprintf(stderr, "ERROR: Failed to init decompressor\n");
                                conn->is_compressed = false;
                                conn->is_html = false;
                                bool should_retry;
                                int written = ssl_write_with_retry(conn->client_ssl, conn->tunnel_buf,
                                                                    to_forward, &should_retry);
                                if (written < 0) return false;
                                
                                // Consume the data
                                conn->tunnel_body_remaining -= to_forward;
                                
                                if (to_forward < conn->tunnel_buf_offset) {
                                    memmove(conn->tunnel_buf, conn->tunnel_buf + to_forward,
                                            conn->tunnel_buf_offset - to_forward);
                                    conn->tunnel_buf_offset -= to_forward;
                                } else {
                                    conn->tunnel_buf_offset = 0;
                                }
                                break;
                            }
                        }
                        
                        // Attempt decompression
                        int decompressed_len = decompress_chunk(conn, conn->tunnel_buf, to_forward, 
                                                            conn->decompress_buffer, BUFFER_SIZE);
                        
                        fprintf(stderr, "DEBUG: Decompression result: %d bytes from %d compressed bytes\n", 
                                decompressed_len, to_forward);
                        
                        if (decompressed_len < 0) {
                            fprintf(stderr, "ERROR: Decompression failed\n");
                            conn->is_html = false;
                            bool should_retry;
                            int written = ssl_write_with_retry(conn->client_ssl, conn->tunnel_buf,
                                                                to_forward, &should_retry);
                            if (written < 0) return false;
                            
                            // Consume the data
                            conn->tunnel_body_remaining -= to_forward;
                            
                            if (to_forward < conn->tunnel_buf_offset) {
                                memmove(conn->tunnel_buf, conn->tunnel_buf + to_forward,
                                        conn->tunnel_buf_offset - to_forward);
                                conn->tunnel_buf_offset -= to_forward;
                            } else {
                                conn->tunnel_buf_offset = 0;
                            }
                            break;
                        }
                        
                        // CRITICAL: Always consume compressed bytes from buffer and counter
                        conn->tunnel_body_remaining -= to_forward;
                        
                        // Move remaining data in buffer
                        if (to_forward < conn->tunnel_buf_offset) {
                            memmove(conn->tunnel_buf, conn->tunnel_buf + to_forward,
                                    conn->tunnel_buf_offset - to_forward);
                            conn->tunnel_buf_offset -= to_forward;
                        } else {
                            conn->tunnel_buf_offset = 0;
                        }
                        
                        // If decompression produced no output yet, just return and wait for more input
                        if (decompressed_len == 0) {
                            fprintf(stderr, "DEBUG: Decompressor needs more input (remaining=%d)\n", 
                                    conn->tunnel_body_remaining);
                            
                            // If we've consumed all compressed data but got no output, 
                            // we might be at the end - check if done
                            if (conn->tunnel_body_remaining <= 0) {
                                fprintf(stderr, "DEBUG: All compressed data consumed, finalizing\n");
                                goto body_complete;
                            }
                            
                            return true;
                        }
                        
                        data_to_process = conn->decompress_buffer;
                        data_len = decompressed_len;
                        
                        fprintf(stderr, "DEBUG: Decompressed %d -> %d bytes (remaining compressed: %d)\n", 
                                to_forward, decompressed_len, conn->tunnel_body_remaining);
                    } else {
                        // === NOT COMPRESSED: Use data from tunnel_buf directly ===
                        // Don't consume yet - we'll do that after we know what data_to_process is
                        data_to_process = conn->tunnel_buf;
                        data_len = to_forward;
                        
                        // NOW consume the data
                        conn->tunnel_body_remaining -= to_forward;
                        
                        if (to_forward < conn->tunnel_buf_offset) {
                            memmove(conn->tunnel_buf, conn->tunnel_buf + to_forward,
                                    conn->tunnel_buf_offset - to_forward);
                            conn->tunnel_buf_offset -= to_forward;
                        } else {
                            conn->tunnel_buf_offset = 0;
                        }
                    }
                    
                    // === INJECTION LOGIC (same for both compressed and uncompressed) ===
                    if (!conn->chatbot_injected) {
                        buffer_append(conn, data_to_process, data_len);
                        
                        char *body_pos = find_body_tag(conn->LLM_buf, conn->html_offset);
                        
                        if (body_pos) {
                            // Found <body> - inject immediately
                            int before_body = body_pos - conn->LLM_buf;
                            
                            fprintf(stderr, "DEBUG: Found <body> in HTTPS at offset %d (total buffered: %d)\n", 
                                    before_body, conn->html_offset);
                            
                            // Send headers
                            if (conn->response_headers && !conn->header_sent_to_client) {
                                bool should_retry;
                                const char *injection = "\r\nX-Proxy:CS112\r\n\r\n";
                                int headers_without_end = conn->response_headers_len - 2;
                                ssl_write_with_retry(conn->client_ssl, conn->response_headers,
                                        headers_without_end, &should_retry);
                                ssl_write_with_retry(conn->client_ssl, injection,
                                        strlen(injection), &should_retry);
                                conn->header_sent_to_client = true;
                            }
                            
                            // Send before <body>
                            bool should_retry;
                            ssl_write_with_retry(conn->client_ssl, conn->LLM_buf,
                                    before_body, &should_retry);
                            
                            // Inject chatbot
                            char *snippet = generate_chatbot_snippet(conn->client_fd);
                            ssl_write_with_retry(conn->client_ssl, snippet,
                                    strlen(snippet), &should_retry);
                            free(snippet);
                            
                            // Send rest
                            int after_body = conn->html_offset - before_body;
                            ssl_write_with_retry(conn->client_ssl, body_pos,
                                    after_body, &should_retry);
                            
                            conn->chatbot_injected = true;
                            
                        } else {
                            // === STREAM SAFE PORTION ===
                            const int SAFETY_MARGIN = 10;
                            
                            if (conn->html_offset > SAFETY_MARGIN) {
                                int safe_to_send = conn->html_offset - SAFETY_MARGIN;
                                
                                // Send headers first time only
                                if (!conn->header_sent_to_client) {
                                    if (conn->response_headers) {
                                        bool should_retry;
                                        const char *injection = "\r\nX-Proxy:CS112\r\n\r\n";
                                        int headers_without_end = conn->response_headers_len - 2;
                                        ssl_write_with_retry(conn->client_ssl, conn->response_headers,
                                                    headers_without_end, &should_retry);
                                        ssl_write_with_retry(conn->client_ssl, injection,
                                                    strlen(injection), &should_retry);
                                    }
                                    conn->header_sent_to_client = true;
                                }
                                
                                // Send safe portion
                                bool should_retry;
                                ssl_write_with_retry(conn->client_ssl, conn->LLM_buf,
                                            safe_to_send, &should_retry);
                                
                                fprintf(stderr, "DEBUG: HTTPS streamed %d bytes (keeping %d in buffer)\n", 
                                        safe_to_send, SAFETY_MARGIN);
                                
                                // Keep last SAFETY_MARGIN bytes
                                memmove(conn->LLM_buf, conn->LLM_buf + safe_to_send, SAFETY_MARGIN);
                                conn->html_offset = SAFETY_MARGIN;
                            }
                        }
                    } else {
                        // Already injected - forward immediately and accumulate for LLM
                        bool should_retry;
                        ssl_write_with_retry(conn->client_ssl, data_to_process,
                                    data_len, &should_retry);
                        buffer_append(conn, data_to_process, data_len);
                    }
                } else {
                    // Non-HTML: forward immediately
                    bool should_retry;
                    int written = ssl_write_with_retry(conn->client_ssl, conn->tunnel_buf,
                                                        to_forward, &should_retry);
                    if (written < 0) return false;
                    
                    // CRITICAL: Consume the data
                    conn->tunnel_body_remaining -= to_forward;
                    
                    // Move excess data
                    if (to_forward < conn->tunnel_buf_offset) {
                        memmove(conn->tunnel_buf, conn->tunnel_buf + to_forward,
                                conn->tunnel_buf_offset - to_forward);
                        conn->tunnel_buf_offset -= to_forward;
                    } else {
                        conn->tunnel_buf_offset = 0;
                    }
                    
                    fprintf(stderr, "DEBUG: Forwarded non-HTML %d bytes, remaining=%d\n", 
                            to_forward, conn->tunnel_body_remaining);
                }
                
            body_complete:
                // Check if complete
                if (conn->tunnel_body_remaining <= 0) {
                    fprintf(stderr, "DEBUG: HTTPS response complete (html=%d, html_offset=%d, injected=%d)\n",
                            conn->is_html, conn->html_offset, conn->chatbot_injected);
                    
                    // Send any remaining buffered data
                    if (conn->is_html) {
                        bool should_retry;
                        // HTML-specific cleanup
                        if (conn->html_offset > 0 && !conn->chatbot_injected) {
                            fprintf(stderr, "DEBUG: Sending remaining buffered HTML without injection (%d bytes)\n",
                                    conn->html_offset);
                            
                            if (conn->response_headers && !conn->header_sent_to_client) {
                                const char *injection = "\r\nX-Proxy:CS112\r\n\r\n";
                                int headers_without_end = conn->response_headers_len - 2;
                                ssl_write_with_retry(conn->client_ssl, conn->response_headers,
                                            headers_without_end, &should_retry);
                                ssl_write_with_retry(conn->client_ssl, injection,
                                            strlen(injection), &should_retry);
                            }
                            ssl_write_with_retry(conn->client_ssl, conn->LLM_buf,
                                        conn->html_offset, &should_retry);
                        } else if (conn->html_offset > 0 && conn->chatbot_injected) {
                            // Send any remaining data after injection
                            fprintf(stderr, "DEBUG: Sending final buffered chunk (%d bytes)\n", conn->html_offset);
                            ssl_write_with_retry(conn->client_ssl, conn->LLM_buf,
                                        conn->html_offset, &should_retry);
                        }
                        
                        // Send to LLM
                        if (conn->html_offset > 0) {
                            fprintf(stderr, "DEBUG: Sending %d bytes to LLM\n", conn->html_offset);
                            send_to_llm(conn, 9450);
                        }
                        
                        // Cleanup decompressor
                        if (conn->gzip_stream) {
                            inflateEnd(conn->gzip_stream);
                            free(conn->gzip_stream);
                            conn->gzip_stream = NULL;
                        }
                        if (conn->brotli_state) {
                            BrotliDecoderDestroyInstance(conn->brotli_state);
                            conn->brotli_state = NULL;
                        }
                        
                        conn->html_offset = 0;
                        conn->is_html = false;
                        conn->is_compressed = false;
                        conn->chatbot_injected = false;
                        conn->decompression_initialized = false;
                        conn->header_sent_to_client = false;
                    }
                    
                    // ALWAYS reset tunnel state for next response (HTML or not)
                    conn->tunnel_state = TUNNEL_EXPECT_RESPONSE_HEADERS;
                }
                break;
            }

            case TUNNEL_READING_CHUNKED_RESPONSE: {
                fprintf(stderr, "DEBUG: CHUNKED state - have %d bytes in tunnel_buf\n", conn->tunnel_buf_offset);
                
                int buf_offset = 0;
                bool found_last_chunk = false;
                
                while (buf_offset < conn->tunnel_buf_offset) {
                    // Parse chunk size
                    int chunk_size = parse_chunk_size(conn->tunnel_buf + buf_offset, 
                                                    conn->tunnel_buf_offset - buf_offset);
                    
                    fprintf(stderr, "DEBUG: Parsed chunk_size=%d at buf_offset=%d (have %d bytes total)\n", 
                            chunk_size, buf_offset, conn->tunnel_buf_offset);
                    
                    if (chunk_size == -1) {
                        fprintf(stderr, "DEBUG: Incomplete chunk size line, breaking\n");
                        break;  // Need more data
                    }
                    
                    if (chunk_size == 0) {
                        fprintf(stderr, "DEBUG: Last chunk (0) found\n");
                        found_last_chunk = true;
                        buf_offset += 5;  // Consume "0\r\n\r\n"
                        break;
                    }
                    
                    // Find end of size line
                    char *size_line_end = strstr(conn->tunnel_buf + buf_offset, "\r\n");
                    if (!size_line_end) {
                        fprintf(stderr, "DEBUG: No CRLF after chunk size, breaking\n");
                        break;
                    }
                    size_line_end += 2;
                    int size_line_len = size_line_end - (conn->tunnel_buf + buf_offset);
                    
                    // Check if we have complete chunk data + trailing CRLF
                    int bytes_needed = size_line_len + chunk_size + 2;
                    int bytes_available = conn->tunnel_buf_offset - buf_offset;
                    
                    if (bytes_available < bytes_needed) {
                        fprintf(stderr, "DEBUG: Incomplete chunk: need %d bytes, have %d. Breaking.\n", 
                                bytes_needed, bytes_available);
                        break;  // Need more data
                    }
                    
                    fprintf(stderr, "DEBUG: Have complete chunk of %d bytes\n", chunk_size);
                    
                    // Extract chunk data (skip size line)
                    char *chunk_data = conn->tunnel_buf + buf_offset + size_line_len;
                    
                    if (conn->is_html) {
                        // === NEW: Just accumulate compressed data, don't decompress yet ===
                        buffer_append(conn, chunk_data, chunk_size);
                        fprintf(stderr, "DEBUG: Accumulated %d bytes (total now: %d)\n", 
                                chunk_size, conn->html_offset);
                        
                    } else {
                        // === NON-HTML: FORWARD ORIGINAL CHUNKED DATA AS-IS ===
                        bool should_retry;
                        ssl_write_with_retry(conn->client_ssl, 
                                            conn->tunnel_buf + buf_offset,  // Includes size line
                                            bytes_needed,                    // Entire chunk with framing
                                            &should_retry);
                    }
                    
                    // Consume this chunk
                    buf_offset += bytes_needed;
                }
                
                // Remove processed data from buffer
                if (buf_offset > 0) {
                    memmove(conn->tunnel_buf, conn->tunnel_buf + buf_offset,
                            conn->tunnel_buf_offset - buf_offset);
                    conn->tunnel_buf_offset -= buf_offset;
                    fprintf(stderr, "DEBUG: Consumed %d bytes, %d remaining\n", buf_offset, conn->tunnel_buf_offset);
                }
                
                // === NEW: Handle completion - decompress and inject at the END ===
                if (found_last_chunk) {
                    fprintf(stderr, "DEBUG: Chunked response complete\n");
                    
                    if (conn->is_html && conn->html_offset > 0) {
                        fprintf(stderr, "DEBUG: Starting final processing - accumulated %d bytes (compressed=%d)\n",
                                conn->html_offset, conn->is_compressed);
                        
                        // === STEP 1: DECOMPRESS EVERYTHING AT ONCE ===
                        if (conn->is_compressed) {
                            fprintf(stderr, "DEBUG: Decompressing %d bytes...\n", conn->html_offset);
                            
                            if (!decompress_and_store(conn)) {
                                fprintf(stderr, "ERROR: Final decompression failed\n");
                                return false;
                            }
                            
                            fprintf(stderr, "DEBUG: Decompressed to %d bytes\n", conn->html_offset);
                            conn->is_compressed = false;
                        }
                        
                        // === STEP 2: SEARCH FOR <BODY> AND INJECT ===
                        char *body_pos = find_body_tag(conn->LLM_buf, conn->html_offset);
                        
                        int injected_len = 0;
                        char *final_html = NULL;
                        
                        if (body_pos) {
                            fprintf(stderr, "DEBUG: Found <body> tag, injecting chatbot\n");
                            
                            // Inject chatbot
                            final_html = inject_chatbot_into_html(conn->LLM_buf, conn->html_offset, 
                                                                &injected_len, conn->client_fd);
                            
                            if (!final_html) {
                                fprintf(stderr, "ERROR: Chatbot injection failed\n");
                                final_html = conn->LLM_buf;
                                injected_len = conn->html_offset;
                            }
                        } else {
                            fprintf(stderr, "DEBUG: No <body> found, sending without injection\n");
                            final_html = conn->LLM_buf;
                            injected_len = conn->html_offset;
                        }
                        
                        // === STEP 3: SEND HEADERS ===
                        if (conn->response_headers) {
                            bool should_retry;
                            const char *injection = "\r\nX-Proxy:CS112\r\n\r\n";
                            int headers_without_end = conn->response_headers_len - 4;
                            
                            ssl_write_with_retry(conn->client_ssl, conn->response_headers,
                                        headers_without_end, &should_retry);
                            ssl_write_with_retry(conn->client_ssl, injection,
                                        strlen(injection), &should_retry);
                        }
                        
                        // === STEP 4: SEND ENTIRE HTML TO CLIENT ===
                        bool should_retry;
                        ssl_write_with_retry(conn->client_ssl, final_html, 
                                            injected_len, &should_retry);
                        
                        fprintf(stderr, "DEBUG: Sent %d bytes to client\n", injected_len);
                        
                        // === STEP 5: SEND TO LLM ===
                        // Update LLM_buf if we created a new buffer for injection
                        if (final_html != conn->LLM_buf) {
                            free(conn->LLM_buf);
                            conn->LLM_buf = final_html;
                            conn->html_offset = injected_len;
                            conn->LLM_buf_capacity = injected_len + 1;
                        }
                        
                        send_to_llm(conn, 9450);
                        
                        // === STEP 6: SEND TERMINATING CHUNK ===
                        ssl_write_with_retry(conn->client_ssl, "0\r\n\r\n", 5, &should_retry);
                        fprintf(stderr, "DEBUG: Sent terminating chunk\n");
                    } else {
                        // Non-HTML chunked - send terminating chunk
                        bool should_retry;
                        ssl_write_with_retry(conn->client_ssl, "0\r\n\r\n", 5, &should_retry);
                    }
                    
                    // === CLEANUP ===
                    conn->html_offset = 0;
                    conn->is_html = false;
                    conn->is_compressed = false;
                    conn->decompression_initialized = false;
                    conn->chatbot_injected = false;
                    conn->header_sent_to_client = false;
                    conn->tunnel_state = TUNNEL_EXPECT_RESPONSE_HEADERS;
                    conn->tunnel_buf_offset = 0;
                }
                
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

void send_as_chunk(SSL *ssl, char *data, int len) {
    if (len == 0) return;
    
    char size_line[32];
    snprintf(size_line, sizeof(size_line), "%x\r\n", len);
    
    bool should_retry;
    int written1 = ssl_write_with_retry(ssl, size_line, strlen(size_line), &should_retry);
    int written2 = ssl_write_with_retry(ssl, data, len, &should_retry);
    int written3 = ssl_write_with_retry(ssl, "\r\n", 2, &should_retry);
    
    fprintf(stderr, "DEBUG: send_as_chunk - size_line=%d, data=%d, crlf=%d (len=%d)\n", 
            written1, written2, written3, len);
}

// send HTML buffer to Flask for analysis, then reset state
void send_and_reset_html(struct Connection *conn, int llm_fd) {
    if (!conn->is_html || conn->html_offset == 0) {
        return;
    }

    // Decompress if needed (for chunked responses that were stored compressed)
    if (conn->is_compressed) {
        if (!decompress_and_store(conn)) {
            fprintf(stderr, "ERROR: Failed to decompress HTML in send_and_reset\n");
        } else {
            conn->is_compressed = false;
        }
    }

    // HTML should already be decompressed at this point
    send_to_llm(conn, 9450);

    // clean up
    conn->html_offset = 0;
    conn->is_html = false;
    conn->is_compressed = false;
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
    free(conn->response_headers);
    free(conn->url);

    free(conn);
    *conn_ptr = NULL;
}
