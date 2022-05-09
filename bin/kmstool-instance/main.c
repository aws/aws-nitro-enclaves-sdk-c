#if defined(_WIN32)
#    include <VirtioVsock.h>
#endif
#include <aws/common/command_line_parser.h>
#include <aws/common/condition_variable.h>
#include <aws/common/encoding.h>
#include <aws/common/logging.h>
#include <aws/common/mutex.h>
#include <aws/common/string.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/host_resolver.h>

#include <aws/auth/credentials.h>

#include <json-c/json.h>

#ifndef _WIN32
#    include <linux/vm_sockets.h>
#    include <sys/socket.h>

#    include <errno.h>
#    include <unistd.h>
typedef int socket_t;
#else
/* json-c includes some int types to support older compiler versions
that did not include inttypes.h - avoid the warning */
#    pragma warning(push)
#    pragma warning(disable : 4005)
#    include <inttypes.h>
#    pragma warning(pop)
typedef SSIZE_T ssize_t;
typedef SOCKET socket_t;
#endif

#define SERVICE_PORT 3000
#define BUF_SIZE 8192

struct app_ctx {
    struct aws_allocator *allocator;
    const struct aws_string *message;
    const struct aws_string *region;
    uint32_t port;
    uint32_t cid;
    socket_t peer_fd;

    char peer_buffer[BUF_SIZE];
    size_t peer_buffer_len;

    struct aws_credentials *credentials;
    bool aws_credentials_done;
    struct aws_mutex mutex;
    struct aws_condition_variable c_var;
};

static void s_on_shutdown_complete(void *user_data) {
    (void)user_data;
}

static void s_usage(int exit_code) {
    fprintf(stderr, "usage: enclave_server [options] ENCRYPTED_MESSAGE\n");
    fprintf(stderr, "\n Options: \n\n");
    fprintf(stderr, "    --port PORT: Enclave service PORT. Default: 3000\n");
    fprintf(stderr, "    --cid CID: Enclave CID\n");
    fprintf(
        stderr,
        "    --region REGION: AWS region to use for KMS; if enclave "
        "already has a region set via its arguments, this will cause an error\n");
    fprintf(stderr, "    ENCRYPTED_MESSAGE: Base64 encoded message\n");
    fprintf(stderr, "    --help: Display this message and exit\n");
    exit(exit_code);
}

static struct aws_cli_option s_long_options[] = {
    {"port", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'p'},
    {"cid", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'c'},
    {"region", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'r'},
    {"help", AWS_CLI_OPTIONS_NO_ARGUMENT, NULL, 'h'},
    {NULL, 0, NULL, 0},
};

static void s_parse_options(int argc, char **argv, struct app_ctx *ctx) {
    ctx->port = SERVICE_PORT;
    ctx->cid = 0;
    ctx->message = NULL;

    while (true) {
        int option_index = 0;
        int c = aws_cli_getopt_long(argc, argv, "p:c:r:h", s_long_options, &option_index);
        if (c == -1) {
            break;
        }

        switch (c) {
            case 0:
                break;
            case 0x02:
                if (ctx->message != NULL) {
                    s_usage(1);
                }
                ctx->message = aws_string_new_from_c_str(ctx->allocator, aws_cli_positional_arg);
                break;
            case 'p':
                ctx->port = atoi(aws_cli_optarg);
                break;
            case 'c':
                ctx->cid = atoi(aws_cli_optarg);
                break;
            case 'r':
                ctx->region = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                break;
            case 'h':
                s_usage(0);
                break;
            default:
                fprintf(stderr, "Unknown option\n");
                s_usage(1);
                break;
        }
    }

    if (ctx->cid == 0) {
        s_usage(1);
    }


    if (ctx->message == NULL) {
        s_usage(1);
    }
}

void s_creds_callback(struct aws_credentials *credentials, int error_code, void *user_data) {
    (void)error_code;
    struct app_ctx *app_ctx = user_data;

    aws_mutex_lock(&app_ctx->mutex);
    app_ctx->credentials = credentials;
    if (credentials != NULL) {
        aws_credentials_acquire(credentials);
    }
    app_ctx->aws_credentials_done = true;
    aws_condition_variable_notify_all(&app_ctx->c_var);
    aws_mutex_unlock(&app_ctx->mutex);
}

bool s_creds_pred(void *ctx) {
    struct app_ctx *app_ctx = ctx;
    return app_ctx->aws_credentials_done;
}

int s_get_credentials(struct app_ctx *app_ctx) {
    int rc = AWS_OP_SUCCESS;
    struct aws_credentials_provider *provider_chain = NULL;
    struct aws_host_resolver *resolver = NULL;
    struct aws_event_loop_group *el_group = aws_event_loop_group_new_default(app_ctx->allocator, 1, NULL);
    if (el_group == NULL) {
        rc = AWS_OP_ERR;
        goto cleanup;
    }

    struct aws_host_resolver_default_options resolver_options = {
        .el_group = el_group,
        .max_entries = 4,
    };

    resolver = aws_host_resolver_new_default(app_ctx->allocator, &resolver_options);
    if (resolver == NULL) {
        rc = AWS_OP_ERR;
        goto cleanup;
    }

    struct aws_client_bootstrap_options bootstrap_options = {0};
    bootstrap_options.host_resolver = resolver;
    bootstrap_options.on_shutdown_complete = NULL;
    bootstrap_options.host_resolution_config = NULL;
    bootstrap_options.user_data = NULL;
    bootstrap_options.event_loop_group = el_group;

    struct aws_client_bootstrap *bootstrap = aws_client_bootstrap_new(app_ctx->allocator, &bootstrap_options);
    if (bootstrap == NULL) {
        rc = AWS_OP_ERR;
        goto cleanup;
    }

    struct aws_credentials_provider_chain_default_options chain_options = {0};
    chain_options.bootstrap = bootstrap;
    chain_options.shutdown_options.shutdown_callback = s_on_shutdown_complete;
    chain_options.shutdown_options.shutdown_user_data = NULL;

    provider_chain = aws_credentials_provider_new_chain_default(app_ctx->allocator, &chain_options);
    if (provider_chain == NULL) {
        rc = AWS_OP_ERR;
        goto cleanup;
    }

    app_ctx->aws_credentials_done = false;
    rc = aws_credentials_provider_get_credentials(provider_chain, s_creds_callback, app_ctx);
    if (rc != AWS_OP_SUCCESS) {
        goto cleanup;
    }

    aws_mutex_lock(&app_ctx->mutex);
    aws_condition_variable_wait_pred(&app_ctx->c_var, &app_ctx->mutex, s_creds_pred, app_ctx);
    aws_mutex_unlock(&app_ctx->mutex);

    if (app_ctx->credentials == NULL) {
        rc = AWS_OP_ERR;
    }

cleanup:
    aws_credentials_provider_release(provider_chain);
    aws_host_resolver_release(resolver);
    aws_event_loop_group_release(el_group);

    return rc;
}

void s_close_socket(socket_t peer_fd) {
#if defined(_WIN32)
    closesocket(peer_fd);
#else
    close(peer_fd);
#endif
}

int s_socket_init(void) {
#if defined(_WIN32)
    WSADATA wsadata;
    int err;

    err = WSAStartup(MAKEWORD(2, 2), &wsadata);
    if (err != 0) {
        fprintf(stderr, "Failed to initialize Winsock: %" PRIu32 "\n", err);
        /* Overwrite the error with -1.  WSA errors are not negative */
        err = -1;
    }
    return err;
#else
    return 0;
#endif
}

void s_socket_cleanup(void) {
#if defined(_WIN32)
    WSACleanup();
#endif
}

/**
 * Helper to ensure that we never send more than INT_MAX to socket send/recv calls.
 * Windows sockets do not accept more than this per send/recv call
 *
 * @param[in]    len    Length of the buffer for current socket send/recv call.
 */
int s_get_max_socket_io_len(size_t len) {
    if (len > INT_MAX) {
        len = INT_MAX;
    }
    return (int)len;
}

ssize_t s_write_all(socket_t peer_fd, const char *msg, size_t msg_len) {
    size_t total_sent = 0;
    while (total_sent < msg_len) {
        int bytes_to_send = s_get_max_socket_io_len(msg_len - total_sent);
        ssize_t sent = send(peer_fd, msg + total_sent, bytes_to_send, 0);
#if defined(_WIN32)
        int wsaerr = WSAGetLastError();
        if (sent <= 0 && (wsaerr == WSAEINPROGRESS || wsaerr == WSAEINTR)) {
#else
        if (sent <= 0 && (errno == EAGAIN || errno == EINTR)) {
#endif
            continue;
        } else if (sent < 0) {
            return -1;
        } else {
            total_sent += sent;
        }
    }
    return total_sent;
}

int s_write_object(socket_t peer_fd, struct json_object *obj) {
    if (obj == NULL) {
        return AWS_OP_ERR;
    }
    const char *json_str = json_object_to_json_string(obj);
    if (json_str == NULL) {
        return AWS_OP_ERR;
    }
    printf("Object = %s\n", json_str);
    ssize_t rc = s_write_all(peer_fd, json_str, strlen(json_str) + 1);
    json_object_put(obj);
    if (rc <= 0) {
        return AWS_OP_ERR;
    } else {
        return AWS_OP_SUCCESS;
    }
}

int s_send_credentials(struct app_ctx *app_ctx) {
    struct json_object *set_client = json_object_new_object();
    json_object_object_add(set_client, "Operation", json_object_new_string("SetClient"));

    struct aws_byte_cursor access_key_id = aws_credentials_get_access_key_id(app_ctx->credentials);
    struct aws_byte_cursor secret_access_key = aws_credentials_get_secret_access_key(app_ctx->credentials);
    struct aws_byte_cursor session_token = aws_credentials_get_session_token(app_ctx->credentials);

    if (!aws_byte_cursor_is_valid(&access_key_id) || !aws_byte_cursor_is_valid(&secret_access_key) ||
        access_key_id.len == 0 || secret_access_key.len == 0 || !aws_byte_cursor_is_valid(&session_token)) {
        fprintf(stderr, "Empty credentials\n");
        return AWS_OP_ERR;
    }

    struct aws_byte_buf access_key_id_buf, secret_access_key_buf, session_token_buf;

    /* Prepare AwsAccessKeyId. */
    aws_byte_buf_init(&access_key_id_buf, app_ctx->allocator, access_key_id.len + 1);
    aws_byte_buf_append(&access_key_id_buf, &access_key_id);
    aws_byte_buf_append_null_terminator(&access_key_id_buf);

    /* Prepare AwsSecretAccessKey. */
    aws_byte_buf_init(&secret_access_key_buf, app_ctx->allocator, secret_access_key.len + 1);
    aws_byte_buf_append(&secret_access_key_buf, &secret_access_key);
    aws_byte_buf_append_null_terminator(&secret_access_key_buf);

    /* Set AwsAccessKeyId. */
    json_object_object_add(
        set_client, "AwsAccessKeyId", json_object_new_string((const char *)access_key_id_buf.buffer));

    /* Set AwsSecretAccessKey */
    json_object_object_add(
        set_client, "AwsSecretAccessKey", json_object_new_string((const char *)secret_access_key_buf.buffer));

    /* If AwsSessionToken is present, prepare and send it. */
    if (session_token.len > 0) {
        aws_byte_buf_init(&session_token_buf, app_ctx->allocator, session_token.len + 1);
        aws_byte_buf_append(&session_token_buf, &session_token);
        aws_byte_buf_append_null_terminator(&session_token_buf);
        printf(PRInSTR "\n", AWS_BYTE_BUF_PRI(session_token_buf));

        json_object_object_add(
            set_client, "AwsSessionToken", json_object_new_string((const char *)session_token_buf.buffer));
    }

    /* If targeting a particular region, prepare and set it. */
    if (aws_string_is_valid(app_ctx->region)) {
        json_object_object_add(set_client, "AwsRegion", json_object_new_string(aws_string_c_str(app_ctx->region)));
    }

    aws_byte_buf_clean_up_secure(&access_key_id_buf);
    aws_byte_buf_clean_up_secure(&secret_access_key_buf);
    if (aws_byte_buf_is_valid(&session_token_buf)) {
        aws_byte_buf_clean_up_secure(&session_token_buf);
    }
    return s_write_object(app_ctx->peer_fd, set_client);
}

void s_handle_status(struct app_ctx *app_ctx) {
    struct json_object *object = NULL;
    while (true) {
        char *sep = memchr(app_ctx->peer_buffer, '\0', app_ctx->peer_buffer_len);
        if (app_ctx->peer_buffer_len == 0 || sep == NULL) {
            /* Buffer full, but no message available. */
            if (app_ctx->peer_buffer_len >= sizeof(app_ctx->peer_buffer)) {
                fprintf(stderr, "Reply too large.\n");
                exit(1);
            }

            int bytes_to_read = s_get_max_socket_io_len(sizeof(app_ctx->peer_buffer) - app_ctx->peer_buffer_len);
            // Read data from socket if no complete message is available
            ssize_t bytes = recv(app_ctx->peer_fd, app_ctx->peer_buffer + app_ctx->peer_buffer_len, bytes_to_read, 0);
            if (bytes == -1) {
#if defined(_WIN32)
                int wsaerr = WSAGetLastError();
                if (wsaerr == WSAEINPROGRESS || wsaerr == WSAEINTR) {
#else
                if (errno == EAGAIN || errno == EINTR) {
#endif
                    /* Retry operation. */
                    continue;
                }
                perror("Socket read error: ");
                exit(1);
            } else if (bytes == 0) {
                /* Peer closed socket. */
                fprintf(stderr, "Peer peer_bufferfer closed before message was fully read.\n");
                exit(1);
            } else {
                /* Update counter and then check for object. */
                app_ctx->peer_buffer_len += bytes;
                continue;
            }
        }

        /* Safe, because we know the peer_bufferfer has a 0 before the end. */
        fprintf(stderr, "Object = %s\n", app_ctx->peer_buffer);
        object = json_tokener_parse(app_ctx->peer_buffer);

        /* Remove message from peer_bufferfer */
        app_ctx->peer_buffer_len -= (sep + 1 - app_ctx->peer_buffer);
        memmove(app_ctx->peer_buffer, sep + 1, app_ctx->peer_buffer_len);
        break;
    }
    if (object == NULL) {
        fprintf(stderr, "Could not decode JSON object.\n");
        exit(1);
    }
    struct json_object *status = json_object_object_get(object, "Status");
    if (status == NULL || !json_object_is_type(status, json_type_string)) {
        fprintf(stderr, "Invalid reply\n");
        exit(1);
    }

    bool status_ok = strcmp(json_object_get_string(status), "Ok") == 0;

    struct json_object *message = json_object_object_get(object, "Message");
    if (message == NULL) {
        goto end;
    }

    if (!json_object_is_type(message, json_type_string)) {
        fprintf(stderr, "Invalid reply\n");
        exit(1);
    }

    if (status_ok) {
        size_t msg_len;
        struct aws_byte_buf msg;
        struct aws_byte_cursor msg_b64 = aws_byte_cursor_from_c_str(json_object_get_string(message));
        aws_base64_compute_decoded_len(&msg_b64, &msg_len);
        aws_byte_buf_init(&msg, app_ctx->allocator, msg_len);
        aws_base64_decode(&msg_b64, &msg);
        printf(PRInSTR "\n", AWS_BYTE_BUF_PRI(msg));
    } else {
        fprintf(stderr, "Error: %s\n", json_object_get_string(message));
    }

end:
    json_object_put(object);
    if (status_ok == false) {
        exit(1);
    }
}

int s_send_decrypt_command(struct app_ctx *app_ctx) {
    struct json_object *decrypt = json_object_new_object();
    json_object_object_add(decrypt, "Operation", json_object_new_string("Decrypt"));
    json_object_object_add(decrypt, "Ciphertext", json_object_new_string(aws_string_c_str(app_ctx->message)));
    return s_write_object(app_ctx->peer_fd, decrypt);
}

int main(int argc, char **argv) {
    struct app_ctx app_ctx;
    int rc = 0;
    app_ctx.allocator = aws_default_allocator();
    aws_auth_library_init(app_ctx.allocator);
    s_parse_options(argc, argv, &app_ctx);
    aws_mutex_init(&app_ctx.mutex);
    aws_condition_variable_init(&app_ctx.c_var);
    app_ctx.peer_buffer_len = 0;

    struct aws_logger err_logger;

    struct aws_logger_standard_options options = {0};
    options.file = stderr;
    options.level = AWS_LL_DEBUG;
    options.filename = NULL;

    aws_logger_init_standard(&err_logger, app_ctx.allocator, &options);
    aws_logger_set(&err_logger);

    rc = s_socket_init();
    if (rc < 0) {
        fprintf(stderr, "Could not initialize sockets");
        exit(1);
    }

    app_ctx.peer_fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (app_ctx.peer_fd < 0) {
        perror("Could not create vsock port");
        s_socket_cleanup();
        exit(1);
    }

    struct sockaddr_vm svm = {0};
    svm.svm_family = AF_VSOCK;
    svm.svm_cid = app_ctx.cid;
    svm.svm_port = app_ctx.port;
    svm.svm_reserved1 = 0; /* needs to be set to 0 */

    rc = connect(app_ctx.peer_fd, (struct sockaddr *)&svm, sizeof(svm));
    if (rc < 0) {
        fprintf(stderr, "Could not connect to vsock %" PRIu32 ".%" PRIu32 ".\n", app_ctx.cid, app_ctx.port);
        s_close_socket(app_ctx.peer_fd);
        s_socket_cleanup();
        exit(1);
    }

    rc = s_get_credentials(&app_ctx);
    if (rc != AWS_OP_SUCCESS) {
        fprintf(stderr, "Could not get credentials\n");
        s_close_socket(app_ctx.peer_fd);
        aws_credentials_release(app_ctx.credentials);
        s_socket_cleanup();
        exit(1);
    }

    rc = s_send_credentials(&app_ctx);
    if (rc != AWS_OP_SUCCESS) {
        fprintf(stderr, "Could not send credentials\n");
        s_close_socket(app_ctx.peer_fd);
        aws_credentials_release(app_ctx.credentials);
        s_socket_cleanup();
        exit(1);
    }
    s_handle_status(&app_ctx);

    rc = s_send_decrypt_command(&app_ctx);
    if (rc != AWS_OP_SUCCESS) {
        fprintf(stderr, "Could not send decrypt command\n");
        s_close_socket(app_ctx.peer_fd);
        aws_credentials_release(app_ctx.credentials);
        s_socket_cleanup();
        exit(1);
    }
    s_handle_status(&app_ctx);

    s_close_socket(app_ctx.peer_fd);
    aws_mutex_clean_up(&app_ctx.mutex);
    aws_condition_variable_clean_up(&app_ctx.c_var);
    aws_credentials_release(app_ctx.credentials);

    s_socket_cleanup();
    return 0;
}
