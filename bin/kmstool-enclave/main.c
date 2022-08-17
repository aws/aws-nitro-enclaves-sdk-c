#include <aws/nitro_enclaves/kms.h>
#include <aws/nitro_enclaves/nitro_enclaves.h>

#include <aws/common/command_line_parser.h>
#include <aws/common/encoding.h>
#include <aws/common/logging.h>

#include <json-c/json.h>

#include <linux/vm_sockets.h>
#include <sys/socket.h>

#include <errno.h>
#include <unistd.h>

#define SERVICE_PORT 3000
#define PROXY_PORT 8000
#define BUF_SIZE 8192
AWS_STATIC_STRING_FROM_LITERAL(default_region, "us-east-1");

enum status {
    STATUS_OK,
    STATUS_ERR,
};

#define fail_on(cond, label, msg)                                                                                      \
    if (cond) {                                                                                                        \
        err_msg = NULL;                                                                                                \
        if (msg != NULL) {                                                                                             \
            fprintf(stderr, "%s\n", msg);                                                                              \
            err_msg = msg;                                                                                             \
        }                                                                                                              \
        goto label;                                                                                                    \
    }

#define break_on(cond)                                                                                                 \
    if (cond) {                                                                                                        \
        break;                                                                                                         \
    }

struct app_ctx {
    /* Allocator to use for memory allocations. */
    struct aws_allocator *allocator;
    /* KMS region to use. */
    const struct aws_string *region;
    /* vsock port on which to open service. */
    uint32_t port;
    /* vsock port on which vsock-proxy is available in parent. */
    uint32_t proxy_port;
    /* alternative kms endpoint hostname */
    const struct aws_string *kms_endpoint;
};

static void s_usage(int exit_code) {
    fprintf(stderr, "usage: enclave_server [options]\n");
    fprintf(stderr, "\n Options: \n\n");
    fprintf(stderr, "    --region REGION: AWS region to use for KMS. Default: us-east-1.\n");
    fprintf(stderr, "    --port PORT: Await new connections on PORT. Default: 3000\n");
    fprintf(stderr, "    --proxy-port PORT: Connect to KMS proxy on PORT. Default: 2000\n");
    fprintf(stderr, "    --help: Display this message and exit");
    exit(exit_code);
}

static struct aws_cli_option s_long_options[] = {
    {"region", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'r'},
    {"port", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'p'},
    {"proxy-port", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'x'},
    {"help", AWS_CLI_OPTIONS_NO_ARGUMENT, NULL, 'h'},
    {NULL, 0, NULL, 0},
};

static void s_parse_options(int argc, char **argv, struct app_ctx *ctx) {
    ctx->port = SERVICE_PORT;
    ctx->proxy_port = PROXY_PORT;
    ctx->region = NULL;
    ctx->kms_endpoint = NULL;

    while (true) {
        int option_index = 0;
        int c = aws_cli_getopt_long(argc, argv, "r:p:x:h", s_long_options, &option_index);
        if (c == -1) {
            break;
        }

        switch (c) {
            case 0:
                break;
            case 'r':
                ctx->region = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                break;
            case 'p':
                ctx->port = atoi(aws_cli_optarg);
                break;
            case 'x':
                ctx->proxy_port = atoi(aws_cli_optarg);
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
}

struct aws_credentials *s_read_credentials(struct aws_allocator *allocator, struct json_object *object) {
    struct aws_credentials *credentials = NULL;

    struct json_object *aws_access_key_id = json_object_object_get(object, "AwsAccessKeyId");
    struct json_object *aws_secret_access_key = json_object_object_get(object, "AwsSecretAccessKey");
    struct json_object *aws_session_token = json_object_object_get(object, "AwsSessionToken");

    if (aws_access_key_id == NULL || aws_secret_access_key == NULL ||
        !json_object_is_type(aws_access_key_id, json_type_string) ||
        !json_object_is_type(aws_secret_access_key, json_type_string)) {
        fprintf(stderr, "Error parsing JSON object: credentials not correct");
        return NULL;
    }

    if (aws_session_token != NULL && !json_object_is_type(aws_access_key_id, json_type_string)) {
        fprintf(stderr, "Error parsing JSON object: credentials not correct");
        return NULL;
    }

    credentials = aws_credentials_new(
        allocator,
        aws_byte_cursor_from_c_str(json_object_get_string(aws_access_key_id)),
        aws_byte_cursor_from_c_str(json_object_get_string(aws_secret_access_key)),
        aws_byte_cursor_from_c_str(json_object_get_string(aws_session_token)),
        UINT64_MAX);

    return credentials;
}

/**
 * This function returns the AWS region the client will use, with the following
 * rules:
 * 1. If a region is already set at the start of this program it will return it, unless
 * the client also wants to set a region, in which case it will return NULL, since
 * the client and the enclave collide in requirements.
 * 2. If a region is not set at the start of this program, and the client sets one,
 * then the client one is returned, if it's correctly set by the client.
 * 3. If no region is set at either the start of this program, nor by the client,
 * then default_region is returned.
 */
struct aws_string *s_read_region(struct app_ctx *ctx, struct json_object *object) {
    struct json_object *aws_region = json_object_object_get(object, "AwsRegion");
    /* Neither is set, so use default_region */
    if (aws_region == NULL && ctx->region == NULL) {
        return aws_string_clone_or_reuse(ctx->allocator, default_region);
    }

    /* Both are set, don't allow it. */
    if (aws_region != NULL && ctx->region != NULL) {
        return NULL;
    }

    /* Enclave is set. */
    if (aws_region == NULL && ctx->region != NULL) {
        return aws_string_clone_or_reuse(ctx->allocator, ctx->region);
    }

    /* AwsRegion is set, verify it. */
    if (!json_object_is_type(aws_region, json_type_string))
        return NULL;

    return aws_string_new_from_c_str(ctx->allocator, json_object_get_string(aws_region));
}

ssize_t s_write_all(int peer_fd, const char *msg, size_t msg_len) {
    size_t total_sent = 0;
    while (total_sent < msg_len) {
        ssize_t sent = write(peer_fd, msg + total_sent, msg_len - total_sent);
        if (sent <= 0 && (errno == EAGAIN || errno == EINTR)) {
            continue;
        } else if (sent < 0) {
            return -1;
        } else {
            total_sent += sent;
        }
    }
    return total_sent;
}

int s_send_status(int peer_fd, int status, const char *msg) {
    int rc = 0;
    struct json_object *status_object = json_object_new_object();
    if (status_object == NULL) {
        return -1;
    }

    json_object_object_add(status_object, "Status", json_object_new_string(status == STATUS_OK ? "Ok" : "Error"));

    if (msg != NULL) {
        json_object_object_add(status_object, "Message", json_object_new_string(msg));
    }

    const char *status_str = json_object_to_json_string(status_object);
    rc = s_write_all(peer_fd, status_str, strlen(status_str) + 1);
    json_object_put(status_object);
    return rc;
}

static void handle_connection(struct app_ctx *app_ctx, int peer_fd) {
    char buf[BUF_SIZE] = {0};
    size_t buf_idx = 0;
    ssize_t rc = 0;
    struct json_object *object = NULL;
    char *err_msg = NULL;

    struct aws_credentials *credentials = NULL;
    struct aws_string *region = NULL;
    struct aws_nitro_enclaves_kms_client *client = NULL;

    /* Parent is always on CID 3 */
    struct aws_socket_endpoint endpoint = {.address = "3", .port = app_ctx->proxy_port};
    struct aws_nitro_enclaves_kms_client_configuration configuration = {
        .allocator = app_ctx->allocator,
        .endpoint = &endpoint,
        .domain = AWS_SOCKET_VSOCK,
        .host_name = app_ctx->kms_endpoint,
    };

    while (true) {
        char *sep = memchr(buf, '\0', buf_idx);
        if (buf_idx == 0 || sep == NULL) {
            /* Buffer full, but no message available. */
            if (buf_idx >= sizeof(buf)) {
                rc = s_send_status(peer_fd, STATUS_ERR, "Message size too large.");
                fprintf(stderr, "Message size too large.\n");
                break;
            }

            // Read data from socket if no complete message is available
            ssize_t bytes = read(peer_fd, buf + buf_idx, sizeof(buf) - buf_idx);
            if (bytes == -1) {
                if (errno == EAGAIN || errno == EINTR) {
                    /* Retry operation. */
                    continue;
                }
                perror("Socket read error: ");
                break;
            } else if (bytes == 0) {
                /* Peer closed socket. */
                break;
            } else {
                /* Update counter and then check for object. */
                buf_idx += bytes;
                continue;
            }
        }

        /* Safe, because we know the buffer has a 0 before the end. */
        fprintf(stderr, "Object = %s\n", buf);
        object = json_tokener_parse(buf);

        /* Remove message from buffer */
        buf_idx -= (sep + 1 - buf);
        memmove(buf, sep + 1, buf_idx);

        fail_on(object == NULL, loop_next_err, "Error reading JSON object");
        fail_on(!json_object_is_type(object, json_type_object), loop_next_err, "JSON is wrong type");

        struct json_object *operation = json_object_object_get(object, "Operation");
        fail_on(operation == NULL, loop_next_err, "JSON structure incomplete");
        fail_on(!json_object_is_type(operation, json_type_string), loop_next_err, "Operation is wrong type");

        if (strcmp(json_object_get_string(operation), "SetClient") == 0) {
            /* SetClient operation sets the AWS credentials and optionally a region and
             * creates a matching KMS client. This needs to be called before Decrypt. */
            struct aws_credentials *new_credentials = s_read_credentials(app_ctx->allocator, object);
            fail_on(new_credentials == NULL, loop_next_err, "Could not read credentials");

            /* If credentials or client already exists, replace them. */
            if (credentials != NULL) {
                aws_nitro_enclaves_kms_client_destroy(client);
                aws_credentials_release(credentials);
            }

            if (aws_string_is_valid(region)) {
                aws_string_destroy(region);
                region = NULL;
            }
            region = s_read_region(app_ctx, object);
            fail_on(region == NULL, loop_next_err, "Could not set region correctly, check configuration.");

            credentials = new_credentials;
            configuration.credentials = new_credentials;
            configuration.region = region;
            client = aws_nitro_enclaves_kms_client_new(&configuration);

            fail_on(client == NULL, loop_next_err, "Could not create new client");

            rc = s_send_status(peer_fd, STATUS_OK, NULL);
            fail_on(rc <= 0, exit_clean_json, "Could not send status");
        } else if (strcmp(json_object_get_string(operation), "Decrypt") == 0) {
            /* Decrypt uses KMS to decrypt the data passed to it in the Ciphertext
             * field and sends it back to the called*
             * TODO: This should instead send a hash of the data instead.
             */
            fail_on(client == NULL, loop_next_err, "Client not initialized");

            struct json_object *ciphertext_obj = json_object_object_get(object, "Ciphertext");
            fail_on(ciphertext_obj == NULL, loop_next_err, "Message does not contain a Ciphertext");
            fail_on(
                !json_object_is_type(ciphertext_obj, json_type_string),
                loop_next_err,
                "Ciphertext not a base64 string");

            /* Get decode base64 string into bytes. */
            size_t ciphertext_len;
            struct aws_byte_buf ciphertext;
            struct aws_byte_cursor ciphertext_b64 = aws_byte_cursor_from_c_str(json_object_get_string(ciphertext_obj));

            rc = aws_base64_compute_decoded_len(&ciphertext_b64, &ciphertext_len);
            fail_on(rc != AWS_OP_SUCCESS, loop_next_err, "Ciphertext not a base64 string");
            rc = aws_byte_buf_init(&ciphertext, app_ctx->allocator, ciphertext_len);
            fail_on(rc != AWS_OP_SUCCESS, loop_next_err, "Memory allocation error");
            rc = aws_base64_decode(&ciphertext_b64, &ciphertext);
            fail_on(rc != AWS_OP_SUCCESS, loop_next_err, "Ciphertext not a base64 string");

            /* Decrypt the data with KMS. */
            struct aws_byte_buf ciphertext_decrypted;
            rc = aws_kms_decrypt_blocking(client, NULL, NULL, &ciphertext, &ciphertext_decrypted);
            aws_byte_buf_clean_up(&ciphertext);
            fail_on(rc != AWS_OP_SUCCESS, loop_next_err, "Could not decrypt ciphertext");

            json_object_put(object);
            object = NULL;
            /* Encode ciphertext into base64 for sending back result. */
            size_t ciphertext_decrypted_b64_len;
            struct aws_byte_buf ciphertext_decrypted_b64;
            struct aws_byte_cursor ciphertext_decrypted_cursor = aws_byte_cursor_from_buf(&ciphertext_decrypted);
            aws_base64_compute_encoded_len(ciphertext_decrypted.len, &ciphertext_decrypted_b64_len);
            rc = aws_byte_buf_init(&ciphertext_decrypted_b64, app_ctx->allocator, ciphertext_decrypted_b64_len + 1);
            fail_on(rc != AWS_OP_SUCCESS, decrypt_clean_err, "Memory allocation error");
            rc = aws_base64_encode(&ciphertext_decrypted_cursor, &ciphertext_decrypted_b64);
            fail_on(rc != AWS_OP_SUCCESS, decrypt_clean_err, "Base64 encoding error");
            aws_byte_buf_append_null_terminator(&ciphertext_decrypted_b64);

            /* Send back result. */
            rc = s_send_status(peer_fd, STATUS_OK, (const char *)ciphertext_decrypted_b64.buffer);
            aws_byte_buf_clean_up_secure(&ciphertext_decrypted);
            aws_byte_buf_clean_up_secure(&ciphertext_decrypted_b64);
            break_on(rc <= 0);
        decrypt_clean_err:
            /* This is a fallthrough that cleans up local objects ahead of loop_next_err */
            aws_byte_buf_clean_up_secure(&ciphertext_decrypted);
            aws_byte_buf_clean_up_secure(&ciphertext_decrypted_b64);
            goto loop_next_err;
        } else {
            rc = s_send_status(peer_fd, STATUS_ERR, "Operation not recognized");
            break_on(rc <= 0);
        }

        json_object_put(object);
        object = NULL;
        continue;
    loop_next_err:
        json_object_put(object);
        object = NULL;
        rc = s_send_status(peer_fd, STATUS_ERR, err_msg);
        err_msg = NULL;
        break_on(rc <= 0);
    }

    aws_nitro_enclaves_kms_client_destroy(client);
    aws_credentials_release(credentials);
    return;
exit_clean_json:
    json_object_put(object);
    aws_nitro_enclaves_kms_client_destroy(client);
    aws_credentials_release(credentials);
    return;
}

int main(int argc, char **argv) {
    int rc = 0;
    struct app_ctx app_ctx;

    /* Initialize the SDK */
    aws_nitro_enclaves_library_init(NULL);

    /* Initialize the entropy pool: this is relevant for TLS */
    AWS_ASSERT(aws_nitro_enclaves_library_seed_entropy(1024) == AWS_OP_SUCCESS);

    /* Parse the commandline */
    app_ctx.allocator = aws_nitro_enclaves_get_allocator();
    s_parse_options(argc, argv, &app_ctx);

    /* Set region if not already set and  */
    if (app_ctx.region == NULL && getenv("REGION") != NULL && strlen(getenv("REGION")) > 0) {
        app_ctx.region = aws_string_new_from_c_str(app_ctx.allocator, getenv("REGION"));
    }

    /* Override KMS endpoint hostname */
    if (app_ctx.kms_endpoint == NULL && getenv("ENDPOINT") != NULL && strlen(getenv("ENDPOINT")) > 0) {
        app_ctx.kms_endpoint = aws_string_new_from_c_str(app_ctx.allocator, getenv("ENDPOINT"));
    }

    /* Optional: Enable logging for aws-c-* libraries */
    struct aws_logger err_logger;
    struct aws_logger_standard_options options = {
        .file = stderr,
        .level = AWS_LL_INFO,
        .filename = NULL,
    };
    aws_logger_init_standard(&err_logger, app_ctx.allocator, &options);
    aws_logger_set(&err_logger);

    /* Set up a really simple vsock server. We are purposefully using vsock directly
     * in this example, as an example for using it in other projects.
     * High level communication libraries might be better suited for production
     * usage.
     * The server will work as follow:
     * 1. Set up a vsock socket and bind it to port given as a parameter.
     * 2. Listen for new connections on the socket.
     * 3. On a new connection, go into a loop that reads strings split by '\0'.
     *    Each string should be parsed into JSON object containing a command
     *    and its parameters.
     * 4. Process the command.
     * 5. When the connection is closed, listen for a new connection. */
    int vsock_fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (vsock_fd < 0) {
        perror("Could not create vsock port");
        exit(1);
    }

    struct sockaddr_vm svm = {
        .svm_family = AF_VSOCK,
        .svm_cid = VMADDR_CID_ANY,
        .svm_port = app_ctx.port,
        .svm_reserved1 = 0, /* needs to be set to 0 */
    };

    rc = bind(vsock_fd, (struct sockaddr *)&svm, sizeof(svm));
    if (rc < 0) {
        perror("Could not bind socket to port");
        close(vsock_fd);
        exit(1);
    }

    rc = listen(vsock_fd, 1);
    if (rc < 0) {
        perror("Could not listen on socket");
        close(vsock_fd);
        exit(1);
    }

    while (true) {
        /* Wait for a new connection. */
        fprintf(stderr, "Awaiting connection...\n");
        int peer_fd = accept(vsock_fd, NULL, NULL);
        fprintf(stderr, "Connected peer\n");
        if (peer_fd < 0) {
            if (errno == EAGAIN || errno == EINTR) {
                /* Try to get a new connection again */
                continue;
            }
            perror("Could not accept new connection");
            close(vsock_fd);
            aws_nitro_enclaves_library_clean_up();
            exit(1);
        }
        handle_connection(&app_ctx, peer_fd);
        fprintf(stderr, "Sesssion ended\n");
        close(peer_fd);
    }

    aws_nitro_enclaves_library_clean_up();

    return 0;
}
