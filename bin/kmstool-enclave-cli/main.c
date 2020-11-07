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

#define PROXY_PORT 8000

enum status {
    STATUS_OK,
    STATUS_ERR,
};

#define fail_on(cond)                                                                                                  \
    if (cond) {                                                                                                        \
        return;                                                                                                        \
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

    const struct aws_string *aws_access_key_id;
    const struct aws_string *aws_secret_access_key;
    const struct aws_string *aws_session_token;

    const struct aws_string *ciphertext_b64;
};

static void s_usage(int exit_code) {
    fprintf(stderr, "usage: enclave_server [options]\n");
    fprintf(stderr, "\n Options: \n\n");
    fprintf(stderr, "    --region REGION: AWS region to use for KMS\n");
    fprintf(stderr, "    --proxy-port PORT: Connect to KMS proxy on PORT. Default: 8000\n");
    fprintf(stderr, "    --aws-access-key-id ACCESS_KEY_ID: AWS access key ID\n");
    fprintf(stderr, "    --aws-secret-access-key SECRET_ACCESS_KEY: AWS secret access key\n");
    fprintf(stderr, "    --aws-session-token SESSION_TOKEN: Session token associated with the access key ID\n");
    fprintf(stderr, "    --ciphertext CIPHERTEXT: base64-encoded ciphertext that need to decrypt\n");
    fprintf(stderr, "    --help: Display this message and exit");
    exit(exit_code);
}

static struct aws_cli_option s_long_options[] = {
    {"region", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'r'},
    {"proxy-port", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'x'},
    {"help", AWS_CLI_OPTIONS_NO_ARGUMENT, NULL, 'h'},
    {"aws-access-key-id", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'k'},
    {"aws-secret-access-key", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 's'},
    {"aws-session-token", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 't'},
    {"ciphertext", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'c'},
    {NULL, 0, NULL, 0},
};

static void s_parse_options(int argc, char **argv, struct app_ctx *ctx) {
    ctx->proxy_port = PROXY_PORT;
    ctx->region = NULL;

    while (true) {
        int option_index = 0;
        int c = aws_cli_getopt_long(argc, argv, "r:x:k:s:t:c:h", s_long_options, &option_index);
        if (c == -1) {
            break;
        }

        switch (c) {
            case 0:
                break;
            case 'r': {
                ctx->region = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                break;
            }
            case 'x':
                ctx->proxy_port = atoi(aws_cli_optarg);
                break;
            case 'k':
                ctx->aws_access_key_id = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                break;
            case 's':
                ctx->aws_secret_access_key = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                break;
            case 't':
                ctx->aws_session_token = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                break;
            case 'c':
                ctx->ciphertext_b64 = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
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

static void decrypt(struct app_ctx *app_ctx, struct aws_byte_buf *ciphertext_decrypted_b64) {
    ssize_t rc = 0;

    struct aws_credentials *credentials = NULL;
    struct aws_nitro_enclaves_kms_client *client = NULL;

    /* Parent is always on CID 3 */
    struct aws_socket_endpoint endpoint = {.address = "3", .port = app_ctx->proxy_port};
    struct aws_nitro_enclaves_kms_client_configuration configuration = {
        .allocator = app_ctx->allocator,
        .endpoint = &endpoint,
        .domain = AWS_SOCKET_VSOCK,
        .region = app_ctx->region
    };

    /* SetCredentials operation sets the AWS credentials and creates a KMS
        * client.with them. This needs to be called before Decrypt. */
    struct aws_credentials *new_credentials = aws_credentials_new(
        app_ctx->allocator,
        aws_byte_cursor_from_c_str((const char*) app_ctx->aws_access_key_id->bytes),
        aws_byte_cursor_from_c_str((const char*) app_ctx->aws_secret_access_key->bytes),
        aws_byte_cursor_from_c_str((const char*) app_ctx->aws_session_token->bytes),
        UINT64_MAX);

    /* If credentials or client already exists, replace them. */
    if (credentials != NULL) {
        aws_nitro_enclaves_kms_client_destroy(client);
        aws_credentials_release(credentials);
    }

    credentials = new_credentials;
    configuration.credentials = new_credentials;
    client = aws_nitro_enclaves_kms_client_new(&configuration);
    
    /* Decrypt uses KMS to decrypt the data passed to it in the Ciphertext
    * field and sends it back to the called*
    * TODO: This should instead send a hash of the data instead.
    */

    /* Get decode base64 string into bytes. */
    size_t ciphertext_len;
    struct aws_byte_buf ciphertext;
    struct aws_byte_cursor ciphertext_b64 = aws_byte_cursor_from_c_str((const char*) app_ctx->ciphertext_b64->bytes);

    rc = aws_base64_compute_decoded_len(&ciphertext_b64, &ciphertext_len);
    fail_on(rc != AWS_OP_SUCCESS);
    rc = aws_byte_buf_init(&ciphertext, app_ctx->allocator, ciphertext_len);
    fail_on(rc != AWS_OP_SUCCESS);
    rc = aws_base64_decode(&ciphertext_b64, &ciphertext);
    fail_on(rc != AWS_OP_SUCCESS);

    /* Decrypt the data with KMS. */
    struct aws_byte_buf ciphertext_decrypted;
    rc = aws_kms_decrypt_blocking(client, &ciphertext, &ciphertext_decrypted);
    aws_byte_buf_clean_up(&ciphertext);
    fail_on(rc != AWS_OP_SUCCESS);

    /* Encode ciphertext into base64 for sending back result. */
    size_t ciphertext_decrypted_b64_len;
    struct aws_byte_cursor ciphertext_decrypted_cursor = aws_byte_cursor_from_buf(&ciphertext_decrypted);
    aws_base64_compute_encoded_len(ciphertext_decrypted.len, &ciphertext_decrypted_b64_len);
    rc = aws_byte_buf_init(ciphertext_decrypted_b64, app_ctx->allocator, ciphertext_decrypted_b64_len + 1);
    fail_on(rc != AWS_OP_SUCCESS);
    rc = aws_base64_encode(&ciphertext_decrypted_cursor, ciphertext_decrypted_b64);
    fail_on(rc != AWS_OP_SUCCESS);
    aws_byte_buf_append_null_terminator(ciphertext_decrypted_b64);

    aws_nitro_enclaves_kms_client_destroy(client);
    aws_credentials_release(credentials);
    return;
}

int main(int argc, char **argv) {
    struct app_ctx app_ctx;
    struct aws_byte_buf ciphertext_decrypted_b64;

    /* Initialize the SDK */
    aws_nitro_enclaves_library_init(NULL);

    /* Initialize the entropy pool: this is relevant for TLS */
    AWS_ASSERT(aws_nitro_enclaves_library_seed_entropy(1024) == AWS_OP_SUCCESS);

    /* Parse the commandline */
    app_ctx.allocator = aws_nitro_enclaves_get_allocator();
    s_parse_options(argc, argv, &app_ctx);

    /* Optional: Enable logging for aws-c-* libraries */
    struct aws_logger err_logger;
    struct aws_logger_standard_options options = {
        .file = stderr,
        .level = AWS_LL_INFO,
        .filename = NULL,
    };
    aws_logger_init_standard(&err_logger, app_ctx.allocator, &options);
    aws_logger_set(&err_logger);

    decrypt(&app_ctx, &ciphertext_decrypted_b64);

    fprintf(stdout, "%s", (const char *) ciphertext_decrypted_b64.buffer);

    aws_byte_buf_clean_up(&ciphertext_decrypted_b64);
    aws_nitro_enclaves_library_clean_up();
    aws_global_thread_creator_shutdown_wait_for(10);

    return 0;
}
