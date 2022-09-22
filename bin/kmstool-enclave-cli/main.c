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

#define DEFAULT_PROXY_PORT  8000
#define DEFAULT_REGION      "us-east-1"
#define DEFAULT_PARENT_CID  "3"
#define DEFAULT_NUMBER_OF_BYTES 32

#define DECRYPT_CMD "decrypt"
#define GENKEY_CMD  "genkey"
#define GENRAND_CMD  "genrand"

#define AES_256_ARG "AES-256"
#define AES_128_ARG "AES-128"

#define MAX_SUB_COMMAND_LENGTH sizeof(DECRYPT_CMD)
#define MAX_KEY_SPEC_LENGTH sizeof(AES_256_ARG)

enum status {
    STATUS_OK,
    STATUS_ERR,
};

#define fail_on(cond, msg)                                                                                             \
    if (cond) {                                                                                                        \
        if (msg != NULL) {                                                                                             \
            fprintf(stderr, "%s\n", msg);                                                                              \
        }                                                                                                              \
        return AWS_OP_ERR;                                                                                             \
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

    /* KMS credentials */
    const struct aws_string *aws_access_key_id;
    const struct aws_string *aws_secret_access_key;
    const struct aws_string *aws_session_token;

    /* Data parameters */
    const struct aws_string *ciphertext_b64;
    const struct aws_string *encryption_algorithm;
    const struct aws_string *key_id;
    enum aws_key_spec key_spec;
    uint32_t number_of_bytes;
};

/*
 * Function to print the different commands
 */
static void print_commands(int exit_code) {
    fprintf(stderr, "usage: kmstool_enclave_cli [command]\n");
    fprintf(stderr, "\n Commands: \n\n");
    fprintf(stderr, "    decrypt: Decrypt a given ciphertext blob.\n");
    fprintf(stderr, "    genkey: Generate a datakey from KMS encrypted with the given key id.\n");
    fprintf(stderr, "    genrand: Generate a random string.\n");
    exit(exit_code);
}

/*
 * Function to print out the argumetns for decrypt
 */
static void s_usage_decrypt(int exit_code) {
    fprintf(stderr, "usage: kmstool_enclave_cli decrypt [options]\n");
    fprintf(stderr, "\n Options: \n\n");
    fprintf(stderr, "    --help: Displays this message and exits\n");
    fprintf(stderr, "    --region REGION: AWS region to use for KMS. Default: 'us-east-1'\n");
    fprintf(stderr, "    --proxy-port PORT: Connect to KMS proxy on PORT. Default: 8000\n");
    fprintf(stderr, "    --aws-access-key-id ACCESS_KEY_ID: AWS access key ID\n");
    fprintf(stderr, "    --aws-secret-access-key SECRET_ACCESS_KEY: AWS secret access key\n");
    fprintf(stderr, "    --aws-session-token SESSION_TOKEN: Session token associated with the access key ID\n");
    fprintf(stderr, "    --ciphertext CIPHERTEXT: base64-encoded ciphertext that need to decrypt\n");
    fprintf(stderr, "    --key-id KEY_ID: decrypt key id (for symmetric keys, is optional)\n");
    fprintf(stderr, "    --encryption-algorithm ENCRYPTION_ALGORITHM: encryption algorithm for ciphertext\n");
    exit(exit_code);
}

/*
 * Function to print out the arguments for genkey
 */
static void s_usage_genkey(int exit_code) {
    fprintf(stderr, "usage: kmstool_enclave_cli genkey [options]\n");
    fprintf(stderr, "\n Options: \n\n");
    fprintf(stderr, "    --help: Displays this message and exits\n");
    fprintf(stderr, "    --region REGION: AWS region to use for KMS. Default: 'us-east-1'\n");
    fprintf(stderr, "    --proxy-port PORT: Connect to KMS proxy on PORT. Default: 8000\n");
    fprintf(stderr, "    --aws-access-key-id ACCESS_KEY_ID: AWS access key ID\n");
    fprintf(stderr, "    --aws-secret-access-key SECRET_ACCESS_KEY: AWS secret access key\n");
    fprintf(stderr, "    --aws-session-token SESSION_TOKEN: Session token associated with the access key ID\n");
    fprintf(stderr, "    --key-id KEY_ID: key id\n");
    fprintf(stderr, "    --key-spec KEY_SPEC: The key spec used to create the key (AES-256 or AES-128).\n");
    exit(exit_code);
}

/*
 * Function to print out the arguments for genrand
 */
static void s_usage_genrand(int exit_code) {
    fprintf(stderr, "usage: kmstool_enclave_cli genrand [options]\n");
    fprintf(stderr, "\n Options: \n\n");
    fprintf(stderr, "    --help: Displays this message and exits\n");
    fprintf(stderr, "    --region REGION: AWS region to use for KMS. Default: 'us-east-1'\n");
    fprintf(stderr, "    --proxy-port PORT: Connect to KMS proxy on PORT. Default: 8000\n");
    fprintf(stderr, "    --aws-access-key-id ACCESS_KEY_ID: AWS access key ID\n");
    fprintf(stderr, "    --aws-secret-access-key SECRET_ACCESS_KEY: AWS secret access key\n");
    fprintf(stderr, "    --aws-session-token SESSION_TOKEN: Session token associated with the access key ID\n");
    fprintf(stderr, "    --number_of_bytes NUMBER_OF_BYTES: The length of the random byte string. This parameter is required(1-1024)\n");
    exit(exit_code);
}

/* Command line options */
static struct aws_cli_option s_long_options[] = {
    {"region", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'r'},
    {"proxy-port", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'x'},
    {"aws-access-key-id", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'k'},
    {"aws-secret-access-key", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 's'},
    {"aws-session-token", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 't'},
    {"ciphertext", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'c'},
    {"key-id", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'K'},
    {"key-spec", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'p'},
    {"encryption-algorithm", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'a'},
    {"number-of-bytes", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'n'},
    {"help", AWS_CLI_OPTIONS_NO_ARGUMENT, NULL, 'h'},
    {NULL, 0, NULL, 0},
};

/*
 * Function to parse the common command line arguments.
 *
 * @param[in]  argc: number of arguments
 * @param[in]  argv: array of passed in arguments
 * @param[in]  subcommand: sub-command being called
 * @param[out] app_ctx: struct to store all of the arguments
 */
static void s_parse_options(int argc, char **argv, const char *subcommand, struct app_ctx *ctx) {
    ctx->proxy_port = DEFAULT_PROXY_PORT;
    ctx->region = NULL;
    ctx->aws_access_key_id = NULL;
    ctx->aws_secret_access_key = NULL;
    ctx->aws_session_token = NULL;
    ctx->ciphertext_b64 = NULL;
    ctx->key_id = NULL;
    ctx->key_spec = -1;
    ctx->encryption_algorithm = NULL;
    ctx->number_of_bytes = DEFAULT_NUMBER_OF_BYTES;

    aws_cli_optind = 2;
    while (true) {
        int option_index = 0;

        int c = aws_cli_getopt_long(argc, argv, "r:x:k:s:t:c:K:p:a:n:h", s_long_options, &option_index);
        if (c == -1) {
            break;
        }

        switch (c) {
            case 0:
                break;
            case 'r':
                ctx->region = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                break;
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
            case 'h':
                if (strncmp(subcommand, DECRYPT_CMD, MAX_SUB_COMMAND_LENGTH) == 0)
                    s_usage_decrypt(1);
                else if (strncmp(subcommand, GENKEY_CMD, MAX_SUB_COMMAND_LENGTH) == 0)
                    s_usage_genkey(1);
                else if (strncmp(subcommand, GENRAND_CMD, MAX_SUB_COMMAND_LENGTH) == 0)
                    s_usage_genrand(1);
                break;
            default:
                if (strncmp(subcommand, DECRYPT_CMD, MAX_SUB_COMMAND_LENGTH) == 0) { 
                    switch (c) {
                        case 'c':
                            ctx->ciphertext_b64 = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                            break;
                         case 'a':
                            ctx->encryption_algorithm = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                            break;

                        default:
                            fprintf(stderr, "Unknown option: %s\n", aws_cli_optarg);
                            s_usage_decrypt(1);
                    }
                } else if (strncmp(subcommand, GENKEY_CMD, MAX_SUB_COMMAND_LENGTH) == 0) {
                    switch(c) {
                        case 'K':
                            ctx->key_id = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                            break;
                        case 'p':
                            if (strncmp(aws_cli_optarg, AES_256_ARG, MAX_KEY_SPEC_LENGTH) == 0) {
                                ctx->key_spec = AWS_KS_AES_256;
                            } else if (strncmp(aws_cli_optarg, AES_128_ARG, MAX_KEY_SPEC_LENGTH) == 0) {
                                ctx->key_spec = AWS_KS_AES_128;
                            } else {
                                fprintf(stderr, "Unknown key spec: %s\n", aws_cli_optarg);
                                s_usage_genkey(1);
                            }
                            break;
                    }
                } else if (strncmp(subcommand, GENRAND_CMD, MAX_SUB_COMMAND_LENGTH) == 0) {
                    switch(c) {
                        case 'n' :
                            ctx->number_of_bytes = (uint32_t)aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                            break;
                    }
                }
        }
    }

    /* Check if AWS access key ID is set */
    if (ctx->aws_access_key_id == NULL) {
        fprintf(stderr, "--aws-access-key-id must be set\n");
        exit(1);
    }

    /* Check if AWS secret access key is set */
    if (ctx->aws_secret_access_key == NULL) {
        fprintf(stderr, "--aws-secret-access-key must be set\n");
        exit(1);
    }

    /* Check if AWS session token is set */
    if (ctx->aws_session_token == NULL) {
        fprintf(stderr, "--aws-session-token must be set\n");
        exit(1);
    }

    /* Set default AWS region if not specified */
    if (ctx->region == NULL) {
        ctx->region = aws_string_new_from_c_str(ctx->allocator, DEFAULT_REGION);
    }

    if (strncmp(subcommand, DECRYPT_CMD, MAX_SUB_COMMAND_LENGTH) == 0) {
        /* Check if ciphertext is set */
        if (ctx->ciphertext_b64 == NULL) {
            fprintf(stderr, "--ciphertext must be set\n");
            exit(1);
        }

    } else if (strncmp(subcommand, GENKEY_CMD, MAX_SUB_COMMAND_LENGTH) == 0) {
        /* Check if the key id is set */
        if (ctx->key_id == NULL) {
            fprintf(stderr, "--key-id must be set\n");
            exit(1);
        }

        /* Check if key spec is set */
        if (ctx->key_spec == -1) {
            fprintf(stderr, "--key-spec must be set\n");
            exit(1);
        }
    } else if (strncmp(subcommand, GENRAND_CMD, MAX_SUB_COMMAND_LENGTH) == 0) {
        /* Check if ciphertext is set */
        if (ctx->number_of_bytes < 1 || ctx->number_of_bytes > 1024) {
            fprintf(stderr, "--number-of-bytes must be set and size between 1-1024\n");
            exit(1);
        }
    }
}

/*
 * Function to initialize the kms client with the provided aws credentials
 *
 * @param[in]  app_ctx: place where all of the credentials are currently stored
 * @param[out] credentials: location to store the aws credentials
 * @param[out] client: location to store new kms client
 */
static void init_kms_client(struct app_ctx *app_ctx, struct aws_credentials **credentials, struct aws_nitro_enclaves_kms_client **client) {
    /* Parent is always on CID 3 */
    struct aws_socket_endpoint endpoint = {.address = DEFAULT_PARENT_CID, .port = app_ctx->proxy_port};
    struct aws_nitro_enclaves_kms_client_configuration configuration = {
        .allocator = app_ctx->allocator, .endpoint = &endpoint, .domain = AWS_SOCKET_VSOCK, .region = app_ctx->region};

    /* Sets the AWS credentials and creates a KMS client with them. */
    struct aws_credentials *new_credentials = aws_credentials_new(
        app_ctx->allocator,
        aws_byte_cursor_from_c_str((const char *)app_ctx->aws_access_key_id->bytes),
        aws_byte_cursor_from_c_str((const char *)app_ctx->aws_secret_access_key->bytes),
        aws_byte_cursor_from_c_str((const char *)app_ctx->aws_session_token->bytes),
        UINT64_MAX);

    /* If credentials or client already exists, replace them. */
    if (*credentials != NULL) {
        aws_nitro_enclaves_kms_client_destroy(*client);
        aws_credentials_release(*credentials);
    }

    *credentials = new_credentials;
    configuration.credentials = new_credentials;
    *client = aws_nitro_enclaves_kms_client_new(&configuration);
}

/*
 * Function to encode a string in base64 for printing
 *
 * @param[in]  app_ctx: contains the allocator required for memory management
 * @param[in]  text: pointer to where the original text is stored
 * @param[out] text_b64: pointer to where the encoded string should be stored
 */ 
static int encode_b64(struct app_ctx *app_ctx, struct aws_byte_buf *text, struct aws_byte_buf *text_b64) {
    ssize_t rc = 0;
    size_t text_b64_len;

    struct aws_byte_cursor text_cursor = aws_byte_cursor_from_buf(text);
    aws_base64_compute_encoded_len(text->len, &text_b64_len);
    rc = aws_byte_buf_init(text_b64, app_ctx->allocator, text_b64_len + 1);
    fail_on(rc != AWS_OP_SUCCESS, "Memory allocation error");
    rc = aws_base64_encode(&text_cursor, text_b64);
    fail_on(rc != AWS_OP_SUCCESS, "Base64 encoding error");
    aws_byte_buf_append_null_terminator(text_b64);

    return AWS_OP_SUCCESS;
}

/*
 * Function to decrypt a given ciphertext with attestation.
 *
 * @param[in]  app_ctx: Struct that has all of the necessary arguments
 * @param[out] ciphertext_decrypted_b64: Byte buffer where the decrypted ciphertext will be stored
 */
static int decrypt(struct app_ctx *app_ctx, struct aws_byte_buf *ciphertext_decrypted_b64) {
    ssize_t rc = 0;

    struct aws_credentials *credentials = NULL;
    struct aws_nitro_enclaves_kms_client *client = NULL;

    init_kms_client(app_ctx, &credentials, &client);
   
    
    /* Get decode base64 string into bytes. */
    size_t ciphertext_len;
    struct aws_byte_buf ciphertext;
    struct aws_byte_cursor ciphertext_b64 = aws_byte_cursor_from_c_str((const char *)app_ctx->ciphertext_b64->bytes);
    rc = aws_base64_compute_decoded_len(&ciphertext_b64, &ciphertext_len);
    fail_on(rc != AWS_OP_SUCCESS, "Ciphertext not a base64 string");
    rc = aws_byte_buf_init(&ciphertext, app_ctx->allocator, ciphertext_len);
    fail_on(rc != AWS_OP_SUCCESS, "Memory allocation error");
    rc = aws_base64_decode(&ciphertext_b64, &ciphertext);
    fail_on(rc != AWS_OP_SUCCESS, "Ciphertext not a base64 string");

    /* Decrypt the data with KMS. */
    struct aws_byte_buf ciphertext_decrypted;
    rc = aws_kms_decrypt_blocking(
        client, app_ctx->key_id, app_ctx->encryption_algorithm, &ciphertext, &ciphertext_decrypted);
    
    aws_byte_buf_clean_up(&ciphertext);
    fail_on(rc != AWS_OP_SUCCESS, "Could not decrypt ciphertext");

    /* Encode ciphertext into base64 for printing out the result. */
    rc = encode_b64(app_ctx, &ciphertext_decrypted, ciphertext_decrypted_b64);
    fail_on(rc != AWS_OP_SUCCESS, "Could not encode ciphertext");

    /* Cleaning up allocated memory */
    aws_nitro_enclaves_kms_client_destroy(client);
    aws_credentials_release(credentials);
    
    return AWS_OP_SUCCESS;
}

/*
 * Function to generate a data key from KMS with attestation.
 *
 * @param[in]  app_ctx: Struct that has all of the necessary arguments
 * @param[out] ciphertext_decrypted_b64: Byte buffer where the ciphertext blob will be stored
 * @param[out] plaintext_b64: Byte buffer where the plaintext output will be stored
 */
static int gen_datakey(struct app_ctx *app_ctx, struct aws_byte_buf *ciphertext_b64, struct aws_byte_buf *plaintext_b64) {
    ssize_t rc = 0;

    struct aws_credentials *credentials = NULL;
    struct aws_nitro_enclaves_kms_client *client = NULL;

    init_kms_client(app_ctx, &credentials, &client);

    /* Generate data key with KMS. */
    struct aws_byte_buf plaintext;
    struct aws_byte_buf ciphertext;
    rc = aws_kms_generate_data_key_blocking(client, app_ctx->key_id, app_ctx->key_spec, &plaintext, &ciphertext);
    fail_on(rc != AWS_OP_SUCCESS, "Could not generate data key");
    
    /* Encode ciphertext into base64 for printing out the result. */
    rc = encode_b64(app_ctx, &ciphertext, ciphertext_b64);
    fail_on(rc != AWS_OP_SUCCESS, "Could not encode ciphertext");
    
    /* Encode plaintext into base64 for printing out the result. */
    rc = encode_b64(app_ctx, &plaintext, plaintext_b64);
    fail_on(rc != AWS_OP_SUCCESS, "Could not encode plaintext");

    /* Cleaning up allocated memory. */
    aws_nitro_enclaves_kms_client_destroy(client);
    aws_credentials_release(credentials);
    
    return AWS_OP_SUCCESS;
}

/*
 * Function to generate a data key from KMS with attestation.
 *
 * @param[in]  app_ctx: Struct that has all of the necessary arguments
 * @param[out] ciphertext_decrypted_b64: Byte buffer where the ciphertext blob will be stored
 * @param[out] plaintext_b64: Byte buffer where the plaintext output will be stored
 */
static int gen_random(struct app_ctx *app_ctx, struct aws_byte_buf *randomstr_b64) {
    ssize_t rc = 0;

    struct aws_credentials *credentials = NULL;
    struct aws_nitro_enclaves_kms_client *client = NULL;

    init_kms_client(app_ctx, &credentials, &client);

    /* Generate data key with KMS. */
    struct aws_byte_buf randomstr;
    rc = aws_kms_generate_random_blocking(client, app_ctx->number_of_bytes, &randomstr);
    fail_on(rc != AWS_OP_SUCCESS, "Could not generate random string");

    /* Encode ciphertext into base64 for printing out the result. */
    rc = encode_b64(app_ctx, &randomstr, randomstr_b64);
    fail_on(rc != AWS_OP_SUCCESS, "Could not encode random string");

    /* Cleaning up allocated memory. */
    aws_nitro_enclaves_kms_client_destroy(client);
    aws_credentials_release(credentials);

    return AWS_OP_SUCCESS;
}

int main(int argc, char **argv) {
    struct app_ctx app_ctx;
    int rc;
    const char *subcommand;

    /* Initialize the SDK */
    aws_nitro_enclaves_library_init(NULL);

    /* Initialize the entropy pool: this is relevant for TLS */
    AWS_ASSERT(aws_nitro_enclaves_library_seed_entropy(1024) == AWS_OP_SUCCESS);

    /* Parse the commandline */
    app_ctx.allocator = aws_nitro_enclaves_get_allocator();
    
    /* Verifies there are at least two arguments */    
    if (argc < 2) {
        print_commands(1);
    }
    fprintf(stderr, "argc is %d\n", argc);
    subcommand = argv[1];
    fprintf(stderr, "subcommand is %s\n", subcommand);

    /* Optional: Enable logging for aws-c-* libraries */
    struct aws_logger err_logger;
    struct aws_logger_standard_options options = {
        .file = stderr,
        .level = AWS_LL_INFO,
        .filename = NULL,
    };
    aws_logger_init_standard(&err_logger, app_ctx.allocator, &options);
    aws_logger_set(&err_logger);

    s_parse_options(argc, argv, subcommand, &app_ctx);

    if (strncmp(subcommand, DECRYPT_CMD, MAX_SUB_COMMAND_LENGTH) == 0) {
        struct aws_byte_buf ciphertext_decrypted_b64;
    
        rc = decrypt(&app_ctx, &ciphertext_decrypted_b64);
        
        /* Error out if ciphertext wasn't decrypted */
        fail_on(rc != AWS_OP_SUCCESS, "Could not decrypt\n");

        /* Print the base64-encoded plaintext to stdout */
        fprintf(stdout, "PLAINTEXT: %s\n", (const char *)ciphertext_decrypted_b64.buffer);
    
        aws_byte_buf_clean_up(&ciphertext_decrypted_b64);
    } else if (strncmp(subcommand, GENKEY_CMD, MAX_SUB_COMMAND_LENGTH) == 0) {
        struct aws_byte_buf ciphertext_b64;
        struct aws_byte_buf plaintext_b64;
        
        rc = gen_datakey(&app_ctx, &ciphertext_b64, &plaintext_b64);
    
        /* Error if data key wasn't generated */
        fail_on(rc != AWS_OP_SUCCESS, "Could not generate data key\n");

        /* Print the base64-encoded ciphertext and plaintext to stdout */
        fprintf(stdout, "CIPHERTEXT: %s\n", (const char *)ciphertext_b64.buffer);
        fprintf(stdout, "PLAINTEXT: %s\n", (const char *)plaintext_b64.buffer);
    
        aws_byte_buf_clean_up(&ciphertext_b64);
        aws_byte_buf_clean_up(&plaintext_b64);
    } else {
        print_commands(1);
    }
    
    aws_nitro_enclaves_library_clean_up();
    
    return 0;
}
