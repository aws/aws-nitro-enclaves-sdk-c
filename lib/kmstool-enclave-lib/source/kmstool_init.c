#include "../include/kmstool_init.h"

/* Default parent CID for vsock communication with the parent enclave */
#define DEFAULT_PARENT_CID "3"

/* Initialize app context with the provided parameters */
static void app_ctx_init_with_params(struct app_ctx *ctx, const struct kmstool_init_params *params) {
    ctx->proxy_port = params->proxy_port;
    ctx->region = aws_string_new_from_c_str(ctx->allocator, params->aws_region);
    ctx->aws_access_key_id = aws_string_new_from_c_str(ctx->allocator, params->aws_access_key_id);
    ctx->aws_secret_access_key = aws_string_new_from_c_str(ctx->allocator, params->aws_secret_access_key);
    ctx->aws_session_token = aws_string_new_from_c_str(ctx->allocator, params->aws_session_token);
    ctx->key_id = aws_string_new_from_c_str(ctx->allocator, params->kms_key_id);
    ctx->encryption_algorithm = aws_string_new_from_c_str(ctx->allocator, params->kms_algorithm);
}

/* Initialize KMS client with AWS credentials and vsock endpoint configuration */
static int kms_client_init(struct app_ctx *ctx) {
    if (ctx->kms_client != NULL || ctx->aws_credentials != NULL) {
        fprintf(stderr, "KMS client has already been initialized\n");
        return AWS_OP_SUCCESS;
    }

    /* Configure vsock endpoint for parent enclave communication */
    struct aws_socket_endpoint endpoint = {.address = DEFAULT_PARENT_CID, .port = ctx->proxy_port};
    struct aws_nitro_enclaves_kms_client_configuration configuration = {
        .allocator = ctx->allocator, .endpoint = &endpoint, .domain = AWS_SOCKET_VSOCK, .region = ctx->region};

    /* Create AWS credentials and KMS client */
    struct aws_credentials *new_credentials = aws_credentials_new(
        ctx->allocator,
        aws_byte_cursor_from_c_str((const char *)ctx->aws_access_key_id->bytes),
        aws_byte_cursor_from_c_str((const char *)ctx->aws_secret_access_key->bytes),
        aws_byte_cursor_from_c_str((const char *)ctx->aws_session_token->bytes),
        UINT64_MAX);
    configuration.credentials = new_credentials;

    ctx->kms_client = aws_nitro_enclaves_kms_client_new(&configuration);
    if (ctx->kms_client == NULL) {
        fprintf(stderr, "Failed to initialize KMS client\n");
        aws_credentials_release(new_credentials);
        new_credentials = NULL;
        return AWS_OP_ERR;
    }

    ctx->aws_credentials = new_credentials;
    return AWS_OP_SUCCESS;
}

/**
 * Initialize the KMS Tool enclave library.
 *
 * This function must be called before using any KMS operations.
 * It performs the following initialization steps:
 * 1. Validates all required parameters
 * 2. Initializes AWS Nitro Enclaves library
 * 3. Sets up logging if enabled
 * 4. Creates KMS client with provided credentials
 *
 * @param ctx The KMS Tool enclave context to initialize
 * @param params Configuration parameters including AWS credentials and KMS settings
 *
 * @return KMSTOOL_SUCCESS on success, KMSTOOL_ERROR on failure
 */
int app_lib_init(struct app_ctx *ctx, const struct kmstool_init_params *params) {
    if (ctx->allocator != NULL || ctx->kms_client != NULL) {
        fprintf(stderr, "kms tool enclave lib has already been initialized\n");
        return KMSTOOL_SUCCESS;
    }

    /* Set default AWS region if not specified */
    if (params->region == NULL) {
        fprintf(stderr, "region must be set\n");
        return KMSTOOL_ERROR;
    }

    /* Check if AWS access key ID is set */
    if (params->aws_access_key_id == NULL) {
        fprintf(stderr, "aws_access_key_id must be set\n");
        return KMSTOOL_ERROR;
    }

    /* Check if AWS secret access key is set */
    if (params->aws_secret_access_key == NULL) {
        fprintf(stderr, "aws_secret_access_key must be set\n");
        return KMSTOOL_ERROR;
    }

    /* Check if AWS session token is set */
    if (params->aws_session_token == NULL) {
        fprintf(stderr, "aws_session_token must be set\n");
        return KMSTOOL_ERROR;
    }

    if (params->key_id == NULL) {
        fprintf(stderr, "key_id must be set\n");
        return KMSTOOL_ERROR;
    }

    /* Check if encryption algorithm is set */
    if (params->encryption_algorithm == NULL) {
        fprintf(stderr, "encryption_algorithm must be set\n");
        return KMSTOOL_ERROR;
    }

    /* Initialize the AWS Nitro Enclaves library */
    aws_nitro_enclaves_library_init(NULL);

    if (aws_nitro_enclaves_library_seed_entropy(1024) != AWS_OP_SUCCESS) {
        aws_nitro_enclaves_library_clean_up();
        return KMSTOOL_ERROR;
    }

    ctx->allocator = aws_nitro_enclaves_get_allocator();
    if (ctx->allocator == NULL) {
        aws_nitro_enclaves_library_clean_up();
        return KMSTOOL_ERROR;
    }

    if (params->with_logs == 1) {
        ctx->logger = malloc(sizeof(struct aws_logger));
        if (ctx->logger == NULL) {
            aws_nitro_enclaves_library_clean_up();
            return KMSTOOL_ERROR;
        }
        struct aws_logger_standard_options options = {
            .file = stderr,
            .level = AWS_LL_INFO,
            .filename = NULL,
        };
        if (aws_logger_init_standard(ctx->logger, ctx->allocator, &options) != AWS_OP_SUCCESS) {
            free(ctx->logger);
            ctx->logger = NULL;
            aws_nitro_enclaves_library_clean_up();
            return KMSTOOL_ERROR;
        }
        aws_logger_set(ctx->logger);
    }

    app_ctx_init_with_params(ctx, params);

    ssize_t rc = kms_client_init(ctx);
    if (rc != AWS_OP_SUCCESS) {
        app_lib_clean_up(ctx);
        fprintf(stderr, "failed to init kms client: %s\n", aws_error_str(aws_last_error()));
        return KMSTOOL_ERROR;
    }

    return KMSTOOL_SUCCESS;
}

/**
 * Clean up all resources associated with the KMS Tool enclave library.
 *
 * This function releases all allocated resources including:
 * - AWS strings (region, credentials, etc.)
 * - KMS client
 * - AWS credentials
 * - Logger
 * - AWS Nitro Enclaves library
 *
 * @param ctx The KMS Tool enclave context to clean up
 * @return KMSTOOL_SUCCESS on success
 */
int app_lib_clean_up(struct app_ctx *ctx) {
    if (ctx->region) {
        aws_string_destroy(ctx->region);
        ctx->region = NULL;
    }

    if (ctx->aws_access_key_id) {
        aws_string_destroy(ctx->aws_access_key_id);
        ctx->aws_access_key_id = NULL;
    }

    if (ctx->aws_secret_access_key) {
        aws_string_destroy(ctx->aws_secret_access_key);
        ctx->aws_secret_access_key = NULL;
    }

    if (ctx->aws_session_token) {
        aws_string_destroy(ctx->aws_session_token);
        ctx->aws_session_token = NULL;
    }

    if (ctx->key_id) {
        aws_string_destroy(ctx->key_id);
        ctx->key_id = NULL;
    }

    if (ctx->encryption_algorithm) {
        aws_string_destroy(ctx->encryption_algorithm);
        ctx->encryption_algorithm = NULL;
    }

    if (ctx->kms_client != NULL) {
        aws_nitro_enclaves_kms_client_destroy(ctx->kms_client);
        ctx->kms_client = NULL;
    }

    if (ctx->aws_credentials != NULL) {
        aws_credentials_release(ctx->aws_credentials);
        ctx->aws_credentials = NULL;
    }

    aws_nitro_enclaves_library_clean_up();

    if (ctx->logger) {
        free(ctx->logger);
        ctx->logger = NULL;
    }

    ctx->allocator = NULL;
    return KMSTOOL_SUCCESS;
}

/**
 * Update AWS credentials for an initialized KMS Tool enclave.
 *
 * This function updates the AWS credentials and reinitializes the KMS client.
 * The enclave must be initialized before calling this function.
 *
 * @param ctx The KMS Tool enclave context
 * @param params New AWS credentials
 * @return KMSTOOL_SUCCESS on success, KMSTOOL_ERROR on failure
 */
int app_lib_update_aws_key(struct app_ctx *ctx, const struct kmstool_update_aws_key_params *params) {
    if (ctx->allocator == NULL) {
        fprintf(stderr, "should init kms tool lib before update\n");
        return KMSTOOL_ERROR;
    }

    /* Free previously allocated memory for aws_access_key_id if it exists */
    if (ctx->aws_access_key_id) {
        aws_string_destroy(ctx->aws_access_key_id);
    }
    ctx->aws_access_key_id = aws_string_new_from_c_str(ctx->allocator, params->aws_access_key_id);

    /* Similarly free and update aws_secret_access_key */
    if (ctx->aws_secret_access_key) {
        aws_string_destroy(ctx->aws_secret_access_key);
    }
    ctx->aws_secret_access_key = aws_string_new_from_c_str(ctx->allocator, params->aws_secret_access_key);

    /* And free and update aws_session_token */
    if (ctx->aws_session_token) {
        aws_string_destroy(ctx->aws_session_token);
    }
    ctx->aws_session_token = aws_string_new_from_c_str(ctx->allocator, params->aws_session_token);

    if (ctx->kms_client != NULL) {
        aws_nitro_enclaves_kms_client_destroy(ctx->kms_client);
        ctx->kms_client = NULL;
    }

    if (ctx->aws_credentials != NULL) {
        aws_credentials_release(ctx->aws_credentials);
        ctx->aws_credentials = NULL;
    }

    ssize_t rc = AWS_OP_ERR;
    rc = kms_client_init(ctx);
    if (rc != AWS_OP_SUCCESS) {
        fprintf(stderr, "failed to update kms client \n");
        return KMSTOOL_ERROR;
    }

    return KMSTOOL_SUCCESS;
}
