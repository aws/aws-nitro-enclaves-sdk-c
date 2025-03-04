#include "../include/kmstool_init.h"

#define DEFAULT_PARENT_CID "3"

static void app_ctx_init_with_params(struct app_ctx *ctx, const struct kmstool_init_params *params) {
    ctx->proxy_port = params->proxy_port;
    ctx->region = aws_string_new_from_c_str(ctx->allocator, params->region);
    ctx->aws_access_key_id = aws_string_new_from_c_str(ctx->allocator, params->aws_access_key_id);
    ctx->aws_secret_access_key = aws_string_new_from_c_str(ctx->allocator, params->aws_secret_access_key);
    ctx->aws_session_token = aws_string_new_from_c_str(ctx->allocator, params->aws_session_token);
    ctx->key_id = aws_string_new_from_c_str(ctx->allocator, params->key_id);
    ctx->encryption_algorithm = aws_string_new_from_c_str(ctx->allocator, params->encryption_algorithm);
}

static int kms_client_init(struct app_ctx *ctx) {
    if (ctx->kms_client != NULL || ctx->aws_credentials != NULL) {
        fprintf(stderr, "kms client have already been initialized\n");
        return AWS_OP_SUCCESS;
    }

    /* Parent is always on CID 3 */
    struct aws_socket_endpoint endpoint = {.address = DEFAULT_PARENT_CID, .port = ctx->proxy_port};
    struct aws_nitro_enclaves_kms_client_configuration configuration = {
        .allocator = ctx->allocator, .endpoint = &endpoint, .domain = AWS_SOCKET_VSOCK, .region = ctx->region};

    /* Sets the AWS credentials and creates a KMS client with them. */
    struct aws_credentials *new_credentials = aws_credentials_new(
        ctx->allocator,
        aws_byte_cursor_from_c_str((const char *)ctx->aws_access_key_id->bytes),
        aws_byte_cursor_from_c_str((const char *)ctx->aws_secret_access_key->bytes),
        aws_byte_cursor_from_c_str((const char *)ctx->aws_session_token->bytes),
        UINT64_MAX);
    configuration.credentials = new_credentials;

    ctx->kms_client= aws_nitro_enclaves_kms_client_new(&configuration);
    if (ctx->kms_client == NULL) {
        fprintf(stderr, "failed to init kms client\n");
        aws_credentials_release(new_credentials);
        new_credentials = NULL;
        return AWS_OP_ERR;
    }

    ctx->aws_credentials = new_credentials;
    return AWS_OP_SUCCESS;
}

/**
 * Initializes the KMS Tool enclave.
 *
 * This function must be called before the KMS Tool enclave is used.
 * It initializes the AWS Nitro Enclaves library and creates a KMS client.
 * It also sets the AWS region, AWS access key ID, AWS secret access key,
 * AWS session token, key ID, and encryption algorithm.
 *
 * @param ctx The KMS Tool enclave context.
 * @param params The KMS Tool enclave initialization parameters.
 *
 * @return ENCLAVE_KMS_SUCCESS on success, or ENCLAVE_KMS_ERROR on failure.
 */
int app_lib_init(struct app_ctx *ctx, const struct kmstool_init_params *params) {
    if (ctx->allocator != NULL || ctx->kms_client != NULL) {
        fprintf(stderr, "kms tool enclave lib have already been initialized\n");
        return ENCLAVE_KMS_SUCCESS;
    }

    /* Set default AWS region if not specified */
    if (params->region == NULL) {
        fprintf(stderr, "region must be set\n");
        return ENCLAVE_KMS_ERROR;
    }

    /* Check if AWS access key ID is set */
    if (params->aws_access_key_id == NULL) {
        fprintf(stderr, "aws_access_key_id must be set\n");
        return ENCLAVE_KMS_ERROR;
    }

    /* Check if AWS secret access key is set */
    if (params->aws_secret_access_key == NULL) {
        fprintf(stderr, "aws_secret_access_key must be set\n");
        return ENCLAVE_KMS_ERROR;
    }

    /* Check if AWS session token is set */
    if (params->aws_session_token == NULL) {
        fprintf(stderr, "aws_session_token must be set\n");
        return ENCLAVE_KMS_ERROR;
    }

    if (params->key_id == NULL) {
        fprintf(stderr, "key_id must be set\n");
        return ENCLAVE_KMS_ERROR;
    }

    /* Check if encryption algorithm is set */
    if (params->encryption_algorithm == NULL) {
        fprintf(stderr, "encryption_algorithm must be set\n");
        return ENCLAVE_KMS_ERROR;
    }


    /* Initialize the AWS Nitro Enclaves library */
    aws_nitro_enclaves_library_init(NULL);

    if (aws_nitro_enclaves_library_seed_entropy(1024) != AWS_OP_SUCCESS) {
        aws_nitro_enclaves_library_clean_up();
        return ENCLAVE_KMS_ERROR;
    }

    ctx->allocator = aws_nitro_enclaves_get_allocator();

    if (params->with_logs == 1) {
        ctx->logger = malloc(sizeof(struct aws_logger));
        struct aws_logger_standard_options options = {
            .file = stderr,
            .level = AWS_LL_INFO,
            .filename = NULL,
        };
        aws_logger_init_standard(ctx->logger, ctx->allocator, &options);
        aws_logger_set(ctx->logger);
    }

    app_ctx_init_with_params(ctx, params);

    ssize_t rc = AWS_OP_ERR;
    rc = kms_client_init(ctx);
    if (rc != AWS_OP_SUCCESS) {
        ctx->allocator = NULL;
        aws_nitro_enclaves_library_clean_up();
        fprintf(stderr, "failed to init kms client \n");
        return ENCLAVE_KMS_ERROR;
    }

    return ENCLAVE_KMS_SUCCESS;
}

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
    return ENCLAVE_KMS_SUCCESS;
}

int app_lib_update_aws_key(struct app_ctx *ctx, const struct kmstool_update_aws_key_params *params) {
    if (ctx->allocator == NULL) {
        fprintf(stderr, "should init kms tool lib before update\n");
        return ENCLAVE_KMS_ERROR;
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
        return ENCLAVE_KMS_ERROR;
    }

    return ENCLAVE_KMS_SUCCESS;
}
