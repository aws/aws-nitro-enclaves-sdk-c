include(AwsTestHarness)
enable_testing()

file(GLOB TEST_SRC "*.c")
file(GLOB TEST_HDRS "*.h")
file(GLOB TESTS ${TEST_HDRS} ${TEST_SRC})

add_test_case(check_test)
add_test_case(test_kms_decrypt_request_cipher_to_json)
add_test_case(test_kms_decrypt_request_ea_to_json)
add_test_case(test_kms_decrypt_request_context_to_json)
add_test_case(test_kms_decrypt_request_tokens_to_json)
add_test_case(test_kms_decrypt_request_to_json)

set(TEST_BINARY_NAME ${PROJECT_NAME}-tests)
generate_test_driver(${TEST_BINARY_NAME})
