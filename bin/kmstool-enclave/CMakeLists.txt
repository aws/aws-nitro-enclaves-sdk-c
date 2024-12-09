project(kmstool-enclave C)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_INSTALL_PREFIX}/lib/cmake")

set(KMSTOOL_ENCLAVE_PROJECT_NAME kmstool_enclave)
add_executable(${KMSTOOL_ENCLAVE_PROJECT_NAME} "main.c")

aws_set_common_properties(${KMSTOOL_ENCLAVE_PROJECT_NAME})

target_include_directories(${KMSTOOL_ENCLAVE_PROJECT_NAME} PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>)

target_link_libraries(${KMSTOOL_ENCLAVE_PROJECT_NAME} aws-nitro-enclaves-sdk-c)

target_compile_options(${KMSTOOL_ENCLAVE_PROJECT_NAME} PUBLIC "-Wall" "-Werror")

if (BUILD_SHARED_LIBS AND NOT WIN32)
    message(INFO " kmstool will be built with shared libs, but you may need to set LD_LIBRARY_PATH=${CMAKE_INSTALL_PREFIX}/lib to run the application")
endif()

install(TARGETS ${KMSTOOL_ENCLAVE_PROJECT_NAME}
    EXPORT ${KMSTOOL_ENCLAVE_PROJECT_NAME}-targets
        COMPONENT Runtime
        RUNTIME
        DESTINATION bin
        COMPONENT Runtime)
