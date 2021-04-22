project(kmstool-instance C)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_INSTALL_PREFIX}/lib/cmake")

set(KMSTOOL_INSTANCE_PROJECT_NAME kmstool_instance)
add_executable(${KMSTOOL_INSTANCE_PROJECT_NAME} "main.c")

aws_set_common_properties(${KMSTOOL_INSTANCE_PROJECT_NAME})

target_include_directories(${KMSTOOL_INSTANCE_PROJECT_NAME} PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>)

target_link_libraries(${KMSTOOL_INSTANCE_PROJECT_NAME} ${PLATFORM_DEP_LIBS})
target_link_libraries(${KMSTOOL_INSTANCE_PROJECT_NAME} PUBLIC ${PLATFORM_LIBS})
target_link_libraries(${KMSTOOL_INSTANCE_PROJECT_NAME} PUBLIC ${DEP_AWS_LIBS})

if (BUILD_SHARED_LIBS AND NOT WIN32)
    message(INFO " kmstool will be built with shared libs, but you may need to set LD_LIBRARY_PATH=${CMAKE_INSTALL_PREFIX}/lib to run the application")
endif()

install(TARGETS ${KMSTOOL_INSTANCE_PROJECT_NAME}
    EXPORT ${KMSTOOL_INSTANCE_PROJECT_NAME}-targets
        COMPONENT Runtime
        RUNTIME
        DESTINATION bin
        COMPONENT Runtime)

if (WIN32)
    install(FILES $<TARGET_PDB_FILE:${KMSTOOL_INSTANCE_PROJECT_NAME}> 
        DESTINATION bin 
        OPTIONAL)
endif()