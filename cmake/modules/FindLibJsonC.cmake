# - Try to find LibJsonC include dirs and libraries
#
# Usage of this module as follows:
#
#     find_package(LibJsonC)
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
# Variables defined by this module:
#
#  LibJsonC_FOUND             System has libjson-c, include and library dirs found
#  LibJsonC_INCLUDE_DIR       The json-c include directories.
#  LibJsonC_LIBRARY           The json-c library, depending on the value of BUILD_SHARED_LIBS.
#  LibJsonC_SHARED_LIBRARY    The path to libjson-c.so
#  LibJsonC_STATIC_LIBRARY    The path to libjson-c.a

find_path(LibJsonC_INCLUDE_DIR
        NAMES json-c/json.h
        HINTS
        ${CMAKE_PREFIX_PATH}/include
        ${CMAKE_INSTALL_PREFIX}/include
        /usr/include/json-c/
        /usr/local/include/json-c/
        )
find_library(LibJsonC_SHARED_LIBRARY
        NAMES libjson-c.so
        HINTS
        ${CMAKE_PREFIX_PATH}/build/json-c
        ${CMAKE_PREFIX_PATH}/build
        ${CMAKE_PREFIX_PATH}
        ${CMAKE_PREFIX_PATH}/lib64
        ${CMAKE_PREFIX_PATH}/lib
        ${CMAKE_INSTALL_PREFIX}/build/json-c
        ${CMAKE_INSTALL_PREFIX}/build
        ${CMAKE_INSTALL_PREFIX}
        ${CMAKE_INSTALL_PREFIX}/lib64
        ${CMAKE_INSTALL_PREFIX}/lib
        )
find_library(LibJsonC_STATIC_LIBRARY
        NAMES libjson-c.a
        HINTS
        ${CMAKE_PREFIX_PATH}/build/json-c
        ${CMAKE_PREFIX_PATH}/build
        ${CMAKE_PREFIX_PATH}
        ${CMAKE_PREFIX_PATH}/lib64
        ${CMAKE_PREFIX_PATH}/lib
        ${CMAKE_INSTALL_PREFIX}/build/json-c
        ${CMAKE_INSTALL_PREFIX}/build
        ${CMAKE_INSTALL_PREFIX}
        ${CMAKE_INSTALL_PREFIX}/lib64
        ${CMAKE_INSTALL_PREFIX}/lib
        )

if (BUILD_SHARED_LIBS)
    set(LibJsonC_LIBRARY ${LibJsonC_SHARED_LIBRARY})
else()
    set(LibJsonC_LIBRARY ${LibJsonC_STATIC_LIBRARY})
endif()


include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibJsonC DEFAULT_MSG
        LibJsonC_LIBRARY
        LibJsonC_INCLUDE_DIR
        )

mark_as_advanced(
        LibJsonC_ROOT_DIR
        LibJsonC_INCLUDE_DIR
        LibJsonC_LIBRARY
        LibJsonC_SHARED_LIBRARY
        LibJsonC_STATIC_LIBRARY
)

# some versions of cmake have a super esoteric bug around capitalization differences between
# find dependency and find package, just avoid that here by checking and
# setting both.
if(LIBJSONC_FOUND OR LibJsonC_FOUND)
    set(LIBJSONC_FOUND true)
    set(LibJsonC_FOUND true)

    message(STATUS "LibJsonC Include Dir: ${LibJsonC_INCLUDE_DIR}")
    message(STATUS "LibJsonC Shared Lib:  ${LibJsonC_SHARED_LIBRARY}")
    message(STATUS "LibJsonC Static Lib:  ${LibJsonC_STATIC_LIBRARY}")

    if (NOT TARGET LibJsonC::Json AND (EXISTS "${LibJsonC_LIBRARY}"))
        add_library(LibJsonC::Json UNKNOWN IMPORTED)
        set_target_properties(LibJsonC::Json PROPERTIES
                INTERFACE_INCLUDE_DIRECTORIES "${LibJsonC_INCLUDE_DIR}")
        set_target_properties(LibJsonC::Json PROPERTIES
                IMPORTED_LINK_INTERFACE_LANGUAGES "C"
                IMPORTED_LOCATION "${LibJsonC_LIBRARY}")
    endif()
endif()
