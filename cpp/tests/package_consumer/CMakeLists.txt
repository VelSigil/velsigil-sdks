# A minimal application that consumes the SDK the way integrators do. CI builds it twice:
#
#   find_package:  after `cmake --install <build> --prefix <prefix>`
#     cmake -S tests/package_consumer -B <dir> -DCMAKE_PREFIX_PATH=<prefix>
#   FetchContent:  from the release source tarball (velsigil-cpp-<version>.tar.gz) and its SHA-256
#     cmake -S tests/package_consumer -B <dir> -DVELSIGIL_CONSUMER_MODE=fetchcontent \
#           -DVELSIGIL_URL=<path or URL of the tarball> -DVELSIGIL_URL_HASH=SHA256=<hex>
#
# The SDK's dependencies (libcurl, libsodium, nlohmann/json) must be findable in both modes.
cmake_minimum_required(VERSION 3.16)

project(velsigil_package_consumer LANGUAGES CXX)

set(VELSIGIL_CONSUMER_MODE "find_package" CACHE STRING "How to get the SDK: find_package or fetchcontent")
set(VELSIGIL_URL "" CACHE STRING "fetchcontent mode: path or URL of velsigil-cpp-<version>.tar.gz")
set(VELSIGIL_URL_HASH "" CACHE STRING "fetchcontent mode: SHA256=<hex> of that tarball")

if(VELSIGIL_CONSUMER_MODE STREQUAL "find_package")
  find_package(velsigil 1.0 CONFIG REQUIRED)
  message(STATUS "velsigil ${velsigil_VERSION} found via find_package in ${velsigil_DIR}")
elseif(VELSIGIL_CONSUMER_MODE STREQUAL "fetchcontent")
  if(VELSIGIL_URL STREQUAL "" OR NOT VELSIGIL_URL_HASH MATCHES "^SHA256=[0-9a-fA-F]+$")
    message(FATAL_ERROR "fetchcontent mode needs -DVELSIGIL_URL=<tarball> and -DVELSIGIL_URL_HASH=SHA256=<hex>")
  endif()
  if(POLICY CMP0135)
    cmake_policy(SET CMP0135 NEW)  # extracted files get the extraction time as their timestamp
  endif()
  include(FetchContent)
  FetchContent_Declare(velsigil URL "${VELSIGIL_URL}" URL_HASH "${VELSIGIL_URL_HASH}")
  FetchContent_MakeAvailable(velsigil)
  message(STATUS "velsigil added via FetchContent from ${VELSIGIL_URL}")
else()
  message(FATAL_ERROR "VELSIGIL_CONSUMER_MODE must be find_package or fetchcontent, not '${VELSIGIL_CONSUMER_MODE}'")
endif()

add_executable(velsigil_consumer main.cpp)
target_link_libraries(velsigil_consumer PRIVATE velsigil::velsigil)
target_compile_features(velsigil_consumer PRIVATE cxx_std_17)

enable_testing()
add_test(NAME velsigil_consumer COMMAND velsigil_consumer)
