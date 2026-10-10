cmake_minimum_required(VERSION 3.16)

project(velsigil
  VERSION 1.0.5
  DESCRIPTION "Velsigil license client SDK for C++17"
  LANGUAGES CXX)

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
  set(VX_IS_TOP_LEVEL ON)
else()
  set(VX_IS_TOP_LEVEL OFF)
endif()

option(VX_BUILD_EXAMPLES "Build the Velsigil examples" ${VX_IS_TOP_LEVEL})
option(VX_BUILD_TESTS "Build the Velsigil tests (test vectors + client behaviour)" ${VX_IS_TOP_LEVEL})
option(VX_BUILD_HTTP_TESTS "Also run libcurl tests against the Python mock server (needs Python 3 + cryptography)" OFF)
option(VX_INSTALL "Generate install and package export rules" ${VX_IS_TOP_LEVEL})

include(GNUInstallDirs)

# Match the static MSVC runtime (/MT) that vcpkg's -static triplets use.
if(MSVC AND DEFINED VCPKG_TARGET_TRIPLET AND VCPKG_TARGET_TRIPLET MATCHES "-static$" AND NOT DEFINED CMAKE_MSVC_RUNTIME_LIBRARY)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

find_package(Threads REQUIRED)  # -pthread on older glibc
find_package(CURL REQUIRED)
find_package(nlohmann_json 3.7 CONFIG REQUIRED)

# vcpkg ships "unofficial-sodium"; Linux distributions ship pkg-config files.
find_package(unofficial-sodium CONFIG QUIET)
if(TARGET unofficial-sodium::sodium)
  set(VX_SODIUM_TARGET unofficial-sodium::sodium)
  set(VX_SODIUM_FROM_PKGCONFIG OFF)
else()
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(VX_SODIUM REQUIRED IMPORTED_TARGET libsodium)
  set(VX_SODIUM_TARGET PkgConfig::VX_SODIUM)
  set(VX_SODIUM_FROM_PKGCONFIG ON)
endif()

# Static on purpose: a separate shared library is easier to patch out.

add_library(velsigil STATIC
  src/base64.cpp
  src/client.cpp
  src/crypto.cpp
  src/hwid.cpp
  src/http.cpp
  src/store.cpp)
add_library(velsigil::velsigil ALIAS velsigil)

target_compile_features(velsigil PUBLIC cxx_std_17)
set_target_properties(velsigil PROPERTIES
  CXX_EXTENSIONS OFF
  POSITION_INDEPENDENT_CODE ON
  EXPORT_NAME velsigil)

target_include_directories(velsigil
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src)

# Dependencies stay private: the public header only uses the standard library.
target_link_libraries(velsigil
  PRIVATE
    CURL::libcurl
    ${VX_SODIUM_TARGET}
    Threads::Threads
    $<BUILD_INTERFACE:nlohmann_json::nlohmann_json>)

if(WIN32)
  # Windows 7 API level; MinGW defaults to an older one.
  target_compile_definitions(velsigil PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0601 WINVER=0x0601)
  target_link_libraries(velsigil PRIVATE advapi32)  # registry and file ACLs
endif()

if(MSVC)
  target_compile_options(velsigil PRIVATE /W4 /permissive- /utf-8)
else()
  target_compile_options(velsigil PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(VX_BUILD_EXAMPLES)
  add_executable(velsigil_example_basic examples/basic.cpp)
  target_link_libraries(velsigil_example_basic PRIVATE velsigil::velsigil)
  if(MSVC)
    target_compile_options(velsigil_example_basic PRIVATE /W4 /permissive- /utf-8)
  endif()
endif()

if(VX_BUILD_TESTS)
  enable_testing()

  # Release tarballs ship the vectors here; a repository checkout keeps them one level up.
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test-vectors.json")
    set(VX_DEFAULT_TEST_VECTORS "${CMAKE_CURRENT_SOURCE_DIR}/test-vectors.json")
  else()
    get_filename_component(VX_DEFAULT_TEST_VECTORS "${CMAKE_CURRENT_SOURCE_DIR}/../test-vectors.json" ABSOLUTE)
  endif()
  set(VX_TEST_VECTORS "${VX_DEFAULT_TEST_VECTORS}" CACHE FILEPATH "Path to the shared test-vectors.json")
  if(NOT EXISTS "${VX_TEST_VECTORS}")
    message(FATAL_ERROR "VX_TEST_VECTORS: ${VX_TEST_VECTORS} does not exist. Pass -DVX_TEST_VECTORS=<path to test-vectors.json> or -DVX_BUILD_TESTS=OFF.")
  endif()

  # The public helpers refuse the test-vector keys, so this test uses src/detail.hpp.
  add_executable(velsigil_vector_tests tests/vector_tests.cpp)
  target_link_libraries(velsigil_vector_tests PRIVATE velsigil::velsigil nlohmann_json::nlohmann_json)
  target_include_directories(velsigil_vector_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_compile_definitions(velsigil_vector_tests PRIVATE VX_TEST_VECTORS_PATH="${VX_TEST_VECTORS}")
  add_test(NAME velsigil_vector_tests COMMAND velsigil_vector_tests)

  add_executable(velsigil_client_tests tests/client_tests.cpp)
  target_link_libraries(velsigil_client_tests PRIVATE velsigil::velsigil nlohmann_json::nlohmann_json ${VX_SODIUM_TARGET} Threads::Threads)
  target_include_directories(velsigil_client_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_compile_definitions(velsigil_client_tests PRIVATE VX_TEST_VECTORS_PATH="${VX_TEST_VECTORS}")
  add_test(NAME velsigil_client_tests COMMAND velsigil_client_tests)

  add_executable(velsigil_untyped_optin_tests tests/untyped_optin_tests.cpp)
  target_link_libraries(velsigil_untyped_optin_tests PRIVATE velsigil::velsigil nlohmann_json::nlohmann_json)
  target_include_directories(velsigil_untyped_optin_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_compile_definitions(velsigil_untyped_optin_tests PRIVATE VELSIGIL_ALLOW_UNTYPED_ENVELOPE
                             VX_TEST_VECTORS_PATH="${VX_TEST_VECTORS}")
  add_test(NAME velsigil_untyped_optin_tests COMMAND velsigil_untyped_optin_tests)

  foreach(vx_test IN ITEMS velsigil_vector_tests velsigil_client_tests velsigil_untyped_optin_tests)
    if(WIN32)
      target_compile_definitions(${vx_test} PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
    endif()
    if(MSVC)
      target_compile_options(${vx_test} PRIVATE /W4 /permissive- /utf-8)
    endif()
  endforeach()

  if(VX_BUILD_HTTP_TESTS)
    find_package(Python3 COMPONENTS Interpreter REQUIRED)
    add_executable(velsigil_http_tests tests/http_tests.cpp)
    target_link_libraries(velsigil_http_tests PRIVATE velsigil::velsigil)
    if(MSVC)
      target_compile_options(velsigil_http_tests PRIVATE /W4 /permissive- /utf-8)
    endif()
    add_test(NAME velsigil_http_tests
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/mock_server/run_http_tests.py
              --vectors ${VX_TEST_VECTORS} -- $<TARGET_FILE:velsigil_http_tests>)
  endif()
endif()

if(VX_INSTALL)
  include(CMakePackageConfigHelpers)

  install(TARGETS velsigil
    EXPORT velsigilTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
  install(DIRECTORY include/velsigil DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
  install(EXPORT velsigilTargets
    NAMESPACE velsigil::
    FILE velsigilTargets.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/velsigil)

  configure_package_config_file(cmake/velsigilConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/velsigilConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/velsigil)
  write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/velsigilConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion)
  install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/velsigilConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/velsigilConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/velsigil)
  install(FILES LICENSE README.md CHANGELOG.md DESTINATION ${CMAKE_INSTALL_DOCDIR})
endif()
