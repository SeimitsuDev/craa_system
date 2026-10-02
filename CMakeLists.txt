cmake_minimum_required(VERSION 3.14)
project(custom_chat_system VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# OpenSSL Package found
find_package(OpenSSL REQUIRED)
message(STATUS "[Status] OpenSSL found: ${OPENSSL_VERSION}")
message(STATUS "[Status] OpenSSL include directory: ${OPENSSL_INCLUDE_DIR}")

# Include directories with headers and linkers
include_directories(${CMAKE_SOURCE_DIR}/include ${OPENSSL_INCLUDE_DIR})
message(STATUS "[Status] Include directories: ${CMAKE_SOURCE_DIR}/include, ${OPENSSL_INCLUDE_DIR}")
message(STATUS "[Status] Linker libraries: ${OPENSSL_LIBRARIES}")

# Added src/transfer_manager.cpp to support backpressure and chunk management
add_library(network_core src/socket.cpp src/auth.cpp src/transfer_manager.cpp)
target_link_libraries(network_core PRIVATE OpenSSL::Crypto)

add_executable(server app/server.cpp)
target_link_libraries(server PRIVATE network_core OpenSSL::Crypto)

add_executable(client app/client.cpp)
target_link_libraries(client PRIVATE network_core OpenSSL::Crypto)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    message(STATUS "[Config] Production release mode: Logs disabled.")
else()
    target_compile_definitions(network_core PRIVATE DEBUG_MODE)
    target_compile_definitions(server PRIVATE DEBUG_MODE)
    target_compile_definitions(client PRIVATE DEBUG_MODE)
    message(STATUS "[Config] Debug logging enabled.")
endif()