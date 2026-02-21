cmake_minimum_required(VERSION 3.16)
project(fdupes LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)

find_package(OpenSSL REQUIRED)

add_executable(fdupes fdupes.cpp)
target_include_directories(fdupes PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(fdupes PRIVATE OpenSSL::Crypto)


install(TARGETS fdupes DESTINATION bin)
