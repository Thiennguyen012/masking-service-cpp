cmake_minimum_required(VERSION 3.14)
project(masking-service LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add executable
add_executable(masking-service src/main.cpp)

# Include path for header-only libs (httplib.h, json.hpp)
target_include_directories(masking-service PRIVATE include)

# Windows: link ws2_32 for sockets
if(WIN32)
    target_link_libraries(masking-service ws2_32)
endif()
