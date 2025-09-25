cmake_minimum_required(VERSION 3.20)
project(baksmali_cpp VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(Threads REQUIRED)

# Include directories
include_directories(src)

# Source files
file(GLOB_RECURSE SOURCES
    "src/*.cpp"
    "src/*.hpp"
)

# Exclude main.cpp from library sources
list(FILTER SOURCES EXCLUDE REGEX ".*main\\.cpp$")

# Create library
add_library(baksmali_lib ${SOURCES})

# Link libraries
target_link_libraries(baksmali_lib Threads::Threads)

# Create executable
add_executable(baksmali src/main.cpp)
target_link_libraries(baksmali baksmali_lib)

# Compiler flags
target_compile_options(baksmali_lib PRIVATE
    -Wall -Wextra -Wpedantic -O3
)

target_compile_options(baksmali PRIVATE
    -Wall -Wextra -Wpedantic -O3
)

# Install targets
install(TARGETS baksmali DESTINATION bin)