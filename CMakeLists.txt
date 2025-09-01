cmake_minimum_required(VERSION 3.15)
project(neo3crypto-core)

set(CMAKE_CXX_STANDARD 17)

include(FetchContent)
FetchContent_Declare(
        pybind11
        GIT_REPOSITORY https://github.com/pybind/pybind11.git
        GIT_TAG        v2.13.6
)
FetchContent_MakeAvailable(pybind11)

pybind11_add_module(neo3crypto python-bindings.cpp ecc.h ecc.cpp microecc/uECC.h microecc/uECC.c smhasher/src/MurmurHash3.h smhasher/src/MurmurHash3.cpp)
if(MSVC)
    target_link_libraries(neo3crypto PRIVATE advapi32)
endif()
