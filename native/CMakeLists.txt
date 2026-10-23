cmake_minimum_required(VERSION 3.16)
project(profast_native VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(PF_BUILD_TOOLS "Build the pfbench verification tool" ON)
option(PF_BUILD_TESTS "Build native unit tests" ON)

# Multi-config generators (Visual Studio, Xcode) append the configuration name
# to the runtime output directory unless it is set per configuration. Doing so
# keeps the tools at build/native/bin/<tool> on every generator, which is the
# path the scripts, CI and docs use.
function(pf_place_runtime target)
    set_target_properties(${target} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
    foreach(config DEBUG RELEASE RELWITHDEBINFO MINSIZEREL)
        set_target_properties(${target} PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY_${config} ${CMAKE_BINARY_DIR}/bin)
    endforeach()
endfunction()

set(PF_SOURCES
    src/sha256.cpp
    src/mirage.cpp
    src/packet.cpp
    src/bucket.cpp
    src/capi.cpp
)

if(WIN32)
    list(APPEND PF_SOURCES src/process_win32.cpp)
else()
    list(APPEND PF_SOURCES src/process_posix.cpp)
endif()

add_library(profast_native SHARED ${PF_SOURCES})
add_library(profast_native_static STATIC ${PF_SOURCES})

foreach(target profast_native profast_native_static)
    target_include_directories(${target}
        PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
               $<INSTALL_INTERFACE:include>
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /O2)
        target_compile_definitions(${target} PRIVATE _CRT_SECURE_NO_WARNINGS)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -O2 -fvisibility=hidden)
    endif()
endforeach()

set_target_properties(profast_native PROPERTIES OUTPUT_NAME profast_native)
set_target_properties(profast_native_static PROPERTIES OUTPUT_NAME profast_native)

if(PF_BUILD_TOOLS)
    add_executable(pfbench tools/pfbench.cpp)
    target_link_libraries(pfbench PRIVATE profast_native_static)
    if(MSVC)
        target_compile_options(pfbench PRIVATE /W4)
    else()
        target_compile_options(pfbench PRIVATE -Wall -Wextra)
    endif()
    pf_place_runtime(pfbench)
endif()

if(PF_BUILD_TESTS)
    enable_testing()
    add_executable(pf_native_tests tests/native_tests.cpp)
    target_link_libraries(pf_native_tests PRIVATE profast_native_static)
    target_include_directories(pf_native_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    add_test(NAME pf_native_tests COMMAND pf_native_tests)
    pf_place_runtime(pf_native_tests)
endif()

include(GNUInstallDirs)
install(TARGETS profast_native profast_native_static
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES include/profast/native.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/profast)
