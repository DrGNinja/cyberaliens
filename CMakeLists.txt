cmake_minimum_required(VERSION 3.16)
project(Cyb3rALIENS_Sim VERSION 1.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    add_compile_options(/W4 /permissive-)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

include_directories(${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/third_party)

set(CORE_SOURCES
    src/entropy.cpp
    src/dna_identity.cpp
    src/dual_mc.cpp
    src/aes_sea.cpp
    src/p2pe_channel.cpp
    src/iam_registry.cpp
    src/bce_ledger.cpp
    src/process_trace.cpp
)

# ---------- Main simulation + web executable ----------
add_executable(cyb3raliens_sim
    ${CORE_SOURCES}
    src/demo_harness.cpp
    src/web_api.cpp
    src/main.cpp
)
target_link_libraries(cyb3raliens_sim PRIVATE OpenSSL::SSL OpenSSL::Crypto Threads::Threads)

# ---------- Unit tests ----------
add_executable(cyb3raliens_tests
    tests/test_core.cpp
    ${CORE_SOURCES}
)
target_link_libraries(cyb3raliens_tests PRIVATE OpenSSL::SSL OpenSSL::Crypto Threads::Threads)

file(MAKE_DIRECTORY ${CMAKE_SOURCE_DIR}/data)

install(TARGETS cyb3raliens_sim DESTINATION bin)
install(DIRECTORY web/ DESTINATION share/cyb3raliens/web)

message(STATUS "=======================================================")
message(STATUS "  Cyb3rALIENS Pure Simulation v${PROJECT_VERSION}")
message(STATUS "  Build : cmake -B build && cmake --build build")
message(STATUS "  Run   : ./build/cyb3raliens_sim          (console menu)")
message(STATUS "          ./build/cyb3raliens_sim --demo   (full auto)")
message(STATUS "          ./build/cyb3raliens_sim --web    (browser UI)")
message(STATUS "  Tests : ./build/cyb3raliens_tests")
message(STATUS "=======================================================")
