set(TEST_SOURCES
    nv_attach_impl_tests.cpp
    test_register_guard.cpp
    # test_kernel_finder.cpp
)
add_executable(bpftime_nv_attach_tests ${TEST_SOURCES})

option(TEST_LCOV "option for lcov" OFF)

if(${TEST_LCOV})
    target_compile_options(bpftime_nv_attach_tests PRIVATE -fprofile-arcs -ftest-coverage -fprofile-update=atomic)
endif()
if(${ENABLE_EBPF_VERIFIER} AND NOT TARGET Catch2)
    message(STATUS "Adding Catch2 by FetchContent at nv_attach_impl")
    Include(FetchContent)
    FetchContent_Declare(
        Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG v3.4.0
    )
    FetchContent_MakeAvailable(Catch2)

    # if not enable verifier, we will use the catch2 from submodule
endif()

add_dependencies(bpftime_nv_attach_tests Catch2 bpftime_nv_attach_impl spdlog::spdlog)
if(${TEST_LCOV})
    target_link_options(bpftime_nv_attach_tests PRIVATE -lgcov)
    target_link_libraries(bpftime_nv_attach_tests PRIVATE Catch2::Catch2WithMain bpftime_nv_attach_impl spdlog::spdlog gcov cuda)
else()
    target_link_libraries(bpftime_nv_attach_tests PRIVATE Catch2::Catch2WithMain bpftime_nv_attach_impl spdlog::spdlog cuda)
endif()
target_include_directories(bpftime_nv_attach_tests PRIVATE ${CMAKE_SOURCE_DIR}/runtime/ ${NV_ATTACH_IMPL_INCLUDE} ${Catch2_INCLUDE} ${SPDLOG_INCLUDE})

add_test(NAME bpftime_nv_attach_tests COMMAND bpftime_nv_attach_tests)

set_property(TARGET bpftime_nv_attach_tests PROPERTY CXX_STANDARD 20)
