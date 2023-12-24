if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.24.0")
    cmake_policy(SET CMP0135 NEW)
endif()

add_library(bpftime-agent-transformer SHARED
    agent-transformer.cpp
    text_segment_transformer.cpp
)
add_dependencies(bpftime-agent-transformer spdlog::spdlog FridaGum)
set_property(TARGET bpftime-agent-transformer PROPERTY CXX_STANDARD 20)

target_link_libraries(bpftime-agent-transformer
    PRIVATE
    spdlog::spdlog
    ${FRIDA_GUM_INSTALL_DIR}/libfrida-gum.a
)

target_include_directories(bpftime-agent-transformer
    PRIVATE
    ${FRIDA_GUM_INSTALL_DIR}
    ${SPDLOG_INCLUDE}
)

include(FetchContent)

FetchContent_Declare(
    nlohmann_json
    URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz)
FetchContent_MakeAvailable(nlohmann_json)
add_dependencies(bpftime-agent-transformer nlohmann_json)
target_link_libraries(bpftime-agent-transformer PRIVATE nlohmann_json::nlohmann_json)
