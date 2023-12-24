if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.24.0")
  cmake_policy(SET CMP0135 NEW)
endif()

add_library(bpftime-agent SHARED
  agent.cpp
)
add_dependencies(bpftime-agent FridaGum spdlog::spdlog)
set_property(TARGET bpftime-agent PROPERTY CXX_STANDARD 20)
target_include_directories(bpftime-agent
  PRIVATE
  ${FRIDA_GUM_INSTALL_DIR}
  ../include
  ../../third_party/
  ${SPDLOG_INCLUDE}
)
target_link_libraries(bpftime-agent
  PRIVATE
  ${FRIDA_GUM_INSTALL_DIR}/libfrida-gum.a
  runtime
  -lpthread
  -lm
  -ldl
  spdlog::spdlog
)

include(FetchContent)

FetchContent_Declare(
  nlohmann_json
  URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz)
FetchContent_MakeAvailable(nlohmann_json)
add_dependencies(bpftime-agent nlohmann_json)
target_link_libraries(bpftime-agent PRIVATE nlohmann_json::nlohmann_json)
