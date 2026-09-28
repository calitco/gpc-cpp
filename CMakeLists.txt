cmake_minimum_required(VERSION 3.16)
project(globalprotect_cpp CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

add_compile_options(-Wall -Wextra -Wpedantic)

find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)

add_library(gpcore STATIC
  src/security_options.cpp
  src/random.cpp
  src/html_escape.cpp
  src/net_common.cpp
  src/trace.cpp
  src/cert_policy.cpp
  src/auth_server.cpp
  src/callback_listener.cpp
  src/secret_transport.cpp
  src/service_key.cpp
  src/http_client.cpp
  src/cookie_store.cpp
  src/xml.cpp
  src/json.cpp
  src/posture.cpp
  src/gui.cpp
  src/aead.cpp
  src/ws.cpp
  src/service_daemon.cpp
  src/gateway_client.cpp
  src/tunnel_client.cpp
  src/client_flow.cpp
)
target_include_directories(gpcore PUBLIC include)
# Internal POSIX helpers are exposed to tests and the demo only.
target_include_directories(gpcore PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>)
target_link_libraries(gpcore PUBLIC OpenSSL::SSL OpenSSL::Crypto CURL::libcurl)

enable_testing()

set(GP_TESTS
  test_options
  test_random
  test_html_escape
  test_cert_policy
  test_auth_server
  test_callback_listener
  test_secret_transport
  test_service_key
  test_http_client
  test_cookie_store
  test_xml
  test_json
  test_posture
  test_gui
  test_aead
  test_ws
  test_service_daemon
  test_gateway_client
  test_tunnel_client
  test_client_flow
)

foreach(t ${GP_TESTS})
  add_executable(${t} tests/${t}.cpp)
  target_link_libraries(${t} PRIVATE gpcore)
  add_test(NAME ${t} COMMAND ${t})
endforeach()

add_executable(gp_auth_demo examples/gp_auth_demo.cpp)
target_link_libraries(gp_auth_demo PRIVATE gpcore)

# End-to-end client (Wave H). No tunnel backend is compiled in this build;
# the binary authenticates, obtains the endpoint, and keeps the session alive.
add_executable(gpclient apps/gpclient.cpp)
target_link_libraries(gpclient PRIVATE gpcore)
