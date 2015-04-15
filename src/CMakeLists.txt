project(h2test C CXX)

cmake_minimum_required(VERSION 2.8)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE DEBUG)
endif()

if(CMAKE_COMPILER_IS_GNUCC)
  add_definitions(-Wall -Werror)
endif()

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../cmake)

find_package(NGHTTP2 REQUIRED)

find_package(EVENT2 REQUIRED COMPONENTS core extra)

include_directories(
  ${NGHTTP2_INCLUDE_DIRS}
)

add_executable(server404
  serve404.c
  util.c util.h
)
target_link_libraries(server404
  ${NGHTTP2_LIBRARIES}
  ${EVENT2_LIBRARIES}
)

add_executable(client
  client.c
  util.c util.h
)
target_link_libraries(client
  ${NGHTTP2_LIBRARIES}
  ${EVENT2_LIBRARIES}
)