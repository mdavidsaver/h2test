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
  ${EVENT2_INCLUDE_DIRS}
)

# DEMO

add_library(h2com STATIC
  demo/h2transport.c demo/h2transport.h
)

add_executable(server404
  demo/serve404.c
  demo/util.c demo/util.h
)
target_link_libraries(server404
  ${NGHTTP2_LIBRARIES}
  ${EVENT2_LIBRARIES}
  h2com
)

add_executable(servertick
  demo/servetick.c
  demo/util.c demo/util.h
)
target_link_libraries(servertick
  ${NGHTTP2_LIBRARIES}
  ${EVENT2_LIBRARIES}
  h2com
)

add_executable(serverspam
  demo/servespam.c
  demo/util.c demo/util.h
)
target_link_libraries(serverspam
  ${NGHTTP2_LIBRARIES}
  ${EVENT2_LIBRARIES}
  h2com
)

add_executable(client
  demo/client.c
  demo/util.c demo/util.h
)
target_link_libraries(client
  ${NGHTTP2_LIBRARIES}
  ${EVENT2_LIBRARIES}
  h2com
)
