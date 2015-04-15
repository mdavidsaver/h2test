
find_path(NGHTTP2_INCLUDE_DIRS nghttp2/nghttp2.h
  HINTS ENV NGHTTP2_DIR
  PATHS ${NGHTTP2_DIR}
  PATH_SUFFIXES include
)

find_library(NGHTTP2_LIBRARIES nghttp2
  HINTS ENV NGHTTP2_DIR
  PATHS ${NGHTTP2_DIR}
  PATH_SUFFIXES lib
)

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(NGHTTP2
  REQUIRED_VARS
    NGHTTP2_INCLUDE_DIRS
    NGHTTP2_LIBRARIES
)
