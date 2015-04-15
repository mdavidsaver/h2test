
find_path(EVENT2_INCLUDE_DIRS event2/event.h
  HINTS ENV EVENT2_DIR
  PATHS ${EVENT2_DIR}
  PATH_SUFFIXES include
)

set(_event2_comps "")
foreach(comp IN LISTS EVENT2_FIND_COMPONENTS)
  find_library(EVENT2_${comp}_LIBRARY event_${comp}
    HINTS ENV EVENT2_DIR
    PATHS ${EVENT2_DIR}
    PATH_SUFFIXES lib
  )
  list(APPEND EVENT2_LIBRARIES ${EVENT2_${comp}_LIBRARY})
  list(APPEND _event2_comps EVENT2_${comp}_LIBRARY)
endforeach()

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(EVENT2
  REQUIRED_VARS
    EVENT2_INCLUDE_DIRS
    EVENT2_LIBRARIES
    ${_event2_comps}
)
