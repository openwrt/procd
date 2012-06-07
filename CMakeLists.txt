cmake_minimum_required(VERSION 2.6)

PROJECT(procd C)
ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -Wmissing-declarations)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

IF(APPLE)
  INCLUDE_DIRECTORIES(/opt/local/include)
  LINK_DIRECTORIES(/opt/local/lib)
ENDIF()

SET(SOURCES main.c ubus.c service.c instance.c)

SET(LIBS ubox ubus)

IF(DEBUG)
  ADD_DEFINITIONS(-DDEBUG -g3)
ENDIF()

ADD_EXECUTABLE(procd ${SOURCES})

TARGET_LINK_LIBRARIES(procd ${LIBS})

INSTALL(TARGETS procd
	RUNTIME DESTINATION sbin
)
