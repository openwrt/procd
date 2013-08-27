cmake_minimum_required(VERSION 2.6)

PROJECT(procd C)
ADD_DEFINITIONS(-Os -ggdb -Wall -Werror --std=gnu99 -Wmissing-declarations)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

IF(APPLE)
  INCLUDE_DIRECTORIES(/opt/local/include)
  LINK_DIRECTORIES(/opt/local/lib)
ENDIF()

SET(SOURCES main.c ubus.c service.c instance.c utils.c md5.c hotplug.c state.c mkdev.c early.c inittab.c preinit.c coldplug.c syslog.c log.c watchdog.c signal.c system.c debug.c rcS.c trigger.c measure.c)

find_library(json NAMES json-c json)
SET(LIBS ubox ubus ${json} blobmsg_json json_script)

IF(DEBUG)
  ADD_DEFINITIONS(-DDEBUG -g3)
ENDIF()

ADD_EXECUTABLE(procd ${SOURCES})

TARGET_LINK_LIBRARIES(procd ${LIBS})

INSTALL(TARGETS procd
	RUNTIME DESTINATION sbin
)

ADD_EXECUTABLE(askfirst askfirst.c)

INSTALL(TARGETS askfirst
	RUNTIME DESTINATION sbin
)

ADD_EXECUTABLE(udevtrigger udevtrigger.c)

INSTALL(TARGETS udevtrigger
	RUNTIME DESTINATION sbin
)

ADD_EXECUTABLE(logread logread.c)
TARGET_LINK_LIBRARIES(logread ${LIBS})

INSTALL(TARGETS logread
	RUNTIME DESTINATION sbin
)
