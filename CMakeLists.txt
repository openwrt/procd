cmake_minimum_required(VERSION 2.6)

PROJECT(procd C)
ADD_DEFINITIONS(-Os -ggdb -Wall -Werror --std=gnu99 -Wmissing-declarations)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

IF(APPLE)
  INCLUDE_DIRECTORIES(/opt/local/include)
  LINK_DIRECTORIES(/opt/local/lib)
ENDIF()

SET(SOURCES procd.c signal.c watchdog.c state.c	inittab.c rcS.c	ubus.c system.c
	service/service.c service/instance.c service/validate.c service/trigger.c service/watch.c
	plug/coldplug.c plug/hotplug.c utils/utils.c)

SET(LIBS ubox ubus json-c blobmsg_json json_script)

IF(DEBUG)
  ADD_DEFINITIONS(-DDEBUG -g3)
ENDIF()

IF(ZRAM_TMPFS)
  ADD_DEFINITIONS(-DZRAM_TMPFS)
  SET(SOURCES_ZRAM initd/zram.c)
ENDIF()

IF(BUILD_UPGRADED)
  add_subdirectory(upgraded)
ENDIF()

ADD_EXECUTABLE(procd ${SOURCES})
TARGET_LINK_LIBRARIES(procd ${LIBS})
INSTALL(TARGETS procd
	RUNTIME DESTINATION sbin
)


ADD_EXECUTABLE(init initd/init.c initd/early.c initd/preinit.c initd/mkdev.c watchdog.c
	utils/utils.c ${SOURCES_ZRAM})
TARGET_LINK_LIBRARIES(init ${LIBS})
INSTALL(TARGETS init
	RUNTIME DESTINATION sbin
)


ADD_EXECUTABLE(udevtrigger plug/udevtrigger.c)
INSTALL(TARGETS udevtrigger
	RUNTIME DESTINATION sbin
)


ADD_EXECUTABLE(askfirst utils/askfirst.c)
INSTALL(TARGETS askfirst
	RUNTIME DESTINATION sbin
)
