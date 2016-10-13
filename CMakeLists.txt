cmake_minimum_required(VERSION 2.6)

PROJECT(procd C)
INCLUDE(GNUInstallDirs)
ADD_DEFINITIONS(-Os -ggdb -Wall -Werror --std=gnu99 -Wmissing-declarations)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

IF(APPLE)
  INCLUDE_DIRECTORIES(/opt/local/include)
  LINK_DIRECTORIES(/opt/local/lib)
ENDIF()


ADD_LIBRARY(setlbf SHARED service/setlbf.c)
INSTALL(TARGETS setlbf
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)


SET(SOURCES procd.c signal.c state.c inittab.c rcS.c ubus.c system.c
	service/service.c service/instance.c service/validate.c service/trigger.c service/watch.c
	utils/utils.c)
IF(NOT DISABLE_INIT)
  SET(SOURCES ${SOURCES} watchdog.c plug/coldplug.c plug/hotplug.c)
ENDIF()

SET(LIBS ubox ubus json-c blobmsg_json json_script)

IF(DEBUG)
  ADD_DEFINITIONS(-DUDEV_DEBUG -g3)
ENDIF()

IF(EARLY_PATH)
  ADD_DEFINITIONS(-DEARLY_PATH="${EARLY_PATH}")
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
	RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

FIND_PATH(ubox_include_dir libubox/uloop.h)
INCLUDE_DIRECTORIES(${ubox_include_dir})

IF(DISABLE_INIT)
ADD_DEFINITIONS(-DDISABLE_INIT)
ELSE()
ADD_EXECUTABLE(init initd/init.c initd/early.c initd/preinit.c initd/mkdev.c watchdog.c
	utils/utils.c ${SOURCES_ZRAM})
TARGET_LINK_LIBRARIES(init ${LIBS})
INSTALL(TARGETS init
	RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

ADD_EXECUTABLE(udevtrigger plug/udevtrigger.c)
INSTALL(TARGETS udevtrigger
	RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)
ENDIF()


ADD_EXECUTABLE(askfirst utils/askfirst.c)
INSTALL(TARGETS askfirst
	RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

ADD_CUSTOM_COMMAND(
	OUTPUT syscall-names.h
	COMMAND ./make_syscall_h.sh ${CMAKE_C_COMPILER} > ./syscall-names.h
	DEPENDS ./make_syscall_h.sh
)
ADD_CUSTOM_TARGET(syscall-names-h DEPENDS syscall-names.h)

ADD_CUSTOM_COMMAND(
	OUTPUT capabilities-names.h
	COMMAND ./make_capabilities_h.sh ${CMAKE_C_COMPILER} > ./capabilities-names.h
	DEPENDS ./make_capabilities_h.sh
)
ADD_CUSTOM_TARGET(capabilities-names-h DEPENDS capabilities-names.h)

IF(SECCOMP_SUPPORT)
ADD_LIBRARY(preload-seccomp SHARED jail/preload.c jail/seccomp.c)
TARGET_LINK_LIBRARIES(preload-seccomp dl ubox blobmsg_json)
INSTALL(TARGETS preload-seccomp
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
ADD_DEPENDENCIES(preload-seccomp syscall-names-h)
endif()

IF(JAIL_SUPPORT)
ADD_EXECUTABLE(ujail jail/jail.c jail/elf.c jail/fs.c jail/capabilities.c)
TARGET_LINK_LIBRARIES(ujail ubox blobmsg_json)
INSTALL(TARGETS ujail
	RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)
ADD_DEPENDENCIES(ujail capabilities-names-h)
endif()

IF(UTRACE_SUPPORT)
ADD_EXECUTABLE(utrace trace/trace.c)
TARGET_LINK_LIBRARIES(utrace ubox ${json} blobmsg_json)
INSTALL(TARGETS utrace
	RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)
ADD_DEPENDENCIES(utrace syscall-names-h)

ADD_LIBRARY(preload-trace SHARED trace/preload.c)
TARGET_LINK_LIBRARIES(preload-trace dl)
INSTALL(TARGETS preload-trace
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
endif()
