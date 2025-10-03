cmake_minimum_required(VERSION 3.10)

PROJECT(upgraded C)
FIND_PATH(ubox_include_dir libubox/uloop.h)
INCLUDE_DIRECTORIES(${ubox_include_dir})
ADD_DEFINITIONS(-Os -ggdb -Wall -Werror --std=gnu99 -Wmissing-declarations)
ADD_EXECUTABLE(upgraded upgraded.c ../watchdog.c)
TARGET_LINK_LIBRARIES(upgraded ${ubox})
INSTALL(TARGETS upgraded
	RUNTIME DESTINATION sbin
)
