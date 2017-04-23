cmake_minimum_required(VERSION 2.6)

PROJECT(upgraded C)
ADD_DEFINITIONS(-Os -ggdb -Wall -Werror --std=gnu99 -Wmissing-declarations)
ADD_EXECUTABLE(upgraded upgraded.c ../watchdog.c)
TARGET_LINK_LIBRARIES(upgraded ubox)
INSTALL(TARGETS upgraded
	RUNTIME DESTINATION sbin
)
