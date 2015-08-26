#!/bin/sh

CC=$1
[ -n "$TARGET_CC_NOCACHE" ] && CC=$TARGET_CC_NOCACHE

echo "#include <linux/capability.h>"
echo "static const char *capabilities_names[] = {"
echo "#include <linux/capability.h>" | ${CC} -E -dM - | grep '#define CAP' | grep -vE '(CAP_TO|CAP_LAST_CAP)' | \
	awk '{print $3" "$2}' | sort -n | awk '{print "   ["$1"]\t= \""tolower($2)"\","}'
echo "};"
