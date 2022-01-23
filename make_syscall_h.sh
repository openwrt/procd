#!/bin/sh
# syscall reporting example for seccomp
#
# Copyright (c) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
# Authors:
#  Kees Cook <keescook@chromium.org>
#
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

CC=$1
[ -n "$TARGET_CC_NOCACHE" ] && CC=$TARGET_CC_NOCACHE

echo "#include <asm/unistd.h>"
echo "static const char *__syscall_names[] = {"
echo "#include <sys/syscall.h>" | ${CC} -E -dM - | grep '^#define __NR_[a-z0-9_]\+[ \t].*[0-9].*$' | \
	LC_ALL=C sed -r -n -e 's/^\#define[ \t]+__NR_([a-z0-9_]+)[ \t]+([ ()+0-9a-zNR_LSYCABE]+)(.*)/ [\2] = "\1",/p'
echo "};"

extra_syscalls="$(echo "#include <sys/syscall.h>" | ${CC} -E -dM - | sed -r -n -e 's/^#define __ARM_NR_([a-z0-9_]+)/\1/p')"

cat <<EOF
static inline const char *syscall_name(unsigned i) {
  if (i < ARRAY_SIZE(__syscall_names))
    return __syscall_names[i];
  switch (i) {
EOF
echo "$extra_syscalls" | \
    LC_ALL=C sed -r -n -e 's/^([a-z0-9_]+)[ \t]+([ ()+0-9a-zNR_LAMBSE]+)(.*)/    case \2: return "\1";/p'
cat <<EOF
  default: return (void*)0;
  }
}
EOF

cat <<EOF
static inline int syscall_index(unsigned i) {
  if (i < ARRAY_SIZE(__syscall_names))
    return i;
  switch (i) {
EOF
echo "$extra_syscalls" | \
    LC_ALL=C perl -ne 'print "  case $2: return ARRAY_SIZE(__syscall_names) + ", $. - 1, ";\n" if /^([a-z0-9_]+)[ \t]+([ ()+0-9a-zNR_LAMBSE]+)(.*)/;'
cat <<EOF
  default: return -1;
  }
}
EOF

cat <<EOF
static inline int syscall_index_to_number(unsigned i) {
  if (i < ARRAY_SIZE(__syscall_names))
    return i;
  switch (i) {
EOF
echo "$extra_syscalls" | \
    LC_ALL=C perl -ne 'print "  case ARRAY_SIZE(__syscall_names) + ", $. - 1, ": return $2;\n" if /^([a-z0-9_]+)[ \t]+([ ()+0-9a-zNR_LAMBSE]+)(.*)/;'
cat <<EOF
  default: return -1;
  }
}
EOF

echo "#define SYSCALL_COUNT (ARRAY_SIZE(__syscall_names) + $({ test -n "$extra_syscalls" && echo "$extra_syscalls"; } | wc -l))"
