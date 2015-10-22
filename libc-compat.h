#ifndef __PROCD_LIBC_COMPAT_H
#define __PROCD_LIBC_COMPAT_H

#if defined(__GLIBC__) && !defined(__UCLIBC__)
static inline int ignore(int x) {return x;}
#else
#define ignore(x) x
#endif

#endif
