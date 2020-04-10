#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([idemix], [0.1.0], [douxing@zchz.com])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_MACRO_DIRS([m4])
AC_CONFIG_SRCDIR([.])
AC_CONFIG_HEADERS([config.h])
AM_PROG_AR

LT_INIT

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lgmp':
AC_CHECK_LIB([gmp], [mpz_init])
# FIXME: Replace `main' with a function in `-lpbc':
AC_CHECK_LIB([pbc], [element_init])

# Checks for header files.
AC_CHECK_HEADERS([memory.h stdint.h stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
# AC_C_INLINE
AC_TYPE_SIZE_T
# AC_CHECK_HEADER_STDBOOL
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset])

AC_CONFIG_FILES([Makefile example/Makefile])

AC_OUTPUT
