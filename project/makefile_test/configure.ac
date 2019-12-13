#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT(make_test, 1.1, )
AC_CONFIG_SRCDIR([src/test.cpp])
AC_CONFIG_HEADERS([config.h])
##AM_INIT_AUTOMAKE
AM_INIT_AUTOMAKE
# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
##LT_INIT

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

AC_OUTPUT(Makefile
	  src/Makefile
          src/debug/Makefile
	  src/test/Makefile)
