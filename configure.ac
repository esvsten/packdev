
AC_PREREQ([2.69])

AC_INIT([packdev],[1.0],[https://github.com/esvsten/packdev])

AC_CONFIG_AUX_DIR(config)
AC_CONFIG_MACRO_DIR(config)
AC_CONFIG_HEADERS([packdev_config.h])
AC_CONFIG_SRCDIR([src/packdev.c])

AM_INIT_AUTOMAKE([subdir-objects])

AC_SUBST(PACKAGE_VERSION)

# Checks for programs
AC_PROG_CC
AC_PROG_CC_C99
AC_PROG_LIBTOOL

#Use libtool
LT_INIT([])

##########################################################################
# Add glib flags
##########################################################################
PKG_CHECK_MODULES([glib], [glib-2.0 >= 2.2.0],
  [LIBS="$LIBS $glib_LIBS" CFLAGS="$CFLAGS $glib_CFLAGS"],
  AC_MSG_ERROR(Cannot find glib-2.0, check PKG_CONFIG_PATH))

##########################################################################
# Set NUMA install path
##########################################################################
AC_ARG_WITH([numa],
    AC_HELP_STRING([--with-numa=DIR path to external libs and headers]),
    [ NUMA_INSTALL_PATH=$withval 
      substitute_numa_flags="yes"],
    [])
AC_SUBST(NUMA_INSTALL_PATH)

if test "x$substitute_numa_flags" = "xyes"; then
    numa_CFLAGS="-I${with_numa}/include"
    numa_LIBS="-L${with_numa}/lib -lnuma"
fi

##########################################################################
# Set DPDK install path
##########################################################################
AC_ARG_WITH([dpdk],
    AC_HELP_STRING([--with-dpdk=DIR path to external libs and headers]),
    [ DPDK_INSTALL_PATH=$withval 
      search_dpdk="yes"],
    [])
AC_SUBST(DPDK_INSTALL_PATH)

libdpdk_synthetic_cflags=""
libdpdk_synthetic_libs="-ldpdk"

if test "x$search_dpdk" = "xyes"; then
    if test -r "${with_dpdk}/include/rte_eal.h"; then
        libdpdk_synthetic_cflags="-I${with_dpdk}/include"
        libdpdk_synthetic_libs="-L${with_dpdk}/lib -ldpdk"
        found_dpdk_includes="yes"
    else
        AC_MSG_ERROR([${with_dpdk}/include/rte_eal.h not found. Please check libdpdk prefix])
    fi

    AC_MSG_CHECKING([for DPDK include files])
    AC_MSG_RESULT([$found_dpdk_includes])
fi

CFLAGS="${libdpdk_synthetic_cflags} ${numa_CFLAGS} ${CFLAGS}" 
LDFLAGS="${libdpdk_synthetic_libs} ${numa_LIBS} ${LDFLAGS}" 
LIBS="${libdpdk_synthetic_libs} ${numa_LIBS} ${LIBS}"

AC_CHECK_LIB([dpdk], [rte_eal_init],
[ AC_SUBST([dpdk_CFLAGS],[${libdpdk_synthetic_cflags}])
  AC_SUBST([dpdk_LIBS],[${libdpdk_synthetic_libs}]) ],
[AC_MSG_ERROR([cannot link with -ldpdk, install dpdk])])

##########################################################################
# Enable/disable PACKDEV_DEBUG
##########################################################################
PACKDEV_DEBUG=0
AC_ARG_ENABLE([debug],
    [--enable-debug  include debug code],
    [if test "x$enableval" = "xyes"; then
         PACKDEV_DEBUG=1
     else
         PACKDEV_DEBUG=0
     fi],
    [])
PACKDEV_CFLAGS="$PACKDEV_CFLAGS -DPACKDEV_DEBUG=$PACKDEV_DEBUG"

##########################################################################
# Default warning setup
##########################################################################
PACKDEV_CFLAGS="$PACKDEV_CFLAGS -Wincompatible-pointer-types"

# Extra flags for example to suppress certain warning types
PACKDEV_CFLAGS="$PACKDEV_CFLAGS $PACKDEV_CFLAGS_EXTRA"

##########################################################################
# Distribute the modified flags to Makefiles
##########################################################################
AM_CFLAGS="$AM_CFLAGS $PACKDEV_CFLAGS"
AC_SUBST([LIBS])
AC_SUBST([AM_CPPFLAGS])
AC_SUBST([CPPFLAGS])
AC_SUBST([AM_CFLAGS])
AC_SUBST([CFLAGS])
AC_SUBST([AM_LDFLAGS])
AC_SUBST([LDFLAGS])


# Specify output files
AC_CONFIG_FILES([Makefile src/Makefile])

AC_OUTPUT

##########################################################################
# Print configure summary and list make options
##########################################################################
AC_DEFUN([AX_SUMMARIZE_ENV],
[
BUILD_USER=${USER}
BUILD_ARCH=${host}
BUILD_HOST=${ac_hostname}
BUILD_DATE=$(date +'%F %H:%M')

AC_DEFINE_UNQUOTED([BUILD_USER],     "${BUILD_USER}",     [The fine user who built the package])
AC_DEFINE_UNQUOTED([BUILD_ARCH],     "${BUILD_ARCH}",     [Architecture of the build host])
AC_DEFINE_UNQUOTED([BUILD_HOST],     "${BUILD_HOST}",     [Build host name])
AC_DEFINE_UNQUOTED([BUILD_DATE],     "${BUILD_DATE}",     [Build date])

AC_SUBST(BUILD_USER)
AC_SUBST(BUILD_ARCH)
AC_SUBST(BUILD_HOST)
AC_SUBST(BUILD_DATE)
AC_SUBST(BUILD_VERSION)
])


AC_DEFUN([AX_SUMMARIZE_CONFIG],
[
echo
echo '##########################################################################'
echo '#                                SUMMARY                                 #'
echo '##########################################################################'
echo
echo Package version............... : $PACKAGE-$VERSION
echo
echo C compiler.................... : $CC
echo C compiler flags.............. : $CFLAGS
echo C++ compiler.................. : $CXX
echo C++ compiler flags............ : $CXXFLAGS
echo Configure date................ : $BUILD_DATE
echo Build architecture............ : $BUILD_ARCH
echo Build host.................... : $BUILD_HOST
echo Build user.................... : $USER
echo Install dir................... : $prefix

echo
echo '##########################################################################'

echo
echo Configure complete! Now proceed with:
echo "    - 'make'               compile the project"
echo "    - 'make install'       install the project to $prefix"
echo
])

AX_SUMMARIZE_ENV
AX_SUMMARIZE_CONFIG

