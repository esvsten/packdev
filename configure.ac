
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
  [ AM_LDFLAGS="$AM_LDFLAGS $glib_LIBS" 
    AM_CFLAGS="$AM_CFLAGS $glib_CFLAGS"],
  AC_MSG_ERROR(Cannot find glib-2.0, check PKG_CONFIG_PATH))

##########################################################################
# Set NUMA install path
##########################################################################
AC_ARG_WITH([numa],
    AC_HELP_STRING([--with-numa=DIR path to external libs and headers]),
    [ substitute_numa_flags="yes"],
    [])

if test "x$substitute_numa_flags" = "xyes"; then
    numa_CFLAGS="-I${with_numa}/include"
    numa_LIBS="-L${with_numa}/lib -lnuma"
fi

AM_CFLAGS="${AM_CFLAGS} ${numa_CFLAGS}" 
AM_LDFLAGS="${AM_LDFLAGS} ${numa_LIBS}" 

##########################################################################
# Set DPDK install path
##########################################################################
AC_ARG_WITH([dpdk],
    AC_HELP_STRING([--with-dpdk=DIR path to external libs and headers]),
    [ DPDK_INSTALL_PATH=$withval 
      substitute_dpdk_flags="yes"],
    [])
AC_SUBST(DPDK_INSTALL_PATH)

if test "x$substitute_dpdk_flags" = "xyes"; then
    dpdk_CFLAGS="-I${with_dpdk}/include"
    dpdk_LIBS="-L${with_dpdk}/lib -ldpdk"
fi

AM_CFLAGS="${AM_CFLAGS} ${dpdk_CFLAGS}" 
AM_LDFLAGS="${AM_LDFLAGS} ${dpdk_LIBS}" 

##########################################################################                                            
# Check for DPDK availability                                                                                         
##########################################################################                                            
PREVIOUS_LDFLAGS=$LDFLAGS
PREVIOUS_CFLAGS=$CFLAGS
LDFLAGS="$AM_LDFLAGS $LDFLAGS"
CFLAGS="$AM_CFLAGS $CFLAGS"

AC_CHECK_HEADERS([rte_config.h], [],                                                                                  
    [AC_MSG_FAILURE(["can't find DPDK headers"])])                                                                    
                                                                                                                          
AC_SEARCH_LIBS([rte_eal_init], [dpdk], [],                                                                            
    [AC_MSG_ERROR([DPDK libraries required])]) 

LDFLAGS=$PREVIOUS_LDFLAGS
CFLAGS=$PREVIOUS_CFLAGS

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
PACKDEV_CFLAGS="$PACKDEV_CFLAGS -Wno-incompatible-pointer-types"

# Extra flags for example to suppress certain warning types
PACKDEV_CFLAGS="$PACKDEV_CFLAGS $PACKDEV_CFLAGS_EXTRA"

##########################################################################
# Distribute the modified flags to Makefiles
##########################################################################
AM_CFLAGS="$AM_CFLAGS $PACKDEV_CFLAGS"
AC_SUBST([AM_CFLAGS])
AC_SUBST([AM_LDFLAGS])


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
echo Automake CFLAGS............... : $AM_CFLAGS
echo Automake LDFLAGS.............. : $AM_LDFLAGS
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

