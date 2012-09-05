dnl  ext-dns: a DNS framework
dnl  Copyright (C) 2012 Advanced Software Production Line, S.L.
dnl
dnl  This program is free software; you can redistribute it and/or
dnl  modify it under the terms of the GNU Lesser General Public License
dnl  as published by the Free Software Foundation; either version 2.1 of
dnl  the License, or (at your option) any later version.
dnl
dnl  This program is distributed in the hope that it will be useful,
dnl  but WITHOUT ANY WARRANTY; without even the implied warranty of 
dnl  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the  
dnl  GNU Lesser General Public License for more details.
dnl
dnl  You should have received a copy of the GNU Lesser General Public
dnl  License along with this program; if not, write to the Free
dnl  Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
dnl  02111-1307 USA
dnl  
dnl  You may find a copy of the license under this software is released
dnl  at COPYING file. This is LGPL software: you are wellcome to
dnl  develop propietary applications using this library withtout any
dnl  royalty or fee but returning back any change, improvement or
dnl  addition in the form of source code, project image, documentation
dnl  patches, etc. 
dnl
dnl  For comercial support:
dnl          
dnl      Postal address:
dnl         Advanced Software Production Line, S.L.
dnl         C/ Antonio Suarez Nº10, Edificio Alius A, Despacho 102
dnl         Alcalá de Henares 28802 Madrid
dnl         Spain
dnl
dnl      Email address:
dnl         info@aspl.es - http://www.aspl.es/dns-ext
dnl

AC_INIT(src/ext-dns.h)

configure_dir=`dirname "$0"`
EXT_DNS_VERSION=`cat $configure_dir/VERSION`
AC_SUBST(EXT_DNS_VERSION)

AC_CONFIG_AUX_DIR(.)
AM_INIT_AUTOMAKE(ext_dns, $EXT_DNS_VERSION)
AM_CONFIG_HEADER(config.h)
AM_MAINTAINER_MODE

AC_PROG_CC
AC_ISC_POSIX
AC_HEADER_STDC
AM_PROG_LIBTOOL

compiler_options=""
STRICT_PROTOTYPES=""
if test "$compiler" = "gcc" ; then
   compiler_options="-Wstrict-prototypes -Wall -Werror -g -ansi"
   echo "Detected gcc compiler: $compiler, adding options: $compiler_options"
fi
AC_SUBST(compiler_options)

AC_CHECK_PROG(PKG_CONFIG, pkg-config, "yes", "no")
if test "$PKG_CONFIG" = "no" ; then
  AC_MSG_ERROR([You need to install pkg-config to compile ext-Dns. See: http://pkgconfig.freedesktop.org/releases/])
fi

dnl
dnl Thread detection support mostly taken from the apache project 2.2.3.
dnl
dnl EXT_DNS_PTHREADS_TRY_RUN(actions-if-success)
dnl
dnl Try running a program which uses pthreads, executing the
dnl actions-if-success commands on success.
dnl
AC_DEFUN([EXT_DNS_PTHREADS_TRY_RUN], [
AC_TRY_RUN( [
#include <pthread.h>
#include <stddef.h>

void *thread_routine(void *data) {
    return data;
}

int main() {
    pthread_t thd;
    pthread_mutexattr_t mattr;
    pthread_once_t once_init = PTHREAD_ONCE_INIT;
    int data = 1;
    pthread_mutexattr_init(&mattr);
    return pthread_create(&thd, NULL, thread_routine, &data);
} ], [ext_dns_p_t_r=yes], [ext_dns_p_t_r=no], [ext_dns_p_t_r=no])

if test $ext_dns_p_t_r = yes; then
  $1
fi

])dnl


dnl
dnl EXT_DNS_PTHREADS_CHECK()
dnl
dnl Try to find a way to enable POSIX threads.  Sets the 
dnl pthreads_working variable to "yes" on success.
dnl
AC_DEFUN([EXT_DNS_PTHREADS_CHECK],[

AC_CACHE_CHECK([for CFLAGS needed for pthreads], [ext_dns_cv_pthreads_cflags],
[ext_dns_ptc_cflags=$CFLAGS
 for flag in -kthread -pthread -pthreads -mt -mthreads -Kthread -threads; do 
    CFLAGS=$ext_dns_ptc_cflags
    test "x$flag" != "xnone" && CFLAGS="$CFLAGS $flag"
    EXT_DNS_PTHREADS_TRY_RUN([
      ext_dns_cv_pthreads_cflags="$flag"
      break
    ])
 done
 CFLAGS=$ext_dns_ptc_cflags
])

# The CFLAGS may or may not be sufficient to ensure that libext_dns
# depends on the pthreads library: some versions of libtool
# drop -pthread when passed on the link line; some versions of
# gcc ignore -pthread when linking a shared object.  So always
# try and add the relevant library to LIBS too.

AC_CACHE_CHECK([for LIBS needed for pthreads], [ext_dns_cv_pthreads_lib], [
  ext_dns_ptc_libs=$LIBS
  for lib in -lpthread -lpthreads -lc_r; do
    LIBS="$ext_dns_ptc_libs $lib"
    EXT_DNS_PTHREADS_TRY_RUN([
      ext_dns_cv_pthreads_lib=$lib
      break
    ])
  done
  LIBS=$ext_dns_ptc_libs
])

if test "$pthreads_working" = "yes"; then
  threads_result="POSIX Threads found"
else
  threads_result="POSIX Threads not found"
fi
])dnl

dnl call to detect thread activation support
EXT_DNS_PTHREADS_CHECK

PTHREAD_CFLAGS="$ext_dns_cv_pthreads_cflags"
PTHREAD_LIBS="$ext_dns_cv_pthreads_lib"
AC_SUBST(PTHREAD_CFLAGS)
AC_SUBST(PTHREAD_LIBS)

dnl check for poll support
AC_CHECK_HEADER(sys/poll.h, enable_poll=yes, enable_poll=no)
AM_CONDITIONAL(ENABLE_POLL_SUPPORT, test "x$enable_poll" = "xyes")

dnl Check for the Linux epoll interface; epoll* may be available in libc
dnl with Linux kernels 2.6.X
AC_CACHE_CHECK([for epoll(2) support], [enable_cv_epoll],
[AC_TRY_RUN([
#include <sys/epoll.h>
#include <unistd.h>

int main()
{
    return epoll_create(5) == -1;
}], [enable_cv_epoll=yes], [enable_cv_epoll=no], [enable_cv_epoll=no])])
AM_CONDITIONAL(ENABLE_EPOLL_SUPPORT, test "x$enable_cv_epoll" = "xyes")

dnl select the best I/O platform
if test x$enable_cv_epoll = xyes ; then
   default_platform="epoll"
elif test x$enable_poll = xyes ; then
   default_platform="poll"
else 
   default_platform="select"
fi
AM_CONDITIONAL(DEFAULT_EPOLL, test "x$default_platform" = "xepoll")
AM_CONDITIONAL(DEFAULT_POLL, test "x$default_platform" = "xpoll")


dnl LibAxl library support.
PKG_CHECK_MODULES(AXL, axl >= 0.6.4)
AC_SUBST(AXL_CFLAGS)
AC_SUBST(AXL_LIBS)

dnl check for console log
AC_ARG_ENABLE(ext-dns-log, [  --enable-ext-dns-log       Enable building Ext_Dns Library console debug log support [default=yes]], 
	      enable_ext_dns_log="$enableval", 
	      enable_ext_dns_log=yes)
AM_CONDITIONAL(ENABLE_EXT_DNS_LOG, test "x$enable_ext_dns_log" = "xyes")

dnl general libries subsitution
dnl AC_SUBST(LIBRARIES_CFLAGS)
dnl AC_SUBST(LIBRARIES_LIBS)

dnl get current platform and add especific flags
case $host in
  *-*-beos*)
    echo "Found BEOS platform: $host.."
    ;;
  *-*-cygwin*)
    echo "Found cygwin platform: $host.."
    ;;
  *-*-mingw*)
    echo "Found mingw platform: $host.."
    ADDITIONAL_LIBS=-lws2_32
    ;;
  *)
    echo "Found platform: $host.."
    ;;
esac
AC_SUBST(ADDITIONAL_LIBS)

AC_OUTPUT([
Makefile
src/Makefile
test/Makefile
])

echo "------------------------------------------"
echo "--     ext-DNS  SETTINGS                 --"
echo "------------------------------------------"
echo "   Installation prefix:            [$prefix]"
echo "      select(2) support:           [yes]"
echo "      poll(2) support:             [$enable_poll]"
echo "      epoll(2) support:            [$enable_cv_epoll]"
echo "      default:                     [$default_platform]"
echo "      debug log support:           [$enable_ext_dns_log]"
echo "      pthread cflags=$PTHREAD_CFLAGS, libs=$PTHREAD_LIBS"
echo "      additional libs=$ADDITIONAL_LIBS"
if test x$enable_ext_dns_log = xyes ; then
echo "      NOTE: To disable log reporting use: "
echo "            --disable-ext-dns-log"               
fi
echo
echo "   Axl installation: "
echo "      cflags: $AXL_CFLAGS"
echo "      libs:   $AXL_LIBS"
echo
if test x$DOXYGEN = xyes ; then
   echo "   Build ext-DNS Library doc:                 enabled"
else	    
   echo "   Build ext-DNS Library doc:                 disabled"
   echo  
   echo "     NOTE: To enable ext-DNS documentation you will"
   echo "     have to install doxygen tool. Then run again"
   echo "     configure process."
fi
echo
echo "------------------------------------------"
echo "--     NOW TYPE: make; make install     --"
echo "------------------------------------------"
