#!/usr/bin/python

import os

# Support for Squeeze, Wheezy, Jessie
struct_addrinfo_defined = False
if os.path.exists ("/etc/debian_version"):
    version = open ("/etc/debian_version").read ()
    if version[0] in ["6", "7", "8"]:
        # Jessie
        struct_addrinfo_defined = True
    # end if
# end if

# Support for Centos6
if os.path.exists ("/etc/redhat-release"):
    content = open ("/etc/redhat-release").read ()
    if "CentOS release 6" in content:
        struct_addrinfo_defined = True
    if "CentOS Linux release 7" in content:
        struct_addrinfo_defined = True
    # end if
# end if

# Support for Centos6
if os.path.exists ("/etc/lsb-release"):
    content = open ("/etc/lsb-release").read ()
    if "DISTRIB_RELEASE=12" in content:
        struct_addrinfo_defined = True
    # end if
# end if

f = open ("src/ext-dns-private-config.h", "w")
if struct_addrinfo_defined:
    f.write ("#define STRUCT_ADDRINFO_DEFINED (1)\n")
f.close ()
