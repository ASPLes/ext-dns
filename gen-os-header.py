#!/usr/bin/python

import os

struct_addrinfo_defined = False
if os.path.exists ("/etc/debian_version"):
    version = open ("/etc/debian_version").read ()
    if "8" == version[0]:
        # Jessie
        struct_addrinfo_defined = True
    # end if
# end if

f = open ("src/ext-dns-private-config.h", "w")
if struct_addrinfo_defined:
    f.write ("#define STRUCT_ADDRINFO_DEFINED (1)\n")
f.close ()
