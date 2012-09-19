#!/usr/bin/python

import sys

while True:
    # get command from ext-dns
    sys.stdout.flush ()
    command = raw_input ().strip ()

    # sys.stderr.write ("COMMAND RECEIVED: %s\n" % command)

    if command == "INIT":
        # sys.stderr.write ("REPLYING INIT OK\n")
        # ext-dnsd is requesting to start this resolver, we have to
        # reply OK to satisfy its inquire anyway
        print "OK\n"
    # end if

# end while
