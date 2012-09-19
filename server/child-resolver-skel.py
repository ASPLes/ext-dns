#!/usr/bin/python

while True:
    # get command from ext-dns
    command = raw_input ()

    if command == "INIT":
        # ext-dnsd is requesting to start this resolver, we have to
        # reply OK to satisfy its inquire anyway
        print "OK"
    # end if

# end while
