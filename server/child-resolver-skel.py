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
        print "OK"
    elif command[0:7] == "RESOLVE":
        query_items = command.split (" ")
        source_ip   = query_items[1]
        name        = query_items[2]
        dns_record  = query_items[3]
        dns_class   = query_items[4]

        if dns_class != "IN":
            # we only resolve in IN
            print "FORWARD"
            # forward query but ask to not cache result
            # print "FORWARD nocache"
            continue

        # example about letting the server to do the resolution
        if dns_record != "A":
            # we only resolve in IN
            print "FORWARD"
            continue

        print "FORWARD"
        continue

        # example about rewriting a request into another name
        if name == "www.google.com":
            print "REPLY name:www.aspl.es 3600"
            continue

        # example about giving an ip as a reply
        print "REPLY ipv4:192.168.0.1 3600"

    else:
        # by default, if command is not handled, reply forward to make
        # the server to forward the reply to the forward dns server
        # configured and reply to the user with the result
        print "FORWARD"
    # end if

# end while
