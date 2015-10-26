#!/usr/bin/python

import sys
import syslog
import time

import subprocess
from subprocess import PIPE
import fcntl
import os

def _read_content (stream):
    # The function returns (content, exception_found, exception) for
    # each call to this stream.
    # 
    # If exception_found is set to True, it means an error was found
    # while reading and the exception is reported on content.
    # 
    # In the case it went ok, content read is returned and
    # exception_found is set to False.

    try:
        return (stream.read (), False, None)
    except IOError, err:
        return (None, True, err)
    # never reached


def run (command, run_as = None, timeout = None, output_byte_limit = 10485760, output_handler = None, output_handler_data = None):
    """
    Allows to run the provided command returning (status, output)
    where status contains the exit code and output contains the
    command complete output.

    The command can be run as the provided user (run_as) and it is
    possible to control the command timeout.
    
    Note that output will be limited to the provided amount of bytes
    (which is by default 10MB). If you want bigger limites, consider
    working out with the command to redirect the output to a file
    since it may provide you with memory problems.

    Keyword parameters:
    
    command - The command to run
    
    run_as - Optional parameter to request running the command as the provided user
    
    timeout - Optional timeout (in seconds) to limit command execution
    
    output_byte_limit -- Optional output byte limit to avoid overloading Memory by a long running command with too much output.

    output_handler -- Optional handler that with the following signature (should_continue, new_content) = output_handler (content) that receives every piece of output get from the command executed allowing to translate it or to indicate that the command should stop.

    output_handler_data -- Optional data that is passed in to the output_handler (in case the handler if defined).

    Returns:
    (status, output) -- A tuple containing the exit code (status) and output reported by the command (output).
    """
    # Error skipped, it will be used in the future
    # [ W0613 ] command.py:8 run: Unused argument 'run_as'


    # check for empty command
    if command is None:
        return (False, "Received None command, nothing to execute")
    command = command.strip ()
    if len (command) == 0:
        return (False, "Received empty command, nothing to execute")

    # grab a copy of current lang value
    lang_was_found = False
    try:
        global lang
        # Hack to modify caller's global lang if defined
        # [ W0601 ] command.py:53 run: Global variable 'lang' undefined at the module level
        local_lang = lang
        lang_was_found = True
    except Exception:
        pass

    # run the command in a subprocess and let other threads to work
    # during the execution
    proc = subprocess.Popen (command, shell = True, stdout = PIPE, stderr = PIPE)

    fl = fcntl.fcntl (proc.stdout, fcntl.F_GETFL)
    fcntl.fcntl(proc.stdout, fcntl.F_SETFL, fl | os.O_NONBLOCK)

    fl = fcntl.fcntl (proc.stderr, fcntl.F_GETFL)
    fcntl.fcntl(proc.stderr, fcntl.F_SETFL, fl | os.O_NONBLOCK)

    # track starting stamp
    if timeout > 0:
        start_stamp = time.time ()

    # while no result is found
    result = ""
    while True:

        # get current status
        status = proc.poll ()
        if status != None:
            break

        # get output if any
        # print "Blocked on communiate.."
        (value_0, exception_found,  exception)  = _read_content (proc.stdout)
        (value_1, exception_found2, exception2) = _read_content (proc.stderr)
        
        # errors skipped, for now we don't use those variables
        # [ W0612 ] command.py:86 run: Unused variable 'exception'
        # [ W0612 ] command.py:87 run: Unused variable 'exception2'

        if exception_found or exception_found2:
            if timeout > 0 and time.time () > (start_stamp + timeout):
                # kill the process
                os.kill (proc.pid, 15)
                return (-1, "Timeout reached during command execution. Output gathered until now was: %s" % result)

            # introduce a wait
            time.sleep (0.1)

        if output_handler:
            if value_0:
                (should_continue, value_0) = output_handler (value_0, output_handler_data)
                if not should_continue:
                    if value_0:
                        result += value_0
                    return (-1, "Output handler requested to stop, command result until now as: %s" % result)
                # end if
            # end if
            if value_1:
                (should_continue, value_1) = output_handler (value_1, output_handler_data)
                if not should_continue:
                    if value_1:
                        result += value_1
                    return (-1, "Output handler requested to stop, command result until now as: %s" % result)
                # end if
            # end if
        # end if

        if value_0:
            result += value_0
        if value_1:
            result += value_1

        if len (result) > output_byte_limit:
            os.kill (proc.pid, 15)
            return (-1, "Output byte limit reached (%d bytes). Output gathered until now was: %s" % (output_byte_limit, result))
            
    # restore lang found before the command
    if lang_was_found:
        lang = local_lang

    # process returned, get output                                                                                                                                            
    (value_0, exception_found, exception)   = _read_content (proc.stdout)
    (value_1, exception_found2, exception2) = _read_content (proc.stderr)
    
    try:

        # check for output handler and calling for translation
        if output_handler:
            if value_0:
                (should_continue, value_0) = output_handler (value_0, output_handler_data)
                if not should_continue:
                    if value_0:
                        result += value_0
                    return (-1, "Output handler requested to stop, command result until now as: %s" % result)
                # end if
                
            # end if
            if value_1:
                (should_continue, value_1) = output_handler (value_1, output_handler_data)
                if not should_continue:
                    if value_1:
                        result += value_1
                    return (-1, "Output handler requested to stop, command result until now as: %s" % result)
                # end if
            # end if
        # end if

        if value_0:
            result += value_0
        if value_1:
            result += value_1
    except Exception:
        pass

    return (status, result)

def log (message):
    # send log to the system log
    syslog.syslog ("ext-dns-watcher: %s" % message) 

    if not verbose:
        return

    # show message to the console
    print "ext-dns-watcher: %s" % message
    return

def restart_ext_dns ():
    # call to kill all ext-dnsd instances
    run ("killall -9 ext-dnsd")
    run ("killall -9 ext-dnsd")

    time.sleep (2)

    # call to restart
    run ("/etc/init.d/ext-dnsd restart")

    return

def check_ext_dns_running ():
    # check ext-dns is running
    (status, output) = run ("ps faux | grep ext-dnsd | grep -v grep  ")
    if status:
        log ("ERROR: ext-dnsd server wasn't found running (0x80001), error was: %s" % output)
        return False

    lines = output.split ("\n")
    if not lines:
        log ("ERROR: ext-dnsd server wasn't found running (0x80002), attempting to restart ext-dnsd")
        return False

    # call to get current IP configured
    (status, output) = run ("ext-dnsd -p")
    if status:
        log ("ERROR: ext-dnsd -p reported wrong value: %s (0x80003), attempting to restart ext-dnsd" % output)
        return False

    # clear ip
    hostip = output.strip ()

    # run command to get resolution
    attempts = 0
    while attempts < 3:
        # call to get resolution
        (status, output)  = run ("edq www.aspl.es %s" % hostip)
        attempts         += 1

        if status:
            log ("ERROR: host resolution from %s is failing (0x80004), output was: %s" % (hostip, output))
            if attempts < 3:
                continue

            # attemps reached
            return False
        # end if

        if "has address" not in output:
            log ("ERROR: expected 'has address' result but found something different: %s (0x80005), calling to restart ext-dnsd" % output)
            return False
        # end if
    # end while

    # reported everything is working
    return True


verbose = False
if "--verbose" in sys.argv:
    verbose = True


if __name__ == "__main__":
    # check ext-dns is running
    status = check_ext_dns_running ()
    if status:
        log ("INFO: ext-dnsd is running and service DNS without error (0x80010)")
        sys.exit (0)

    # call to restart
    log ("ERROR: ext-dnsd is not running, try to restart it (0x80006)")
    restart_ext_dns ()

    # check ext-dns is running
    status = check_ext_dns_running ()
    if status:
        log ("INFO: ext-dnsd wasn't running but it was recovered (0x80007)")
        sys.exit (0)

    log ("ERROR: ext-dnsd is not working and it is not responding to restart commands, please review it (0x80008)")
    sys.exit (-1)
