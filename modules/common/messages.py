"""
Common terminal messages used across the framework.
"""

import os
import sys
import logging

from config import veil
from modules.common import helpers

def title():
    """
    Print the framework title, with version.
    """
    logging.info('=========================================================================')
    logging.info(' Veil | [Version]: 2.0 ')
    logging.info('=========================================================================')
    logging.info(' [Web]: https://www.veil-evasion.com/ | [Twitter]: @veilevasion')
    logging.info('=========================================================================')  
    # check to make sure the current OS is supported,
    # print a warning message if it's not and exit
    if veil.OPERATING_SYSTEM == "Windows" or veil.OPERATING_SYSTEM == "Unsupported":
        print helpers.color(' [!] ERROR: Your operating system is not currently supported...\n', warning=True)
        print helpers.color(' [!] ERROR: Request your distribution at the GitHub repository...\n', warning=True)
        sys.exit()


def helpmsg(commands, showTitle=True):
    """
    Print a help menu.
    """
    if showTitle:
        title()
    
    print " Available commands:\n"
    
    # list commands in sorted order
    for cmd in sorted(commands.iterkeys(), reverse=True):
        print "\t%s\t%s" % ('{0: <12}'.format(cmd), commands[cmd])
    print ""

def endmsg():
    """
    Print the exit message.
    """
    print " [*] Your payload files have been generated, don't get caught!" 
    print helpers.color(" [!] And don't submit samples to any online scanner! ;)\n", warning=True)
