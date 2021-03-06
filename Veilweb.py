#!/usr/bin/env python
'''
    Copyright 2012 Root the Box

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
'''


from optparse import OptionParser
from datetime import datetime
from libs.ConsoleColors import *


__version__ = '0.0.1'
current_time = lambda: str(datetime.now()).split(' ')[1].split('.')[0]


def serve(options, *args, **kwargs):
    ''' Starts the application '''
    from libs.ConfigManager import ConfigManager  # Sets up logging
    from handlers import start_server
    print(INFO + '%s : Starting application ...' % current_time())
    start_server()


def create(options, *args, **kwargs):
    ''' Creates/bootstraps the database '''
    from libs.ConfigManager import ConfigManager  # Sets up logging
    from models import create_tables, boot_strap
    print(INFO + '%s : Creating the database ...' % current_time())
    create_tables()
    print(INFO + '%s : Bootstrapping the database ...' % current_time())
    boot_strap()


### Main
if __name__ == '__main__':
    parser = OptionParser(
        version=__version__,
    )
    parser.add_option(
        "-c", "--create-tables",
        action="callback",
        callback=create,
        help="create database tables"
    )
    parser.add_option(
        "-s", "--start", "--serve",
        action="callback",
        callback=serve,
        help="start the server"
    )
    parser.parse_args()
