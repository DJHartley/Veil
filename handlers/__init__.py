# -*- coding: utf-8 -*-
'''
Created on Mar 13, 2012

@author: moloch

    Copyright 2012 Root the Box

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License
----------------------------------------------------------------------------

This is the main file the defines what URLs get routed to what handlers

'''


import sys

from os import urandom, path, _exit
from base64 import b64encode
from webuimodules.Menu import Menu
from libs.ConsoleColors import *
from libs.ConfigManager import ConfigManager
from tornado import netutil
from tornado.web import Application, StaticFileHandler
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop, PeriodicCallback
from handlers.ErrorHandlers import *
from handlers.PublicHandlers import *
from handlers.AdminHandlers import *
from handlers.VeilHandlers import *


config = ConfigManager.Instance()
app = Application(
    [
        # Static Handlers - StaticFileHandler.py
        (r'/static/(.*)', 
            StaticFileHandler, {'path': 'static/'}),

        # Admin Handlers - AdminHandlers.py
        (r'/admin', AdminLockHandler),

        # Veil Handlers - VeilHandlers.py
        (r'/create/(bind|reverse)', CreatePayloadHandler),
        (r'/history(.*)', HistoryHandler),
        (r'/download/(exe|rc)', DownloadHandler),

        # Public handlers - PublicHandlers.py
        (r'/login', LoginHandler),
        (r'/logout', LogoutHandler),
        (r'/registration', RegistrationHandler),
        (r'/about', AboutHandler),
        (r'/', HomePageHandler),

        # Error handlers - ErrorHandlers.py
        (r'/403', UnauthorizedHandler),
        (r'/(.*)', NotFoundHandler)
    ],

    # Randomly generated secret key
    cookie_secret=b64encode(urandom(64).encode('hex')),

    # Ip addresses that access the admin interface
    admin_ips=config.admin_ips,

    # Template directory
    template_path='templates/',

    # Request that does not pass @authorized will be
    # redirected here
    forbidden_url='/403',

    # Requests that does not pass @authenticated  will be
    # redirected here
    login_url='/login',

    # UI Modules
    ui_modules={
        "Menu": Menu,
    },

    # Enable XSRF protected forms; not optional
    xsrf_cookies=True,

    # WebSocket Host IP Address
    domain=config.domain,
    port=config.listen_port,

    # Debug mode
    debug=config.debug,

    # Version
    version='0.0.1',
)


# Main entry point
def start_server():
    ''' Main entry point for the application '''
    server = HTTPServer(app)
    sockets = netutil.bind_sockets(config.listen_port)
    server.add_sockets(sockets)
    io_loop = IOLoop.instance()
    try:
        sys.stdout.write("\r" + INFO + "The game has begun, good hunting!\n")
        if config.debug:
            sys.stdout.write(WARN + "WARNING: Debug mode is enabled.\n")
        sys.stdout.flush()
        io_loop.start()
    except KeyboardInterrupt:
        sys.stdout.write('\r' + WARN + 'Shutdown Everything!\n')
    except:
      logging.exception("Main i/o loop threw exception")
    finally:
        io_loop.stop()
        _exit(0)
