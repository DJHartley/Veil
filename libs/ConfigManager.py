# -*- coding: utf-8 -*-
'''
Created on June 30, 2012

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
    limitations under the License.
'''


import os
import sys
import getpass
import logging
import ConfigParser

from libs.ConsoleColors import *
from libs.Singleton import Singleton


# .basicConfig must be called prior to ANY call to logging.XXXX so make sure
# this module gets imported prior to any logging!
logging.basicConfig(
    format='\r[%(levelname)s] %(asctime)s - %(message)s', level=logging.DEBUG
)


@Singleton
class ConfigManager(object):
    ''' Central class which handles any user-controlled settings '''

    def __init__(self, cfg_file='config/veilweb.cfg'):
        if os.path.exists(cfg_file) and os.path.isfile(cfg_file):
            self.conf = os.path.abspath(cfg_file)
        else:
            logging.critical(
                "No configuration file found at: %s." % self.conf
            )
            os._exit(1)
        logging.info('Loading config from: %s' % self.conf)
        self.config = ConfigParser.SafeConfigParser()
        self.config.readfp(open(self.conf, 'r'))
        self.__server__()
        self.__sessions__()
        self.__security__()

    def __server__(self):
        ''' Load network configurations '''
        self.listen_port = self.config.getint("Server", 'port')
        log_level = self.config.get("Server", 'logging')
        logger = logging.getLogger()
        if log_level.lower() == 'debug':
            logger.setLevel(logging.DEBUG)
        elif log_level.lower() == 'info':
            logger.setLevel(logging.INFO)
        elif log_level.lower() == 'warn':
            logger.setLevel(logging.WARN)
        else:
            sys.stdout.write(WARN + "Logging level has not been set.\n")
            logger.setLevel(logging.NOTSET)
        sys.stdout.flush()
        self.debug = self.config.getboolean("Server", 'debug')
        self.domain = self.config.get("Server", 'domain').replace(' ', '')

    def __sessions__(self):
        ''' Session settings '''
        self.memcached_server = self.config.get("Sessions", 'memcached')
        self.session_age = self.config.getint("Sessions", 'session_age')
        self.session_regeneration_interval = self.config.getint("Sessions",
            'session_regeneration_interval'
        )

    def __security__(self):
        ''' Load security configurations '''
        ips = self.config.get("Security", 'admin_ips', "127.0.0.1").replace(" ", "")
        ips = ips.split(',')
        if not '127.0.0.1' in ips:
            ips.append('127.0.0.1')
        self.admin_ips = tuple(ips)
        