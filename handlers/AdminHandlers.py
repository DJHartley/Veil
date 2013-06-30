# -*- coding: utf-8 -*-
'''
Created on Mar 13, 2012

@author: moloch

Copyright 2012

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


import logging

from models import dbsession
from models.User import User, ADMIN_PERMISSION
from handlers.BaseHandlers import BaseHandler
from libs.SecurityDecorators import *


class AdminLockHandler(BaseHandler):
    ''' Used to manually lock/unlocked accounts '''

    @authenticated
    @authorized(ADMIN_PERMISSION)
    @restrict_ip_address
    def get(self, *args, **kwargs):
        self.render('admin/manage_users.html')

    @restrict_ip_address
    @authenticated
    @authorized(ADMIN_PERMISSION)
    def post(self, *args, **kwargs):
        ''' Toggle account lock '''
        uuid = self.get_argument('uuid', '')
        user = User.by_uuid(uuid)
        if user is not None:
            user.locked = False if user.locked else True
            dbsession.add(user)
            dbsession.flush()
        self.redirect('/admin')