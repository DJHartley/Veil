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
    limitations under the License.
'''


import logging

from libs.ConfigManager import ConfigManager
from handlers.BaseHandlers import BaseHandler
from models import dbsession, User
from models.User import ADMIN_PERMISSION

class HomePageHandler(BaseHandler):

    def get(self, *args, **kwargs):
        ''' Renders the about page '''
        if self.get_current_user() is not None:
            self.redirect('/history')
        else:
            self.render("public/home.html")


class LoginHandler(BaseHandler):
    ''' Takes care of the login process '''

    def get(self, *args, **kwargs):
        ''' Display the login page '''
        if self.get_current_user() is not None:
            self.redirect('/history')
        else:
            self.render('public/login.html', errors=None)

    def post(self, *args, **kwargs):
        ''' Checks submitted username and password '''
        user = User.by_name(self.get_argument('account', ''))
        password_attempt = self.get_argument('password', '')
        if user is not None and user.validate_password(password_attempt):
            if not user.locked:
                self.successful_login(user)
                if user.has_permission(ADMIN_PERMISSION):
                    self.redirect('/admin')
                else:
                    self.redirect('/history')
            else:
                self.render('public/login.html', 
                    errors=["Your account has been locked"]
                )
        else:
            self.failed_login()

    def successful_login(self, user):
        ''' Called when a user successfully logs in '''
        logging.info("Successful login: %s from %s" %
            (user.name, self.request.remote_ip,))
        self.start_session()
        self.session['user_id'] = int(user.id)
        self.session['username'] = ''.join(user.name)  # Copy string
        if user.has_permission(ADMIN_PERMISSION):
            self.session['menu'] = 'admin'
        else:
            self.session['menu'] = 'user'
        self.session.save()

    def failed_login(self):
        ''' Called if username or password is invalid '''
        logging.info("Failed login attempt from: %s" % self.request.remote_ip)
        self.render('public/login.html',
            errors=["Bad username and/or password, try again"]
        )


class RegistrationHandler(BaseHandler):
    ''' Registration Code '''

    def get(self, *args, **kwargs):
        ''' Renders the registration page '''
        if self.get_current_user() is not None:
            self.redirect('/history')
        else:
            self.render("public/registration.html", 
                errors=None
            )

    def post(self, *args, **kwargs):
        ''' Attempts to create an account, with shitty form validation '''
        username = self.get_argument('username', None)
        pass1 = self.get_argument('pass1', None)
        pass2 = self.get_argument('pass1', None)
        if username is None or User.by_name(username) is not None:
            self.render('public/registration.html', 
                errors=['Invalid username']
            )
        elif pass1 is None or pass2 is None:
            self.render('public/registration.html', 
                errors=['Please type your password twice']
            )
        elif pass1 != pass2:             
            self.render('public/registration.html', 
                errors=['Passwords do not match']
            )
        elif len(pass1) < 12:
            self.render('public/registration.html', 
                errors=['Passwords too shore (min. 12)']
            )            
        else:
            password = self.get_argument('pass1')
            user = self.create_user(username, password)
            self.render('public/successful_reg.html', user=user)

    def create_user(self, username, password):
        ''' Add user to the database '''
        user = User(name=username)
        dbsession.add(user)
        dbsession.flush()
        user.password = password
        dbsession.add(user)
        dbsession.flush()
        return user


class LogoutHandler(BaseHandler):
    ''' Log user out of current session '''

    def get(self, *args, **kwargs):
        ''' Redirect '''
        if self.session is not None:
            self.redirect('/user')
        else:
            self.redirect('/login')

    def post(self, *args, **kwargs):
        ''' 
        This is POST to avoid any CSRF issues,
        Clears cookies and session data 
        '''
        if self.session is not None:
            self.session.delete()
        self.clear_all_cookies()
        self.redirect("/")


class AboutHandler(BaseHandler):

    def get(self, *args, **kwargs):
        ''' Renders the about page '''
        self.render('public/about.html')
