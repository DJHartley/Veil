# -*- coding: utf-8 -*-
'''
Created on Mar 12, 2012

@author: moloch
'''

from os import urandom
from models import dbsession
from models.Permission import Permission
from pbkdf2 import PBKDF2
from sqlalchemy import Column, or_
from sqlalchemy.orm import relationship, backref, synonym
from sqlalchemy.types import String, Boolean
from models.BaseObject import BaseObject


### Constants
ITERATE = 1337
ADMIN_PERMISSION = 'administrator'


class User(BaseObject):

    name = Column(String(32), unique=True, nullable=False)
    history = relationship("Payload", 
        backref=backref("User", lazy="select"), 
        cascade="all, delete-orphan"
    )
    _locked = Column(Boolean, default=True)
    salt = Column(String(16),
        unique=True,
        nullable=False,
        default=lambda: urandom(8).encode('hex')
    )
    _password = Column('password', String(64))
    password = synonym('_password', descriptor=property(
        lambda self: self._password,
        lambda self, password: setattr(self, '_password',
            self.__class__._hash_password(password, self.salt)
        )
    ))
    permissions = relationship("Permission",
        backref=backref("User", lazy="joined"),
        cascade="all, delete-orphan"
    )

    @classmethod
    def by_id(cls, sid):
        return dbsession.query(cls).filter_by(id=sid).first()

    @classmethod
    def by_uuid(cls, sid):
        return dbsession.query(cls).filter_by(uuid=sid).first()

    @classmethod
    def by_name(cls, name):
        return dbsession.query(cls).filter_by(name=name).first()

    @classmethod
    def all(cls):
        ''' Returns a list of all objects in the database '''
        return dbsession.query(cls).all()

    @classmethod
    def all_users(cls):
        ''' Return all non-admin user objects '''
        return filter(lambda user: user.has_permission(ADMIN_PERMISSION) is False, cls.all())

    @classmethod
    def _hash_password(cls, password, salt):
        ''' PBKDF2 hash of password '''
        return PBKDF2(password, salt, iterations=ITERATE).read(32).encode('hex')

    @property
    def permissions(self):
        ''' Return a list with all permissions granted to the user '''
        return dbsession.query(Permission).filter_by(user_id=self.id)

    @property
    def permissions_names(self):
        ''' Return a list with all permissions names granted to the user '''
        return [permission.name for permission in self.permissions]

    @property
    def locked(self):
        '''
        Determines if an admin has locked an account, accounts with
        administrative permissions cannot be locked.
        '''
        if self.has_permission(ADMIN_PERMISSION):
            return False # Admin accounts cannot be locked
        else:
            return self._locked

    @locked.setter
    def locked(self, value):
        ''' Setter method for _lock '''
        assert isinstance(value, bool)
        if not self.has_permission(ADMIN_PERMISSION):
            self._locked = value

    def has_permission(self, permission):
        ''' Return True if 'permission' is in permissions_names '''
        return True if permission in self.permissions_names else False

    def validate_password(self, attempt):
        ''' Check the password against existing credentials '''
        return self.password == self._hash_password(attempt, self.salt)

    def __str__(self):
        return self.name
