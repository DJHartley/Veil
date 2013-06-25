# -*- coding: utf-8 -*-
'''
Created on Mar 12, 2012

@author: moloch
'''


from models import dbsession
from sqlalchemy import Column, or_
from sqlalchemy.types import String
from models.BaseObject import BaseObject


class User(BaseObject):

    nick = Column(String(32), unique=True, nullable=False)
    history = relationship("Payload", 
        backref=backref("User", lazy="select"), 
        cascade="all, delete-orphan"
    )

    @classmethod
    def by_id(cls, sid):
        return dbsession.query(cls).filter_by(id=sid).first()

    @classmethod
    def by_nick(cls, nick):
        return dbsession.query(cls).filter_by(nick=nick).first()
