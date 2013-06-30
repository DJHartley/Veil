# -*- coding: utf-8 -*-
'''
Created on Mar 12, 2012

@author: moloch
'''


from models import dbsession
from sqlalchemy import Column, ForeignKey
from sqlalchemy.types import String, Integer
from irc_models.BaseObject import BaseObject


class Payload(BaseObject):
    ''' Payload settings '''

    user_id = Column(Integer,
        ForeignKey('user.id'), 
        nullable=False
    )
    file_name = Column(String(256), nullable=False)
    lhost = Column(String(256), default="0.0.0.0")
    lport = Column(Integer, default=4444)
    msfpayload = Column(String(256))
    url = Column(String(256))
    protocol = Column(String(32))
    cryptor = Column(String(32))

    @classmethod
    def by_id(cls, sid):
        return dbsession.query(cls).filter_by(id=sid).first()

    @property
    def msfoptions(self):
        _msfoptions = []
        _msfoptions.append("LHOST=%s" % self.lhost)
        _msfoptions.append("LPORT=%d" % self.port)
        return _msfoptions

    def __str__(self):
    	return "Created: %s | MSFPayload: %s | Port: %d | Download: %s" % (
            self.created, self.msfpayload, self.lport, self.url
        )