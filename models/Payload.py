# -*- coding: utf-8 -*-
'''
Created on Mar 12, 2012

@author: moloch
'''


from models import dbsession
from sqlalchemy import Column, or_
from sqlalchemy.types import String
from models.BaseObject import BaseObject


class Payload(BaseObject):
	''' Payload settings '''

    lport = Column(String(32),)
    lhost = Column(String(32),)
    rport = Column(String(32),)
    rhost = Column(String(32),)
    msfpayload = Column(String(64),)
    msfoptions = Column(String(64),)
    download_url = Column(String(64),)

    @classmethod
    def by_id(cls, sid):
        return dbsession.query(cls).filter_by(id=sid).first()

    def get_rc(self):
    	pass

    def __str__(self):
    	return self.msfpayload