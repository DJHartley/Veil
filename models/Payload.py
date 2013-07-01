# -*- coding: utf-8 -*-
'''
Created on Mar 12, 2012

@author: moloch
'''

import os

from models import dbsession
from sqlalchemy import Column, ForeignKey
from sqlalchemy.types import String, Integer
from models.BaseObject import BaseObject


class Payload(BaseObject):
    ''' Payload settings '''

    user_id = Column(Integer,
        ForeignKey('user.id'), 
        nullable=False
    )
    file_path = Column(String(1024))
    lhost = Column(String(256), default="0.0.0.0")
    lport = Column(Integer, default=4444)
    msfpayload = Column(String(256))
    protocol = Column(String(32))
    cryptor = Column(String(32))

    @classmethod
    def by_id(cls, sid):
        return dbsession.query(cls).filter_by(id=sid).first()

    @classmethod
    def by_uuid(cls, sid):
        return dbsession.query(cls).filter_by(uuid=sid).first()

    @property
    def msfoptions(self):
        _msfoptions = []
        _msfoptions.append("LHOST=%s" % self.lhost)
        _msfoptions.append("LPORT=%d" % self.lport)
        return _msfoptions

    @property
    def file_name(self):
        return os.path.basename(str(self.file_path))

    @property
    def rc_file_name(self):
        return self.file_name.replace('.exe', '.rc')

    @property
    def size(self):
        if self.file_path is not None and os.path.exists(self.file_path):
            f = open(self.file_path, 'r')
            _size = len(f.read())
            f.close()
            return _size
        else:
            return 0

    def get_rc_file(self):
        ''' Create an rc file that starts the msf handler '''
        rc = '''
use exploit/multi/handler
set PAYLOAD %s
set LHOST %s
set LPORT %d
''' % (self.msfpayload, self.lhost, self.lport)
        if 'reverse' in self.msfpayload:
            rc += 'set ExitOnSession false\n'
            rc += 'exploit -j\n\n'
        else:
            rc += 'exploit\n\n'
        return rc

    def __str__(self):
    	return "Created: %s | MSFPayload: %s | Port: %d | Download: %s" % (
            self.created, self.msfpayload, self.lport, self.url
        )