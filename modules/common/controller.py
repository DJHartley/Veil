"""
Contains the main controller object for Veil.

"""

# Import Modules
import glob
import imp
import sys
import os
import readline
import re
import socket
import commands
import time
import logging

try:
    from config import veil
except ImportError:
    logging.info(' Veil First Run Detected... Initializing Script Setup...')
    # run the config if it hasn't been run
    logging.info('Executing ./config/update.py...')
    os.system('cd config && python update.py') 
    try:
        from config import veil
    except ImportError:
        logging.error("run ./config/update.py manually")
        sys.exit()

        
from os.path import join, basename, splitext
from modules.common import messages
from modules.common import helpers
from modules.common import supportfiles
from modules.common import completers


class Controller:
    """
    Principal controller object that's instantiated.
    
    Loads all payload modules dynamically from ./modules/payloads/* and
    builds store the instantiated payload objects in self.payloads.
    has options to list languages/payloads, manually set payloads, 
    generate code, and provides the main interactive
    menu that lists payloads and allows for user ineraction.
    """
    
    def __init__(self, langs = None):
        self.payloads = []
        # a specific payload, so we can set it manually
        self.payload = None
        # restrict loaded modules to specific languages
        self.langs = langs
        self.firstRun = True
        
        # "help":"print help screen",
        self.commands = { "use":"use a specific payload",
             "info":"information on a specific payload",
             "list":"list available languages/payloads",
             "exit":"exit Veil"}
        
        self.payloadCommands = {"set":"set a specific option value",
                "info":"show information about the payload",
                "help":"show help menu for payload",
                "back":"go to the main menu",
                "generate":"generate payload"}
        
        self.LoadPayloads()


    def LoadPayloads(self):
        """
        Loads payload modules into an internal self.payloads object.
        
        Loads all payload modules dynamically from ./modules/payloads/* and
        builds store the instantiated payload objects in self.payloads. The
        format for self.payloads is a list of tuples of the form [ (name : <payload object>) ]
        """

        # TODO: detect Windows and modify the paths appropriately
        data = dict((splitext(basename(path))[0], imp.load_source(splitext(basename(path))[0],path)) for path in glob.glob(join(veil.VEIL_PATH + "/modules/payloads/*/",'[!_]*.py')) )
        for name in data:
            stager = data[name].Stager()
            # if specific languages to use are specified, only load those payload modules
            if self.langs:
                if stager.language in self.langs:
                    self.payloads.append( (name, stager) )
            else: self.payloads.append( (name, stager) ) 
            
        # sort the payloads by language name
        self.payloads = sorted(self.payloads, key=lambda x: (x[0]))


    def ListLangs(self):
        """
        Prints out all available languages of loaded paylod modules.
        
        """
        langs = []
        for (name, payload) in self.payloads: 
            langs.append(payload.language)
        return set(langs)

    def ListPayloads(self, lang):
        """
        Prints out the available payloads for a specific language.
        
        lang = the language to list ("python"/"c"/etc.)
        """
        payloads = []
        for (name, payload) in self.payloads: 
            if payload.language == lang: 
                payloads.append((name, payload,))
        return payloads

    def ListAllPayloads(self):
        """
        Prints out the name, language and rating of all loaded payloads. 
        """
        lastLang = None
        x = 1
        return [(pay.name, pay.payload, pay.language) for pay in self.payloads]
    
    def PayloadInfo(self, payload, showTitle=True, showInfo=True):
        """
        Print out information about a specified payload.
        
        payload = the payload object to print information on
        
        """
        if showTitle:
            messages.title()
        
        if showInfo:
            logging.info("\tName:\t\t" + payload.shortname)
            logging.info("\tLanguage:\t" + payload.language)
            logging.info("\tRating:\t\t" + payload.rating)
            
            if hasattr(payload, 'shellcode'):
                if self.payload.shellcode.customshellcode:
                    logging.info("\tShellcode:\t\tused")

            logging.info("\tDescription:\t" + payload.description)
        
        # if required options were specified, output them
        if hasattr(self.payload, 'required_options'):
            #print "\n Required Options:\n"
            
            #print " Name\t\t\tCurrent Value\tDescription"
            #print " ----\t\t\t-------------\t-----------"            
            
            # sort the dictionary by key before we output, so it looks nice
            for key in sorted(self.payload.required_options.iterkeys()):
                logging.info(" %s\t%s\t%s" % (
                    '{0: <16}'.format(key), '{0: <8}'.format(payload.required_options[key][0]), payload.required_options[key][1]
                ))
    
    
    def SetPayload(self, lang, name, options):
        """
        Manually set the payload for this object with specified options.
        
        lang = the language of the payload ("python"/"c"/etc.)
        name = the payload to set ("VirtualAlloc"/etc.)
        options = dictionary of required options for the payload, ex:
            options['customShellcode'] = "\x00..."
            options['required_options'] = {"compile_to_exe" : ["Y", "Compile to an executable"], ...}
            options['msfvenom'] = ["windows/meterpreter/reverse_tcp", ["LHOST=192.168.1.1","LPORT=443"]
        """
        
        # first extract out all languages  to make sure 
        # a language valid choice was passed
        langs = list(set([payload.language for (n, payload) in  self.payloads]))
        if lang not in langs:
            print helpers.color("\n[!] Specified language '" + lang + "' not valid\n", warning=True)
            self.ListLangs()
            sys.exit()

        # extract out the specific payloads for this language
        payloads = list(set([payload.shortname for (n, payload) in  self.payloads if payload.language == lang]))
        if name not in payloads:
            print helpers.color("\n[!] Specified payload '"+name+"' not valid\n", warning=True)
            self.ListPayloads(lang)
            sys.exit()

        # iterate through the set of loaded payloads, trying to match
        # the language name and payload specified
        for (n, payload) in self.payloads:
            if payload.language == lang:
                if payload.shortname == name:
                    
                    # set the internal payload variable
                    self.payload = payload
                    
                    # options['customShellcode'] = "\x00..."
                    if 'customShellcode' in options:
                        self.payload.shellcode.setCustomShellcode(options['customShellcode'])
                    # options['required_options'] = {"compile_to_exe" : ["Y", "Compile to an executable"], ...}
                    if 'required_options' in options:
                        for k,v in options['required_options'].items():
                            self.payload.required_options[k] = v
                    # options['msfvenom'] = ["windows/meterpreter/reverse_tcp", ["LHOST=192.168.1.1","LPORT=443"]
                    if 'msfvenom' in options:
                        self.payload.shellcode.SetPayload(options['msfvenom'])
    
    
    def ValidatePayload(self, payload):
        """
        Check if all required options are filled in.
        
        Returns True if valid, False otherwise.
        """
        
        # don't worry about shellcode - it validates itself
        
        
        # validate required options if present
        if hasattr(payload, 'required_options'):
            for key in sorted(self.payload.required_options.iterkeys()):
                if payload.required_options[key][0] == "":
                    return False
    
        return True
        
        
    def GeneratePayload(self):
        """
        Calls self.payload.generate() to generate payload code.
        
        Returns string of generated payload code.
        """
        return self.payload.generate()

    
    def OutputMenu(self, payload, code, showTitle=True, interactive=True, OutputBaseChoice=""):
        """
        Write a chunk of payload code to a specified ouput file base.
        
        code = the source code to write
        OutputBaseChoice = "payload" or user specified string
        
        Returns the full name the source was written to.
        """
        
        # if we get .exe code back, output to the compiled folder, otherwise write to the source folder
        if payload.extension == "exe":
            outputFolder = veil.PAYLOAD_COMPILED_PATH
        else:
            outputFolder = veil.PAYLOAD_SOURCE_PATH
        
        # only show get input if we're doing the interactive menu
        if interactive:
            if showTitle:
                messages.title()
            
            # Get the base install name for the payloads (i.e. OutputBaseChoice.py/OutputBaseChoice.exe)
            print " [*] Press [enter] for 'payload'"
            OutputBaseChoice = raw_input(" [>] Please enter the base name for output files: ")
        
        if OutputBaseChoice == "": OutputBaseChoice = "payload"
        
        # set the output name to /outout/source/BASENAME.EXT
        OutputFileName = outputFolder + OutputBaseChoice + "." + payload.extension
        
        # as long as the file exists, increment a counter to add to the filename
        # i.e. "payload3.py", to make sure we don't overwrite anything
        x = 1
        while os.path.isfile(OutputFileName):
            OutputFileName = outputFolder + OutputBaseChoice + str(x) + "." + payload.extension
            x += 1
        OutputFile = open(OutputFileName, 'w')
        OutputFile.write(code)
        OutputFile.close()
                
        # start building the information string for the generated payload
        message = "\n Language:\t\t"+helpers.color(payload.language)+"\n Payload:\t\t"+payload.shortname
        
        if hasattr(payload, 'shellcode'):
            # check if msfvenom was used or something custom, print appropriately
            if payload.shellcode.customshellcode != "":
                message += "\n Shellcode:\t\tcustom"
            else:
                message += "\n Shellcode:\t\t" + payload.shellcode.msfvenompayload
            
            # print out any msfvenom options we used in shellcode generation if specified
            if len(payload.shellcode.options) > 0:
                message += "\n Options:\t\t"
                parts = ""
                for option in payload.shellcode.options:
                    parts += ' ' + option + ' '
                message += parts.strip()

        # if required options were specified, output them
        if hasattr(payload, 'required_options'):
            message += "\n Required Options:\t"
            t = ""
            # sort the dictionary by key before we output, so it looks nice
            for key in sorted(payload.required_options.iterkeys()):
                t += " " + key + "=" + payload.required_options[key][0] + " "
            message += t.strip()

        message += "\n Source File:\t\t"+OutputFileName + "\n"
        
        # print out notes if set
        if hasattr(payload, 'notes'):
            message += " Notes:\t\t\t" + payload.notes
        
        # check if compile_to_exe is in the required options, if so,
        # call supportfiles.supportingFiles() to compile appropriately
        exe_path = ''
        if hasattr(self.payload, 'required_options'):
            if "compile_to_exe" in self.payload.required_options:
                value = self.payload.required_options['compile_to_exe'][0].lower()[0]
                if value == "y" or value==True:
                    if interactive:
                        exe_path = supportfiles.supportingFiles(self.payload.language, OutputFileName, {})
                    else:
                        exe_path = supportfiles.supportingFiles(self.payload.language, OutputFileName, {'method':'pyinstaller'})

        # print the full message containing generation notes
        print message
        messages.endmsg()
        if interactive:
            raw_input(" [>] press any key to return to the main menu: ")
            self.MainMenu(showMessage=True)
        return os.path.abspath(exe_path)
    
    
    def PayloadMenu(self, payload, showTitle=True):
        
        comp = completers.PayloadCompleter(self.payload)
        readline.set_completer_delims(' \t\n;')
        readline.parse_and_bind("tab: complete")
        readline.set_completer(comp.complete)
        
        # show the title if specified
        if showTitle:
            messages.title()
        
        print " Payload: " + helpers.color(payload.language + "/" + payload.shortname) + " loaded"
        
        self.PayloadInfo(payload, showTitle=False, showInfo=False)
        messages.helpmsg(self.payloadCommands, showTitle=False)

        choice = ""
        while choice == "":
            
            finished = False
            
            while not finished:
                
                choice = raw_input(" [>] Please enter a command: ").strip()
                
                if choice != "":
                
                    parts = choice.strip().split()
                    # display help menu for the payload
                    if parts[0] == "info":
                        self.PayloadInfo(payload)
                        choice = ""
                    if parts[0] == "help":
                        messages.helpmsg(self.payloadCommands)
                        choice = ""
                    # head back to the main menu
                    if parts[0] == "main" or parts[0] == "back":
                        finished = True
                        self.MainMenu()

                    # set specific options
                    if parts[0] == "set":
                        
                        # catch the case of no value being supplied
                        if len(parts) == 1:
                            print helpers.color(" [!] ERROR: no value supplied\n", warning=True)
                        
                        else:
                            
                            option = parts[1]
                            value = "".join(parts[2:])
                            
                            #### VALIDATION ####
                            
                            # validate LHOST
                            if option == "LHOST":
                                hostParts = value.split(".")

                                if len(hostParts) > 1:

                                    # if the last chunk is a number, assume it's an IP address
                                    if hostParts[-1].isdigit():
                                        # do a regex IP validation
                                        if not re.match(r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$",value):
                                            print helpers.color("\n [!] ERROR: Bad IP address specified.\n", warning=True)
                                        else:
                                            payload.required_options[option][0] = value

                                    # assume we've been passed a domain name
                                    else:
                                        if helpers.isValidHostname(value):
                                            pass
                                        else:
                                            print helpers.color("\n [!] ERROR: Bad hostname specified.\n", warning=True)

                                else:
                                    print helpers.color("\n [!] ERROR: Bad IP address or hostname specified.\n", warning=True)

                            # validate LPORT
                            elif option  == "LPORT":
                                try:
                                    if int(value) <= 0 or int(value) >= 65535:
                                        print helpers.color("\n [!] ERROR: Bad port number specified.\n", warning=True)
                                    else:
                                        payload.required_options[option][0] = value
                                except ValueError:
                                    print helpers.color("\n [!] ERROR: Bad port number specified.\n", warning=True)
                            
                            # set the specific option value if not validation done
                            else:
                                try:
                                    payload.required_options[option][0] = value
                                except:
                                    print helpers.color(" [!] ERROR: Invalid value specified.\n", warning=True)
                                    cmd = ""
                            
                    # generate the payload
                    if parts[0] == "generate":
                        
                        # make sure all required options are filled in first
                        if self.ValidatePayload(payload):
                            
                            finished = True
                            # actually generate the payload code
                            payloadCode = payload.generate()
                            
                            # ensure we got some code back
                            if payloadCode != "":
                                # call the output menu
                                self.OutputMenu(payload, payloadCode)
                            
                        else:
                            print helpers.color("\n [!] WARNING: not all required options filled\n", warning=True)
    
    
    def MainMenu(self, showMessage=True):
        """
        Main interactive menu for payload generation.
        
        showMessage = reset the screen and show the greeting message, default=True
        
        """
        try:
            
            comp = completers.MainMenuCompleter(self.commands, self.payloads)
            # we want to treat '/' as part of a word, so override the delimiters
            readline.set_completer_delims(' \t\n;')
            readline.parse_and_bind("tab: complete")
            readline.set_completer(comp.complete)
            cmd = ""
            
            while cmd == "":
                
                if showMessage:
                    # print the title, where we are, and number of payloads loaded
                    messages.title()
                    print " Main Menu\n"
                    print "\t" + helpers.color(str(len(self.payloads))) + " payloads loaded\n"
                
                if self.firstRun:
                    messages.helpmsg(self.commands, showTitle=False)
                    #self.firstRun = False
                
                cmd = raw_input(' [>] Please enter a command: ').strip()
                
                # handle our tab completed commands                
                if cmd.startswith("help"):
                    #messages.helpmsg(self.commands)
                    messages.title()
                    self.commands
                    cmd = ""
                    showMessage=False
                
                elif cmd.startswith("use"):
                    
                    if len(cmd.split()) == 1:
                        messages.title()
                        self.ListAllPayloads()
                        showMessage=False
                        cmd = ""

                    elif len(cmd.split()) == 2:
                        
                        # pull out the payload/number to use
                        p = cmd.split()[1]

                        # if we're choosing the payload by numbers
                        if p.isdigit() and 0 < int(p) <= len(self.payloads):
                            x = 1
                            for (name, pay) in self.payloads:
                                # if the entered number matches the payload #, use that payload
                                if int(p) == x: 
                                    self.payload = pay
                                    self.PayloadMenu(self.payload)
                                x += 1
                                
                        # else choosing the payload by name
                        elif len(p.split("/")) == 2:    
                            lang,payloadName = p.split("/")
                            
                            for (name, pay) in self.payloads:
                                
                                # if we find the payload specified, kick off the payload menu
                                if pay.language == lang:
                                    if pay.shortname == payloadName:
                                        self.payload = pay
                                        self.PayloadMenu(self.payload)
                            
                        cmd = ""
                        showMessage=True
                        
                    # error catchings if not of form [use BLAH]
                    else:
                        cmd = ""
                        showMessage=False
                
                elif cmd.startswith("info"):
                    
                    if len(cmd.split()) == 1:
                        showMessage=True
                        cmd = ""

                    elif len(cmd.split()) == 2:
                        
                        # pull out the payload/number to use
                        p = cmd.split()[1]

                        # if we're choosing the payload by numbers
                        if p.isdigit() and 0 < int(p) <= len(self.payloads):
                            x = 1
                            for (name, pay) in self.payloads:
                                # if the entered number matches the payload #, use that payload
                                if int(p) == x: 
                                    self.payload = pay
                                    self.PayloadInfo(self.payload)
                                x += 1
                                
                        # else choosing the payload by name
                        elif len(p.split("/")) == 2:    
                            lang,payloadName = p.split("/")
                            
                            for (name, pay) in self.payloads:
                                
                                # if we find the payload specified, kick off the payload menu
                                if pay.language == lang:
                                    if pay.shortname == payloadName:
                                        self.payload = pay
                                        self.PayloadInfo(self.payload)
                            
                        cmd = ""
                        showMessage=False
                        
                    # error catchings if not of form [use BLAH]
                    else:
                        cmd = ""
                        showMessage=False
                
                elif cmd.startswith("list"):
                    
                    if len(cmd.split()) == 1:
                        messages.title()
                        self.ListAllPayloads()
                        
                    if len(cmd.split()) == 2:
                        parts = cmd.split()
                        if parts[1] == "all" or parts[1] == "payloads":
                            messages.title()
                            self.ListAllPayloads()
                        elif parts[1] == "langs":
                            messages.title()
                            self.ListLangs()
                        else:
                            messages.title()
                            self.ListPayloads(parts[1])
                            
                    cmd = ""
                    showMessage=False
                
                elif cmd.startswith("exit") or cmd.startswith("q"):
                    print helpers.color("\n [!] Exiting...\n", warning=True)
                    sys.exit()
                
                # select a payload by just the number
                elif cmd.isdigit() and 0 < int(cmd) <= len(self.payloads):
                    x = 1
                    for (name, pay) in self.payloads:
                        # if the entered number matches the payload #, use that payload
                        if int(cmd) == x: 
                            self.payload = pay
                            self.PayloadMenu(self.payload)
                        x += 1
                    cmd = ""
                    showMessage=False
                
                # if nothing is entered
                else:
                    showMessage=True
            
        # catch any ctrl + c interrupts
        except KeyboardInterrupt:
            print helpers.color("\n\n [!] Exiting...\n", warning=True)
            sys.exit()
