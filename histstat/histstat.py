#!/usr/bin/env python

"""
histstat, history for netstat
https://github.com/vesche/histstat
"""
import os
import sys
import time
import psutil
import argparse
import datetime
import socket
import fnmatch
import IP2Location
import pycountry
import pycountry_convert

from termcolor import colored
from socket import AF_INET, AF_INET6, SOCK_DGRAM, SOCK_STREAM

__version__ = '1.1.4'

PROTOCOLS = {
    (AF_INET,  SOCK_STREAM): 'tcp',
    (AF_INET6, SOCK_STREAM): 'tcp6',
    (AF_INET,  SOCK_DGRAM):  'udp',
    (AF_INET6, SOCK_DGRAM):  'udp6'
}
FIELDS = [
    'date', 'time', 'proto', 'laddr', 'lport', 'raddr', 'rport', 'country', 'cn', 'status',
    'user', 'pid', 'pname', 'command'
]
P_FIELDS = '{:<8} {:<8} {:<5} {:<15.15} {:<5} {:<15.15} {:<5} {:<15.15} {:<2} {:<11.11} ' \
           '{:<10.10} {:<7.7} {:<20.20} {}'

CONTINENTS_SHORT =  ["AF"     , "AN"         , "AS"   , "EU"     , "NA"            , "OC"      , "SA"]
CONTINENTS_LONG =   ["Africa" , "Antarctica" , "Asia" , "Europe" , "North America" , "Oceania" , "South America"]

if sys.platform.startswith('linux') or sys.platform == 'darwin':
    PLATFORM = 'nix'
    from os import geteuid
elif sys.platform.startswith('win'):
    PLATFORM = 'win'
    from ctypes import *
else:
    print('Error: Platform unsupported.')
    sys.exit(1)

def _filter_conn(c):
    if len(output.filter_ip) == 0: return False
    (ip_local,_) = c.laddr
    (ip_remote,_) = c.raddr if c.raddr else (None, None)
    if ip_local in output.filter_ip or (c.raddr and ip_remote in output.filter_ip): return False
    return True


def histmain(interval):
    """Primary execution function for histstat."""

    # ladies and gentlemen this is your captain speaking
    output.preflight()

    # get initial connections
    connections_A = psutil.net_connections()
    for c in connections_A:
        if _filter_conn(c): continue
        output.process(process_conn(c))

    # primary loop
    while True:
        time.sleep(interval)
        connections_B = psutil.net_connections()
        new_conn=False
        for c in connections_B:
            if _filter_conn(c): continue
            if c not in connections_A:
                output.process(process_conn(c))
                new_conn=True

        output.interval_done(new_conn)

        connections_A = connections_B

_ip2l_cache={}

def process_conn(c):
    """Process a psutil._common.sconn object into a list of raw data."""

    date, time = str(datetime.datetime.now()).split()
    proto = PROTOCOLS[(c.family, c.type)]
    raddr = rport = '*'
    status = pid = pname = user = command = '-'
    laddr, lport = c.laddr

    ctry = "-"
    cont = "-"
    if c.raddr:
        raddr, rport = c.raddr
        if raddr in _ip2l_cache:
            ip2l_rec = _ip2l_cache[raddr]
        else:
            ip2l_rec = IP2LocObj.get_all(raddr)
            _ip2l_cache[raddr] = ip2l_rec
        ctry = ip2l_rec.country_short
        try:
            cont = pycountry_convert.country_alpha2_to_continent_code(ctry)
        except KeyError as e:
            pass

    if c.pid:
        try:
            pname, pid = psutil.Process(c.pid).name(), str(c.pid)
            user = psutil.Process(c.pid).username()
            command = ' '.join(psutil.Process(c.pid).cmdline())
        except:
            pass # if process closes during processing
    if c.status != 'NONE':
        status = c.status

    if not output.cmdmax is None and len(command) > (output.cmdmax+3): command = command[:output.cmdmax] + '...'

    return [
        date[2:], time[:8], proto, laddr, lport, raddr, rport, ctry, cont, status,
        user, pid, pname, command
    ]


def get_ip_addresses(family, interfaces:list):
    for interface, snics in psutil.net_if_addrs().items():
        if not interface in interfaces: continue
        for snic in snics:
            if snic.family == family:
                # if family == socket.AF_INET6 and snic.address.find('%') > -1:
                #     yield snic.address[:snic.address.find('%')]
                # else:
                yield snic.address

class Output:
    """Handles all output for histstat."""

    def __init__(self, log, json_out, prettify, flush, quiet, interfaces, cmdmax, rcountry, rcontinent, wcountry):
        self.log = log
        self.json_out = json_out
        self.prettify = prettify
        self.flush = flush
        self.quiet = quiet
        


        if quiet and not log:
            print('Error: Quiet and Log must be used together.')
            sys.exit(2)

        if self.prettify and self.json_out:
            print('Error: Prettify and JSON output cannot be used together.')
            sys.exit(2)

        if self.log:
            self.file_handle = open(self.log, 'a')
            if quiet:
                print("Quiet mode enabled. See output in log file "+self.log)

        try:
            self.cmdmax = int(cmdmax)
            if self.cmdmax < 10: 
                print('Please specify cmdmax of >= 10.')
                sys.exit(2)
        except:
            self.cmdmax = None

        # Process interfaces setting
        interfaces = "" if interfaces is None else interfaces.strip()
        self.filter_ip=[]
        if not interfaces == '':
            interfaces=list(map(lambda s: s.strip(), interfaces.split(',')))
            all_interfaces = psutil.net_if_addrs()
            itmp=[]
            for iface in interfaces:
                if iface.find('*') > -1: #Wildcard match
                    for iface_match in fnmatch.filter(all_interfaces, iface):
                        if not iface_match in itmp: itmp.append(iface_match)

                elif not iface in all_interfaces:
                    print('Invalid adapter passed: {}.'.format(iface))
                    sys.exit(2)

                else:
                    itmp.append(iface)

            interfaces = itmp
            filter_ipv6 = list(get_ip_addresses(socket.AF_INET6, interfaces))
            filter_ipv4 = list(get_ip_addresses(socket.AF_INET, interfaces))
            

            self.filter_ip = filter_ipv4 + filter_ipv6

        else:
            self.adapter = []

        self.rcountry = None
        self.rcontinent = None
        self.wcountry = None
        for k, v in [('rcountry', rcountry), ('rcontinent', rcontinent), ('wcountry', wcountry)]:
            
            if v is None:
                arr = None
            else:
                arr = list(map(lambda s: str(s).strip().upper(), v.split(',')))
                for v2 in arr:
                    if k == 'rcountry' or k == 'wcountry':
                        if pycountry.countries.get(alpha_2=v2) is None:
                            print('Invalid country code passed in --{}: {}.'.format(k, v2))
                            sys.exit(2)
                    else:
                        if v2 in CONTINENTS_SHORT:
                            v2 = CONTINENTS_LONG[CONTINENTS_SHORT.index(v2)]
                        elif not v2 in CONTINENTS_LONG:
                            print('Invalid Continent code passed in --rcontinent paramertr: {}.'.format(v2))
                            sys.exit(2)

                if k == 'rcountry':
                    self.rcountry = arr
                elif k == 'wcountry':
                    self.wcountry = arr
                else:
                    self.rcontinent = arr
        
        

    def preflight(self):
        header = ''
        root_check = False

        if PLATFORM == 'nix':
            euid = geteuid()
            if euid == 0:
                root_check = True
            elif sys.platform == 'darwin':
                print('Error: histstat must be run as root on macOS.')
                sys.exit(3)
        elif PLATFORM == 'win':
            if windll.shell32.IsUserAnAdmin() == 0:
                root_check = True

        if not root_check:
            header += '(Not all process information could be determined, run' \
                      ' at a higher privilege level to see everything.)\n'
        if header:
            print(header)
        if not self.json_out:
            self.process(FIELDS, is_header=True)


    def process(self, cfields, is_header=False):
        ctry = cfields[7]
        cont = cfields[8]
        if not is_header and not ctry == '-':
            c = pycountry.countries.get(alpha_2=ctry)
            cfields[7] = c.name
        bRed = False
        if self.rcontinent and cont in self.rcontinent:
            bRed = (not self.wcountry or not ctry in self.wcountry)
        else:
            bRed = (self.rcountry and ctry in self.rcountry)

        if self.prettify:
            line = P_FIELDS.format(*cfields)
        elif self.json_out:
            line = dict(zip(FIELDS, cfields))
        else:
            line = '\t'.join(map(str, cfields))

        # stdout
        if not self.quiet:
            if bRed:
                print(colored(line, 'red'))
            else:
                print(line)
        if self.log:
            self.file_handle.write(str(line) + '\n')
            

    def interval_done(self, new_conn):
        if new_conn and self.log and self.flush:
            self.file_handle.flush()


def get_parser():
    parser = argparse.ArgumentParser(description='history for netstat')
    parser.add_argument(
        '-i', '--interval', help='specify update interval in seconds',
        default=1, type=float
    )
    parser.add_argument(
        '-l', '--log', help='log output to a text file',
        default=None, type=str
    )
    parser.add_argument(
        '-p', '--prettify', help='prettify output',
        default=False, action='store_true'
    )
    parser.add_argument(
        '-j', '--json', help='json output',
        default=False, action='store_true'
    )
    parser.add_argument(
        '-F', '--flush', help='flush output of log file after each interval',
        default=False, action='store_true'
    )
    parser.add_argument(
        '-q', '--quiet', help='do not output to stdout. Only valid if --log is set',
        default=False, action='store_true'
    )
    parser.add_argument(
        '-v', '--version', help='display the current version',
        default=False, action='store_true'
    )

    parser.add_argument(
        '-I', '--interfaces', help='filter output to IPs of Interfaces',
        default=None, type=str
    )

    parser.add_argument(
        '-m', '--cmdmax', help='Maximum command length',
        default=None, type=str
    )

    parser.add_argument(
        '-r', '--rcountry', help='String containing comma separated list of country codes to flag as red. See https://en.wikipedia.org/wiki/ISO_3166-1',
        default=None, type=str
    )

    parser.add_argument(
        '-w', '--wcountry', help='String containing comma separated list of country codes that are whitelisted. Only applicable if --rcontinent is used. See https://en.wikipedia.org/wiki/ISO_3166-1',
        default=None, type=str
    )

    parser.add_argument(
        '-c', '--rcontinent', help='String containing comma separated list of continent codes to flag as red',
        default=None, type=str
    )

    return parser

IP2LocObj = IP2Location.IP2Location()


def main():

    IP2LocObj.open("IP2L.BIN")

    parser = get_parser()
    args = vars(parser.parse_args())

    if args['version']:
        print(__version__)
        return

    interval = args['interval']
    

    global output
    output = Output(
        log=args['log'],
        json_out=args['json'],
        prettify=args['prettify'],
        flush=args['flush'],
        quiet=args['quiet'],
        interfaces=args['interfaces'],
        cmdmax=args['cmdmax'],
        rcountry=args['rcountry'],
        rcontinent=args['rcontinent'],
        wcountry=args['wcountry'],
    )

    try:
        histmain(interval)
    except KeyboardInterrupt:
        pass

    # gracefully stop histstat
    if output.log:
        output.file_handle.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
