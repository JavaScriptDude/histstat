#!/usr/bin/env python

# TODO:
# [.] Add IPv6 Inet support (c.family == socket.AF_INET6)
# [.] Add parameter to control Single Instance check - Is defaulted on for now. Can be commented out if needed for now.

"""
% histstat -i 1 --ip2ldb V:\20201202_AcclogParser\app\iis_acclog_parser\IP2L.BIN --sqlite V:\20201202_AcclogParser\app\iis_acclog_parser\histstat.db
% histstat -i 1 --ip2ldb .\IP2L.BIN --sqlite .\histstat.db --fladdr 192.168.50.21*:80,192.168.50.21*:443

"""
import os, sys, time, psutil, argparse, datetime, socket, fnmatch, IP2Location, pycountry, pycountry_convert, sqlite3
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
    'date', 'time', 'proto', 'laddr', 'lport', 'raddr', 'rport', 'status',
    'user', 'pid', 'pname', 'command'
]
FIELDS_IP2L = [
    'date', 'time', 'proto', 'laddr', 'lport', 'raddr', 'rport', 'country', 'cn', 'status',
    'user', 'pid', 'pname', 'command'
]
P_FIELDS = '{:<8} {:<8} {:<5} {:<15.15} {:<5} {:<15.15} {:<5} {:<11.11} ' \
           '{:<10.10} {:<7.7} {:<20.20} {}'
P_FIELDS_IP2L = '{:<8} {:<8} {:<5} {:<15.15} {:<5} {:<15.15} {:<5} {:<15.15} {:<2} {:<11.11} ' \
           '{:<10.10} {:<7.7} {:<20.20} {}'

SQL_COLUMNS=[
    # (i,  name, dtype, allow_null, default, pkey)
     (0,  'PKey'        , 'INTEGER' , 0, None, 1)
    ,(1,  'Date'        , 'TEXT'    , 0, None, 0)
    ,(2,  'Protocol'    , 'TEXT'    , 0, None, 0)
    ,(3,  'LAddr'       , 'TEXT'    , 0, None, 0)
    ,(4,  'LPort'       , 'INTEGER' , 0, None, 0)
    ,(5,  'RAddr'       , 'TEXT'    , 0, None, 0)
    ,(6,  'RPort'       , 'INTEGER' , 0, None, 0)
    ,(7,  'Country'     , 'TEXT'    , 0, None, 0)
    ,(8,  'Continent'   , 'TEXT'    , 0, None, 0)
    ,(9,  'Status'      , 'TEXT'    , 0, None, 0)
    ,(10, 'User'        , 'TEXT'    , 0, None, 0)
    ,(11, 'Pid'         , 'INTEGER' , 0, None, 0)
    ,(12, 'ProcName'    , 'TEXT'    , 0, None, 0)
    ,(13, 'ProcCmd'     , 'TEXT'    , 0, None, 0)
    ,(14, 'Parents'     , 'TEXT'    , 0, None, 0)
]

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
    (ip_local,port_local) = c.laddr
    (ip_remote,port_remote) = c.raddr if c.raddr else (None, None)
    # Local IP filtering (see --interfaces)
    if len(output.filter_ip) > 0:
        if not ip_local in output.filter_ip \
            and not (c.raddr and ip_remote in output.filter_ip): 
            return True
    

    # local Address filter (--fladdr)
    if output.fladdr:
        def __match(addr, fil):
            addr = str(addr)
            if fil is None:
                return True
            else:
                if fil.find('*') > -1: #Wildcard match
                    if fnmatch.fnmatch(addr, fil):
                        return True
                else:
                    if addr == fil:
                        return True
            return False

        bFound = False
        for (f_ip, f_port) in output.fladdr:
            if __match(ip_local, f_ip) and __match(port_local, f_port):
                bFound = True
                break

        if not bFound: return True
        


    # status filtering
    v = c.status
    if output.sfilter and isinstance(v, str):
        bFound=False
        for fil in output.sfilter:
            if fil.find('*') > -1: #Wildcard match
                if fnmatch.fnmatch(v, fil):
                    bFound=True
                    break
            else:
                bFound = (v == fil)

        if not bFound: return True

    return False




def histmain(interval):
    """Primary execution function for histstat."""

    # ladies and gentlemen this is your captain speaking
    output.preflight()

    # get initial connections
    connections_A = psutil.net_connections()
    for c in connections_A:
        if output.ip2l and _filter_conn(c): continue
        output.process(process_conn(c))

    # primary loop
    while True:
        time.sleep(interval)
        connections_B = psutil.net_connections()
        new_conn=False
        for c in connections_B:
            if output.ip2l and _filter_conn(c): continue
            if c not in connections_A:
                output.process(process_conn(c))
                new_conn=True

        output.interval_done(new_conn)

        connections_A = connections_B

        if not output.quite_time is None and datetime.datetime.now() > output.quite_time:
            print("Exiting program as per quite time of {} minutes".format(output.quit))
            sys.exit(0)

_ip2l_cache={}

def process_conn(c):
    """Process a psutil._common.sconn object into a list of raw data."""

    date, time = str(datetime.datetime.now()).split()
    proto = PROTOCOLS[(c.family, c.type)]
    raddr = rport = '*'
    status = pid = pname = user = command = parents = '-'
    laddr, lport = c.laddr

    _ctry = "-"
    _cont = "-"
    if c.raddr:
        raddr, rport = c.raddr
        if output.ip2l:
            if raddr in _ip2l_cache:
                ip2l_rec = _ip2l_cache[raddr]
            else:
                if c.family == socket.AF_INET:
                    ip2l_rec = IP2LocObj.get_all(raddr)
                    _ip2l_cache[raddr] = ip2l_rec
                    _ctry = ip2l_rec.country_short
                    try:
                        _cont = pycountry_convert.country_alpha2_to_continent_code(_ctry)
                    except KeyError as e:
                        pass

                else:
                    _cont = _ctry = '(na/ipv6)'

    if c.pid:
        try:
            p = psutil.Process(c.pid)
            pname, pid = p.name(), str(c.pid)
            user = p.username()
            command = ' '.join(p.cmdline())
            
            parents = ' -> '.join(['({}) {}'.format(par.pid, ' '.join(par.cmdline())) for par in p.parents() if True])



        except:
            pass # if process closes during processing
    if c.status != 'NONE':
        status = c.status

    if not output.json_out \
        and not output.cmdmax is None \
        and len(command) > (output.cmdmax+3): 
        command = command[:output.cmdmax] + '...'

    if output.ip2l:
        a = [
            date[2:], time[:8], proto, laddr, lport, raddr, rport, _ctry, _cont, status,
            user, pid, pname, command
        ]
    else:
        a = [
            date[2:], time[:8], proto, laddr, lport, raddr, rport, status,
            user, pid, pname, command
        ]

    if output.sqlite: a.append(parents)

    return a


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

    def __init__(self, log, json_out, prettify, flush, quiet, interfaces, cmdmax, rcountry, rcontinent, wcountry, ip2l, sfilter, sqlite, fladdr, quit):
        self.log = log
        self.json_out = json_out
        self.prettify = prettify
        self.flush = flush
        self.quiet = quiet
        self.ip2l = ip2l
        self.pcount = 0
        self.quit = quit
        
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
            if self.json_out:
                print('Using JSON out. Ignoring cmdmax option.')
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

        # Process Country flagging
        self.rcountry = None
        self.rcontinent = None
        self.wcountry = None
        if not self.ip2l:
            if not rcountry is None or not rcontinent is None or not wcountry is None:
                print('Parameters --rcountry, --rcontinent and --wcountry are not applicable unless --ip2ldb is passed.')
                sys.exit(2)
        else:
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
                                print('Invalid Continent code passed in --rcontinent parameter: {}.'.format(v2))
                                sys.exit(2)

                    if k == 'rcountry':
                        self.rcountry = arr
                    elif k == 'wcountry':
                        self.wcountry = arr
                    else:
                        self.rcontinent = arr

            if self.json_out:
                FIELDS_IP2L[8] = 'continent'
        
        # Local Addr Filter
        if not fladdr:
            self.fladdr = False
        else:
            def _p_fladdr(pattern):
                a = list(map(lambda s: str(s).strip(), pattern.split(':')))
                iL = len(a)
                if iL == 1:
                    return (a[0], None)
                elif iL == 2:
                    v = a[0]; ip = None if v == '' or v == '*' else v
                    v = a[1]; po = None if v == '' or v == '*' else v
                    return (ip, po)
                else:
                    print('Invalid address passed in --fladdr parameter: {}.'.format(pattern))
                    sys.exit(2)

            self.fladdr = list(filter(lambda t: not t == (None, None), map(_p_fladdr, fladdr.split(','))))
            if len(self.fladdr) == 0: self.fladdr = False

            


        # Process status filter
        if not sfilter:
            self.sfilter = False
        else:
            self.sfilter = list(map(lambda s: str(s).strip().upper(), sfilter.split(',')))

        if sqlite:
            self.sqlite = True
            self.sqlite_path = sqlite
            self.sqlite_conn = sqlite3.connect(sqlite)
            col_names=list(map(lambda col: col[1], SQL_COLUMNS[1:]))
            self.sqlite_insert_stmt="INSERT INTO HistStat ({}) VALUES({})".format( (', '.join(col_names)), (('?,'*len(col_names))[:-1]) )
            FIELDS_IP2L.append('parents')
            FIELDS.append('parents')
        else:
            self.sqlite = False


        if self.quit:
            self.quite_time = datetime.datetime.now() + datetime.timedelta(minutes=self.quit)
        else:
            self.quite_time = None
            

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

        if self.sqlite:
            header += '(Output is being written to Sqllite 3 db: {})\n'.format(self.sqlite_path)


        if header:
            print(header)
        if not self.json_out:
            self.process(FIELDS_IP2L if self.ip2l else FIELDS, is_header=True)


    def process(self, cfields, is_header=False):

        if self.sqlite:
            if is_header: return
            self.pcount = self.pcount + 1
            cfields[0] = '20' + cfields[0]
            cfields[1] = cfields[1] + ".0"
            row = cfields[2:6] + ['-', '-'] + cfields[6:] if not self.ip2l else cfields[2:]
            # collate date and time fields to one large string that is parsable and can be used for some comparisons
            row = [cfields[0].replace('-', '')+cfields[1].replace(':','').replace('.0', '000000')] + row
            cur = self.sqlite_conn.cursor()
            cur.execute(self.sqlite_insert_stmt, row)
            return

        self.pcount = self.pcount + 1
        bRed = False
        if self.ip2l:
            _ctry = cfields[7]
            _cont = cfields[8]
            if not self.json_out:
                if not is_header and not _ctry == '-':
                    c = pycountry.countries.get(alpha_2=_ctry)
                    # print("_ctry: {}, c: {}".format(_ctry, c))
                    cfields[7] = '-' if c is None else c.name
                bRed = False
                if self.rcontinent and _cont in self.rcontinent:
                    bRed = (not self.wcountry or not _ctry in self.wcountry)
                else:
                    bRed = (self.rcountry and _ctry in self.rcountry)

        if self.ip2l:
            fields = FIELDS_IP2L
            p_fields = P_FIELDS_IP2L
        else:
            fields = FIELDS
            p_fields = P_FIELDS

        if self.prettify:
            line = p_fields.format(*cfields)
        elif self.json_out:
            line = dict(zip(fields, cfields))
        else:
            line = '\t'.join(map(str, cfields))

        # stdout
        if not self.quiet:
            if self.ip2l and bRed:
                print(colored(line, 'red'))
            else:
                print(line)
        if self.log:
            self.file_handle.write(str(line) + '\n')
            

    def interval_done(self, new_conn):
        if new_conn and self.log and self.flush:
            self.file_handle.flush()
        if self.sqlite:
            self.sqlite_conn.commit()
            # print("committed {} rows".format(self.pcount))
        self.pcount=0


def isSqlite3Db(db):
    if not os.path.isfile(db): return False
    sz = os.path.getsize(db)

    # file is empty, give benefit of the doubt that its sqlite
    # New sqlite3 files created in recent libraries are empty!
    if sz == 0: return True

    # SQLite database file header is 100 bytes
    if sz < 100: return False

    # Validate file header
    with open(db, 'rb') as fd: header = fd.read(100)    

    return (header[:16] == b'SQLite format 3\x00')


def validateDbSchema(sqlitepath):
    # Validate Schema
    conn = sqlite3.connect(sqlitepath)

    sBadSchemaErr=None

    cur = conn.cursor().execute("SELECT name FROM sqlite_master WHERE type='table' AND name='HistStat'")
    if len(cur.fetchall()) == 0:
        sb = []
        sb.append("CREATE TABLE HistStat (")
        for col in SQL_COLUMNS:
            (i, name, dtype, allow_null, default, pkey) = col
            sb.append("\n   {0} {1}{2}{3}".format(name, dtype, (' PRIMARY KEY AUTOINCREMENT' if pkey else ''), ('' if i == len(SQL_COLUMNS)-1 else ',') ))
        sb.append("\n)")

        sql = ''.join(sb)
        cur = conn.cursor()
        cur.execute(sql)
        conn.commit()

        # Create Index
        cur = conn.cursor()
        cur.execute("CREATE INDEX idx_date_status on HistStat (Date, Status)")
        conn.commit()


    else:  #validate schema
        rows = conn.cursor().execute("PRAGMA table_info('HistStat')").fetchall()
        if not len(rows) == len(SQL_COLUMNS):
            sBadSchemaErr = "Number of columns is incorrect."
        else:
            for i, row in enumerate(rows):
                if not SQL_COLUMNS[i] == row:
                    sBadSchemaErr = "Column with issue is: {}".format(row)
                    break

        if sBadSchemaErr:
            print("HistStat table in db {} does not match required schema. {}. Please rename HistStat table so it can be re-created.".format(sqlitepath, sBadSchemaErr))
            sys.exit(2)

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
        '-r', '--rcountry', help='Comma separated list of country codes to flag as red. See https://en.wikipedia.org/wiki/ISO_3166-1',
        default=None, type=str
    )

    parser.add_argument(
        '-w', '--wcountry', help='Comma separated list of country codes that are whitelisted. Only applicable if --rcontinent is used. See https://en.wikipedia.org/wiki/ISO_3166-1',
        default=None, type=str
    )

    parser.add_argument(
        '-c', '--rcontinent', help='Comma separated list of continent codes to flag as red',
        default=None, type=str
    )

    parser.add_argument(
        '-g', '--ip2ldb', help='Path to IP2Location DB file',
        default=None, type=str
    )

    parser.add_argument(
        '-s', '--sfilter', help='Filter output by Status Code',
        default=None, type=str
    )
    parser.add_argument(
        '-A', '--fladdr', help='Filter by local Address. <ip> -or- <ip>:<port> -or- :<port> with wildcards in any value. Comma Separated for multiple.',
        default=None, type=str
    )

    parser.add_argument(
        '-S', '--sqlite', help='Store output in SQLite DB',
        default=None, type=str
    )

    parser.add_argument(
        '-Q', '--quit', help='Quit after n minutes',
        default=None, type=float
    )


    return parser

IP2LocObj = IP2Location.IP2Location()


def main():

    parser = get_parser()
    args = vars(parser.parse_args())

    if args['version']:
        print(__version__)
        return

    k='ip2ldb'; v=args[k]
    if v:
        if not os.path.isfile(v):
            print('Error: IP2Location file {} from --{} param not found.'.format(v, k))
            sys.exit(2)
        IP2LocObj.open(v)
        ip2l = True
    else:
        ip2l = False

    k='sqlite'; v=args[k]
    if v:
        if os.path.isfile(v):
            v = args[k] = os.path.abspath(v)
            if not isSqlite3Db(v):
                print('Error: --sqlite parameter does not point to a valid sqlite db: ({})'.format(v))
                sys.exit(2)

        else:
            _file = os.path.basename(v)
            _path = v[:-(len(_file))-1]
            if _path == '' or _path == './':
                v = args[k] = os.getcwd()+'/'+_file

            elif os.path.isdir(_path):
                v = args[k] = os.path.abspath(_path)+'/'+_file
                
            else:
                print('Error: sqlite db ({}) not found and directory does not exist. Cannot create a new db.'.format(v, k))
                sys.exit(2)

            # create DB
            sqlite3.connect(v).close()

            

        validateDbSchema(v)
        


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
        ip2l=ip2l,
        sfilter=args['sfilter'],
        sqlite=args['sqlite'],
        fladdr=args['fladdr'],
        quit=args['quit'],
    )

    try:
        histmain(args['interval'])
    except KeyboardInterrupt:
        pass

    # gracefully stop histstat
    if output.log:
        output.file_handle.close()
    return 0




class SingleInstanceChecker:
    def __init__(self, id):
        if isWin():
            ensure_win32api()
            self.mutexname = id
            self.lock = win32event.CreateMutex(None, False, self.mutexname)
            self.running = (win32api.GetLastError() == winerror.ERROR_ALREADY_EXISTS)

        else:
            ensure_fcntl()
            self.lock = open(f"/tmp/isnstance_{id}.lock", 'wb')
            try:
                fcntl.lockf(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.running = False
            except IOError:
                self.running = True


    def already_running(self):
        return self.running
        
    def __del__(self):
        if self.lock:
            try:
                if isWin():
                    win32api.CloseHandle(self.lock)
                else:
                    os.close(self.lock)
            except Exception as ex:
                pass

# ---------------------------------------
# Utility Functions
# Dynamically load win32api on demand
# Install with: pip install pywin32
win32api=winerror=win32event=None
def ensure_win32api():
    global win32api,winerror,win32event
    if win32api is None:
        import win32api
        import winerror
        import win32event


# Dynamically load fcntl on demand
# Install with: pip install fcntl
fcntl=None
def ensure_fcntl():
    global fcntl
    if fcntl is None:
        import fcntl


def isWin():
    return (os.name == 'nt')
# ---------------------------------------


if __name__ == '__main__':
    SCR_NAME = "histstat.py"
    sic = SingleInstanceChecker(SCR_NAME)
    if sic.already_running():
        print("An instance of {} is already running.".format(SCR_NAME))
        sys.exit(1)
    else:
         sys.exit(main())
