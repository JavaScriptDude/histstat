# histstat


### NOTE - This is a fork of vesche/histstat and you cannot use pip to install this version. It must be installed using python.

### Special notes on this fork
This version has implemented the following features:
* Utilize  IP2Location to add geolocation information to output
* Add country / continent redlist/whitelist for marking output as red in console as specified
** Applicable params: --rcountry, --rcontinent, --wcountry
** All are comma separated country abbreviations. Continents can be full names.
* Specify interfaces which output will be shown for and filter out output for all other interfaces.
** supports wildcards eg: --interfaces wls*,tun*
* Flush feature so output us flushed on completion of each process
** see --flush param
* Quite feature when outputing to file so stdout is only operational information
** see --quiet param
* Limit command column length in output
** see --cmdmax param

To use this version, you must get a copy of the IP2Location bin file named as 'IP2L.BIN' and locate it in the same folder as the histstat.py script.


This is a cross-platform command-line tool for obtaining live, rudimentary network connection data on a computer system. This tool was designed for network and security analysts to easily view connections on a system **as they occur**. It will display useful information about network connections that utilities like netstat typically won't give you such as what time the connection was made, the exact command that created the connection, and the user that connection was made by.

**Note for Windows users:** Detailed process information will not display unless you're running as `NT AUTHORITY\SYSTEM`. An easy way to drop into a system-level command prompt is to use PsExec from [SysInternals](https://technet.microsoft.com/en-us/sysinternals/bb842062.aspx). Run `psexec -i -s cmd.exe` as Administrator and then run histstat.

### Install
```
python install setup.py
```

### Example Usage

```
$ histstat --help
usage: histstat.py [-h] [-i INTERVAL] [-l LOG] [-p] [-j] [-F] [-q] [-v]
                   [-I INTERFACES] [-m CMDMAX] [-r RCOUNTRY] [-w WCOUNTRY]
                   [-c RCONTINENT]

history for netstat

optional arguments:
  -h, --help            show this help message and exit
  -i INTERVAL, --interval INTERVAL
                        specify update interval in seconds
  -l LOG, --log LOG     log output to a text file
  -p, --prettify        prettify output
  -j, --json            json output
  -F, --flush           flush output of log file after each interval
  -q, --quiet           do not output to stdout. Only valid if --log is set
  -v, --version         display the current version
  -I INTERFACES, --interfaces INTERFACES
                        filter output to IPs of Interfaces
  -m CMDMAX, --cmdmax CMDMAX
                        Maximum command length
  -r RCOUNTRY, --rcountry RCOUNTRY
                        String containing comma separated list of country
                        codes to flag as red. See
                        https://en.wikipedia.org/wiki/ISO_3166-1
  -w WCOUNTRY, --wcountry WCOUNTRY
                        String containing comma separated list of country
                        codes that are whitelisted. Only applicable if
                        --rcontinent is used. See
                        https://en.wikipedia.org/wiki/ISO_3166-1
  -c RCONTINENT, --rcontinent RCONTINENT
                        String containing comma separated list of continent
                        codes to flag as red
```

### Output example
(pardon the prefix which was added to simulate the red text)

```
$ sudo histstat -p --rcontinent AS,OC,SA,AF --wcountry AU,AZ --rcountry PL,HU,TR --cmdmax 20 --interfaces tun*,wls*
```

```diff
# date     time     proto laddr           lport raddr           rport country         cn status      user       pid     pname                command
# 20-12-05 14:35:47 tcp   192.168.101.118 47396 167.172.147.116 443   United States   NA ESTABLISHED tquinn     1583741 firefox              /usr/lib/firefox/fir...
# 20-12-05 14:35:47 tcp   192.168.101.118 47027 72.251.238.254  443   United States   NA ESTABLISHED -          -       -                    -
# 20-12-05 14:35:47 tcp   192.168.101.118 60249 72.251.238.254  443   United States   NA ESTABLISHED -          -       -                    -
# 20-12-05 14:35:47 tcp   192.168.101.118 52222 104.42.78.153   443   United States   NA ESTABLISHED tquinn     2403251 code                 /usr/share/code/code...
# 20-12-05 14:35:47 tcp   192.168.101.118 51032 104.98.196.29   443   United States   NA CLOSE_WAIT  tquinn     202962  vmware               /usr/lib/vmware/bin/...
# 20-12-05 14:35:47 tcp   192.168.101.118 40242 151.101.194.133 443   United States   NA ESTABLISHED tquinn     2148690 chrome               /opt/google/chrome/c...
- 20-12-05 14:35:47 tcp   192.168.101.118 45919 103.132.192.30  443   Singapore       AS ESTABLISHED -          -       -                    -
# ...
```

### Thanks

Huge thanks to Giampaolo Rodola' (giampaolo) and all the contributers of [psutil](https://github.com/giampaolo/psutil) for the amazing open source library that this project relies upon completely.

Also, thanks to gleitz and his project [howdoi](https://github.com/gleitz/howdoi), in my refactor of histstat I modeled my code around his command line tool as the code is exceptionally clean and readable.
