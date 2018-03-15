#!/usr/bin/env python

import socket
import argparse
import re
import sys


parser = argparse.ArgumentParser(description='diff for ip scans')
parser.add_argument('--ports','-p', dest='ports', nargs='+', help='ports to scan')
parser.add_argument('--ip', dest='ips', type=str, nargs='+', help='ip ranges with -. 192.168.1.1-255')
parser.add_argument('--newscanname', dest='newscanname', type=str, nargs='+', help='name of new scan')
parser.add_argument("-v", dest='verbose', help="increase output verbosity", action="store_true")

args = parser.parse_args()

def Verboseout(message, verbose):
    if verbose:
        print(message)

def GenerateIplist(ipranges):
    ips = []
    for iprange in ipranges:
        for subip1 in range(iprange[0][0], iprange[0][1] + 1):
            for subip2 in range(iprange[1][0], iprange[1][1] + 1):
                for subip3 in range(iprange[2][0], iprange[2][1] + 1):
                    for subip4 in range(iprange[3][0], iprange[3][1] + 1):
                        ip = str(subip1) + '.' + str(subip2) + '.' + str(subip3) + '.' + str(subip4)
                        ips.append(ip)
    #make list uniq
    ips = list(set(ips))
    return ips


def ParseIps(ipranges):
    iplist = []
    print("IP ranges:")
    for iprange in ipranges:
        print(iprange)
        regex = re.search(r'^([\d-]+)\.([\d-]+)\.([\d-]+)\.([\d-]+)$', iprange)
        if regex:
            ParsedWithMinus = [regex.group(1), regex.group(2), regex.group(3), regex.group(4)]
            ParsedWithoutMinus = []
            for i in ParsedWithMinus:
                if re.search(r'-', i):
                    ParsedWithoutMinus.append(map(int, i.split('-')))
                else:
                    ParsedWithoutMinus.append(map(int, [i, i]))
            iplist.append(ParsedWithoutMinus) 
        else:
            print("error parsing ip range " + iprange)
            sys.exit()
    return iplist


def ParsePorts(portsinput):
    portlist = []
    for n in portsinput:
        if re.search(r'-', n):
            fromtoport = map(int, n.split('-'))
            for port in range(fromtoport[0], fromtoport[1] + 1):
                portlist.append(port)
        else:
            portlist.append(int(n))
    #make uniq
    portlist = list(set(portlist))
    return portlist


def ScanIp(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((ip, port))

    output = False
    if result:
        output = True

    return output


if args.newscanname:
    if args.ports and args.ips:
        print("new scan:")
        #iplist
        parsedips = ParseIps(args.ips)
        iplist = GenerateIplist(parsedips)
        Verboseout("iplist: " + str(iplist), args.verbose)
        IpsTodo = len(iplist)
        print("IPs to scan: " + str(IpsTodo))

        #ports
        portlist = ParsePorts(args.ports)
        Verboseout("portlist: " + str(portlist), args.verbose)


    else:
        print("port- and ip-ranges needed")