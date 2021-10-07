#!/usr/bin/env python3
#    Look@Lan - A simple network scanner.
#    Copyright (C) 2021 - xopr - xopr@ackspace.nl
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License or any
#    later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    A copy of the GNU General Public License version 3 named LICENSE is
#    in the root directory of this project.
#    If not, see <https://www.gnu.org/licenses/licenses.en.html#GPL>.

# -*- coding: utf-8 -*-
"""
LookEthLan network scanner
"""
__version__ = "0.0.1"

import asyncio
import getopt
import logging
import platform
import re
import sys
import threading

from ipaddress import ip_network
from netifaces import interfaces, ifaddresses, AF_INET, AF_INET6, gateways
from nmb.NetBIOS import NetBIOS
from time import time
from pysnmp.hlapi import (
    getCmd,
    nextCmd,
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity
)

isWindows = platform.system().lower() == "windows"
LOG_FORMAT = "[%(levelname)s] - { %(name)s }: %(message)s"
logger = logging.getLogger()

class EthScanner():
    """
    Ethernet scanner (parallel ping)    
    """
    
    ip_list = None
    _lock = threading.Lock()
    busy_counter = 0
    
    def __init__(self):
        #super().__init__()
        self._lock = threading.Lock()
        self.ip_list = {}

    def scan(self, network:str=None, interface:str=None, *, netbios=False, snmp=False, resolvename=False, counthops=False):
        defaultif = gateways()['default'][AF_INET][1]
        defaultaddress = ifaddresses(defaultif).setdefault( AF_INET )[0]

        ip = None
        subnet = None
        if network and len( network ):
            network = network.split("/")
            ip = network[0] or None
            subnet = len( network ) > 1 and network[1] or None
            
        if ip == None:
            ip = defaultaddress["addr"]
            subnet = defaultaddress["netmask"]
        if subnet == None:
            subnet = 32

        """
        # determine ip/subnet; if no subnet, derive from interface
        # TODO: check if we're working with ipv6
        ip = None
        subnet = None
        if network and len( network ):
            network = network.split("/")
            ip = network[0] or None
            subnet = len( network ) > 1 and network[1] or None
            
        if ip == None:
            ip = defaultaddress["addr"]
            subnet = defaultaddress["netmask"]

        for interface in interfaces():
            print( interface )
            ipv4 = ifaddresses( interface ).setdefault( AF_INET )
            if ipv4:
                ipv4 = ip_network("%s/%s" % (ipv4[0]["addr"], ipv4[0]["netmask"]), False )

            ipv6 = ifaddresses( interface ).setdefault( AF_INET6 )
            if ipv6:
                # Note: expanded subnet masks are not supported, only prefix
                prefix = bin( int( "".join( ipv6[0]["netmask"].split(":") ).ljust( 32,"0" ), 16 ) ).count( "1" )

                try:
                    ipv6 = ip_network("%s/%s" % (ipv6[0]["addr"], prefix), False )
                except:
                    ipv6 = None

            #elif subnet == None:
            ## Find subnet that matches this network
            #subnet = 32
            #network = ip_network("%s/%s" % (ip, subnet), False )

            if ipv4 and subnet == None and ip_network("%s/%s" % (ip, 32)).subnet_of( ipv4 ):
                print( interface, ipv4 )
                print( "AAAAAAAAAAAAAAAAAAAAAAAAAA" )
                subnet = defaultaddress["netmask"]
            #print( "IPv4", ipv4 )
            #print( "IPv6", ipv6 )
            # TypeError: 192.168.2.5/32 and ::1/128 are not of the same version
            #if ipv6:
            #    print( network.subnet_of( ipv6 ) )
            #    print( network.supernet_of( ipv6 ) )
            
            print( "========================================" )
        """
                
        network = ip_network("%s/%s" % (ip, subnet), False )
        
        ping_results = asyncio.run(self.ping_network( network, interface ))
        self.update_ip_list( ping_results )

        asyncio.run(self.resolve_services_async(netbios=netbios, snmp=snmp, resolvename=resolvename, counthops=counthops))

        return self.ip_list
        
    def update_ip_list(self, ping_results: [[str,int]] ):
    
        for ping_result in ping_results:
            ip = ping_result[0]
            online = ping_result[1] != None
            
            state = None

            # Already listed?
            if ip in self.ip_list:
                state = self.ip_list[ip]
                state["previous"] = self.ip_list[ip]["online"]
                state["online"] = online
                
            elif online:
                state = {
                    "previous": None,
                    "online": True
                }

            # Set latency
            if online:
                state["latency"] = ping_result[1]
            
            # Update timestamp if its state changed
            if state and state["previous"] != state["online"]:
                state["ts"] = time()

            if state:
                self.ip_list[ip] = state
    
        return self.ip_list


    async def ping(self, host: str, interface: str=None, decrement=None) -> [ str, int ]:
        """
        Prints the hosts that respond to ping request
        """  
        # Note that parsing only works for English  
        # windows: -I TTL
        # linux: -t TTL
        if interface:
            interface = " {} {}".format('-S' if isWindows else '-I', interface)
        
        cmd = 'ping {} {} 1{}'.format(host, '-n' if isWindows else '-c', interface or "")

        ping_process = \
            await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE,
                                                          stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await ping_process.communicate()
        outstr = stdout.decode()

        if decrement:
            with self._lock:
                self.busy_counter -= decrement

        if ping_process.returncode == 0:
            delay = int(re.search(r'(?:time=)([\d]*)', outstr).group(1)) if 'time=' in outstr else -1
            if delay >= 0:
                # print('{} {}ms'.format(host, delay))
                return [host, delay]

        return [host, None]


    async def ping_network(self, network: str, interface: str=None) -> [[ str, int ]]:
        tasks = []
        ping_results = []
        
        with self._lock:
            self.busy_counter = len( list( network ) )

        no_concurrent = 300
        tasks = set()
        for ip in network:
            if len(tasks) >= no_concurrent:
                # Wait for some download to finish before adding a new one
                (finished, tasks) = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for task in finished:
                    ping_results.append( task.result() )

            tasks.add(asyncio.create_task(self.ping(ip, interface, 1)))
        # Wait for the remaining downloads to finish
        (finished, tasks) = await asyncio.wait(tasks)
        for task in finished:
            ping_results.append( task.result() )

        return ping_results


    def resolve_services(self, *, netbios=False, snmp=False, resolvename=False, counthops=False):
        asyncio.run(self.resolve_services_async(netbios=netbios, snmp=snmp, resolvename=resolvename, counthops=counthops))
        return self.ip_list


    async def resolve_services_async(self, *, netbios=False, snmp=False, resolvename=False, counthops=False):
        netbios = NetBIOS()
        #print( netbios.queryIPForName( "192.168.2.170" ) )
        for ip in self.ip_list:
            if not self.ip_list[ip]["online"]:
                continue
                
            if netbios:
                self.ip_list[ip]["netbios"] = netbios.queryIPForName( str(ip), timeout=1 )
                
            if snmp:
                iterator = getCmd(
                    SnmpEngine(),
                    CommunityData('public'),
                    UdpTransportTarget((str(ip), 161)),
                    ContextData(),
                    #ObjectType(ObjectIdentity('1.3.6.1.2.1.1.3.0')),
                    #ObjectType(ObjectIdentity('1.3.6.1.2.1.1.5.0')),
                    ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysName', 0)),
                    ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)),
                    ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysUpTime', 0)),
                    lookupMib=False
                )
                
                errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
                if not errorIndication and not errorStatus:
                    self.ip_list[ip]["snmp"] = list( map( lambda x: str(x[1]), varBinds ) )
            if resolvename:
                cmd = 'avahi-resolve --address {}'.format(str( ip) )
                #nslookup 192.168.2.170 192.168.2.1


                mdns_process = \
                    await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE,
                                                                  stderr=asyncio.subprocess.PIPE)
                stdout, stderr = await mdns_process.communicate()
                host = stdout.decode().strip("\n").split("\t").pop()
                if host:
                    self.ip_list[ip]["fqdn"] = host

            if counthops:
                for ttl in range( 1, 256 ):
                    cmd = 'ping {} {} 1 {} {}'.format(str(ip), '-n' if isWindows else '-c', '-I' if isWindows else '-t', ttl)

                    ping_process = \
                        await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE,
                                                                  stderr=asyncio.subprocess.PIPE)
                    stdout, stderr = await ping_process.communicate()
                    
                    #print( ttl, ping_process.returncode )
                    if not ping_process.returncode:
                        break;

                self.ip_list[ip]["hops"] = ttl

            #print( self.ip_list[ip] )
        return self.ip_list


def main():
    # get arguments (skip first)
    argument_list = sys.argv[1:]

    # tell getopts() the parameters
    short_options = "Vdhi:n:"
    long_options = ["version", "debug", "help", "", ""]

    # use try-except to cover errors
    try:
        arguments, values = getopt.getopt(
            argument_list, short_options, long_options
        )
    except getopt.error as e:
        # print error message and return error code
        err_msg = str(e)
        print(f"O{err_msg[1:]}")
        sys.exit(2)

    if len(values):
        value = values[0]
        values = values[1:]
        values = value.split("/") + values
        
    for arg, val in arguments:
        if arg in ("-h", "--help"):
            # show help message, then exit
            print(
                f"lookðlan {__version__}  "
                "( https://github.com/ackspace/lookethlan )\n\n"
                "    -h --help           Show this help message and exit\n"
                "    -d --debug          Print debugging output\n"
                "    -V --version        Print version and exit\n"
            )
            sys.exit(0)

        if arg in ("-d", "--debug"):
            # verbose output for debugging
            logging.basicConfig(level=logging.DEBUG, format=LOG_FORMAT)

        if arg in ("-V", "--version"):
            # print version, then exit
            print(f"lookðlan {__version__}")
            sys.exit(0)

    ethScanner = EthScanner()
    ip_list = ethScanner.scan( "/".join( values[:2] ), counthops=True )
    for ip in ip_list:
        print( "{} {}ms".format( ip, ip_list[ip]["latency"] ) )

    sys.exit(0)



if __name__ == "__main__":
    main()

