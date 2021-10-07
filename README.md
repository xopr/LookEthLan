# LookðLan (look eth lan) 0.0.1
This python application is a network scanner that consists of 2 parts

* `lookethlan.py`: the GUI front-end
* `scanner.py`: a command line application

# About
The name is an homage to the windows tool Look@LAN and a tool in the same spirit of 
"Advanced IP scanner", "Angry IP scanner", "Free IP scanner" and possibly others.

It's supposed to run on (English locale) Linux, but some efforts have been made to make it compatible for Windows as well.

It uses the following external tools:
* `ping` for finding hosts and determining the hop count
* `avahi-resolve` for resolving the hostname via mDNS

Also, it needs the following python libraries:
* `PyQt5` for the GUI
* `ipaddress` for creating IP ranges
* `netifaces` for listing ethernet interfaces and their assigned IP addresses
* `pysmb` for retreiving the NetBIOS name
* `pysnmp` for retrieving SNMP information like name and uptime

# TODO
* actual cross-platorm support
* better and cross-platform way of looking up the hostname
* OS identification (TTL/P0f technique)
* allow universal language, swapped values, upper/lowercase TTL: (zeit=nn TTL=) 
* IPv6 support (active scan list too large, might need IPv6 specific techniques)


