#!/usr/bin/env python
try:
    import scapy.all as scapy
except ImportError:
    import scapy

try:
    # This import works from the project directory
    import scapy_http.http as http
except ImportError:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers import http

import re


def processStr(data):
    pattern = re.compile('^b\'(.*?)\'$', re.S)
    res = re.findall(pattern, str(data))
    final = re.split('\\\\r\\\\n', res[0])
    return final

packets = scapy.sniff(iface='eth0', count=100)
for p in packets:
    if 'TCP' in p:
        print('=' * 78)
        Ether_name = p.name
        Ether_dst =  p.dst


        Ether_src = p.src
        IP_name = p.payload.name
       # IP_proto = p.payload.proto
        IP_src = p.payload.src
        IP_dst = p.payload.dst

        print(Ether_name)
        print('dst : ' + Ether_dst)
        print('src : ' + Ether_src)

        print(IP_name)
        # print('protcol : ' + IP_proto)
        print('src : ' + IP_src)
        print('dst : ' + IP_dst)
        if p.haslayer(http.HTTPRequest):
            print("*********request******")
            http_name = 'HTTP Request'
            http_header = p[http.HTTPRequest].fields
            headers = http_header['Headers']
            items = processStr(headers)
            for i in items:
                print(i)

        elif p.haslayer(http.HTTPResponse):
            print("*********response******")
            http_name = 'HTTP Response'
            http_header = p[http.HTTPResponse].fields
            headers = http_header['Headers']
            items = processStr(headers)
            for i in items:
                print(i)

            if 'Raw' in p:
                load = p['Raw'].load
                items = processStr(load)
                for i in items:
                    print(i)