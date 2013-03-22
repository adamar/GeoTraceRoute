#!/usr/bin/python
import sys
import json
import urllib2
import socket

PORT = 1337


def traceRoute(host):
    IP = socket.gethostbyname(host)
    HOP=1
    print "Traceroute to %s" % str(IP)
    curr_addr = ''
    while IP != curr_addr:
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname('icmp'))
        send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.getprotobyname('udp'))
        send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, HOP)
        recv_socket.bind(("", PORT))
        send_socket.sendto("", (IP, PORT))
        curr_addr = recv_socket.recvfrom(512)[1][0]
        curr_name = getCityAndCountry(curr_addr)
        send_socket.close()
        recv_socket.close()
        HOP += 1
        curr_host = "%s (%s)" % (curr_name, curr_addr)
        print "[+] %s" % curr_host

def getCityAndCountry(IP):
    url = 'http://www.freegeoip.net/json/' + str(IP)
    req = json.loads(urllib2.urlopen(url).read())
    if 'country_name' in req:
        if 'city' in req:
            return '%s, %s' % (req['country_name'],req['city'])
    else:
        return 'Fail'

if __name__ == "__main__":
    if len(sys.argv) == 2:
        traceRoute(sys.argv[1])
    else:
        print "Need an IP or Hostname"
