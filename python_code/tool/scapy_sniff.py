#!/usr/bin/env python
# -*- coding: utf-8 -*-

from scapy.all import sniff


def http_header(pkt):
    payloads = pkt.load
    proc1 = [i.strip() for i in payloads.split('\n') if i.strip()]

    result = dict()

    if not proc1:
        # payload is empty
        # TODO
        return result
        
    base_info = proc1[0].split(' ')
    try:
        result['method'], result['uri'], result['version'] = base_info
    except ValueError:
        # some other state need to handle, eg "HTTP/1.1 304 Not Modified"
        # TODO
        pass

    for i in proc1[1:]:
        try:
            key, value = i.split(':')
        except ValueError:
            splt = i.split(':')
            key, value = splt[0], ':'.join(splt[1:])
        result[key.strip()] = value.strip()
    return result


# res = list()
def pkt_callback(pkt):
    # get the packet which is outgoing and payload existed
    if pkt.dport == 80 and "Raw" in pkt:
        info = http_header(pkt['Raw'])
        info['src'], info['src_p'] = pkt['IP'].src, pkt.sport
        info['dst'], info['dst_p'] = pkt['IP'].dst, pkt.dport
        info['time'], info['len'] = pkt.time, pkt['IP'].len

        # res.append(info)
        print info
    else:
        # TODO
        # print pkt['IP'].src, pkt.sport, '==>', pkt['IP'].dst, pkt.dport
        pass


if __name__ == '__main__':
    # sniff the pcap file
    # sniff(offline="test.pcap", prn=pkt_callback, filter="port 80", store=0, count=10)
    # print res

    # sniff local interface
    sniff(iface="en6", prn=pkt_callback, filter="tcp and port 80", store=0)
