#!/usr/bin/env python3
"""Tiny raw-frame client for the isolated brdns-test/brdns-peer veth regression.

No selectable interface or address: run only inside the disposable test netns.
The netns must itself be in a disposable VM: COPY/veth TX can panic host kernels.
Arguments are the test's ephemeral UDP port, DNS request hex and oracle hex.
"""
import json
import os
import socket
import struct
import subprocess
import sys
import time


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    value = sum(struct.unpack('!'+str(len(data)//2)+'H', data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def mac(name):
    link, = json.loads(subprocess.check_output(['ip','-j','-d','link','show',name]))
    assert link['linkinfo']['info_kind'] == 'veth'
    return bytes.fromhex(link['address'].replace(':',''))


def main():
    if os.environ.get('BORONDNS_DISPOSABLE_VM') != '1' or subprocess.run(
            ['systemd-detect-virt', '--vm', '--quiet'], check=False).returncode:
        raise SystemExit('COPY/veth fixture requires explicit disposable-VM opt-in; netns alone is unsafe')
    port = int(sys.argv[1])
    assert 1024 <= port <= 65535
    request, expected = bytes.fromhex(sys.argv[2]), bytes.fromhex(sys.argv[3])
    assert 12 <= len(request) < 1200 and len(expected) >= 12
    ethernet = mac('brdns-test') + mac('brdns-peer') + b'\x08\x00'
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    sock.bind(('brdns-peer',0))
    sock.settimeout(1)
    started = time.monotonic()
    source_ports = []
    for identifier in range(1,21):
        # Vary the five-tuple so the two-queue veth RSS path must exercise both
        # AF_XDP sockets owned by the group loop. The test asserts per-worker
        # receive counters after all phases; payload IDs alone do not steer RSS.
        source_port = 53000 + identifier
        source_ports.append(source_port)
        dns = struct.pack('!H',identifier) + request[2:]
        udp = struct.pack('!HHHH',source_port,port,8+len(dns),0) + dns
        header = struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(udp),0,0,64,17,0,
                             socket.inet_aton('192.0.2.1'),socket.inet_aton('192.0.2.53'))
        header = header[:10] + struct.pack('!H',checksum(header)) + header[12:]
        sock.send(ethernet + header + udp)
        deadline = time.monotonic()+1
        while True:
            assert time.monotonic() < deadline, 'response deadline'
            frame = sock.recv(4096)
            if len(frame)<54 or frame[12:14]!=b'\x08\x00':
                continue
            ihl = (frame[14]&15)*4
            data = 14+ihl
            source,dest,length,_ = struct.unpack('!HHHH',frame[data:data+8])
            if source!=port or dest!=source_port:
                continue
            reply = frame[data+8:data+length]
            assert reply == struct.pack('!H',identifier)+expected[2:], (reply.hex(),expected.hex())
            assert checksum(frame[14:14+ihl])==0
            pseudo=frame[26:34]+b'\0\x11'+struct.pack('!H',length)
            assert checksum(pseudo+frame[data:data+length])==0
            break
        time.sleep(0.002)
    print(json.dumps(dict(responses=20,checksum_errors=0,content_errors=0,
                          source_ports=[min(source_ports),max(source_ports)],
                          seconds=time.monotonic()-started)))


if __name__ == '__main__':main()
