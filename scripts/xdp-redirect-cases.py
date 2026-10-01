#!/usr/bin/env python3
"""Emit wire-free XDP test-run fixtures as JSON on stdout (no traffic)."""
import ipaddress
import json
import struct


def packet(family, address=None, port=15353, ihl=5, frag=0, proto=17, payload=8):
    address = address or ("192.168.10.11" if family == 4 else "2001:db8::53")
    dest = ipaddress.ip_address(address).packed
    udp = struct.pack("!HHHH", 20000, port, 8, 0)
    if family == 4:
        header = struct.pack("!BBHHHBBH4s4s", 0x40 | ihl, 0, ihl * 4 + 8,
                             0, frag, 64, proto, 0, bytes([192, 0, 2, 1]), dest)
        return bytes(12) + b"\x08\x00" + header + bytes(max(0, ihl * 4 - 20)) + udp
    header = struct.pack("!IHBB16s16s", 6 << 28, payload, proto, 64,
                         ipaddress.ip_address("2001:db8::1").packed, dest)
    return bytes(12) + b"\x86\xdd" + header + udp


def fixtures():
    groups = []
    for family in (4, 6):
        address = "192.168.10.11" if family == 4 else "2001:db8::53"
        for wildcard, port in ((False, 15353), (True, 15353), (False, 0)):
            listen = ("0.0.0.0" if family == 4 else "::") if wildcard else address
            listener = f"{listen}:{port}" if family == 4 else f"[{listen}]:{port}"
            cases = []

            def add(name, data, expected):
                if len(data) >= 14:
                    cases.append(dict(name=name, packet=list(data), expected=expected))

            base = packet(family)
            for length in range(14, len(base) + 1):
                add(f"length-{length}", base[:length], 4 if length == len(base) else 2)
            add("padding", base + bytes(12), 4)
            add("wrong-family", packet(6 if family == 4 else 4), 2)
            for ethertype in (0x8100, 0x0806, 0x88a8):
                add(f"ether-{ethertype}", base[:12] + struct.pack("!H", ethertype) + base[14:], 2)
            wrong = bytearray(base)
            wrong[14] = (wrong[14] & 15) | 0x30
            add("wrong-version", wrong, 2)
            for byte in range(4 if family == 4 else 16):
                wrong = bytearray(base)
                wrong[(30 if family == 4 else 38) + byte] ^= 1
                add(f"address-{byte}", wrong, 4 if wildcard else 2)
            for dest_port in (0, 53, 15352, 65535):
                add(f"port-{dest_port}", packet(family, port=dest_port), 4 if port == 0 else 2)
            for proto in (0, 6, 44, 60, 255):
                add(f"protocol-{proto}", packet(family, proto=proto), 2)
            if family == 4:
                for ihl in (0, 4, 5, 6, 15):
                    data = packet(4, ihl=ihl)
                    add(f"ihl-{ihl}", data, 4 if ihl >= 5 else 2)
                    if ihl >= 5:
                        for missing in range(1, 9):
                            add(f"ihl-{ihl}-short-{missing}", data[:-missing], 2)
                for frag in (1, 0x2000, 0x3fff, 0x4000, 0x8000):
                    add(f"fragment-{frag}", packet(4, frag=frag), 2 if frag & 0x3fff else 4)
            else:
                for payload in range(8):
                    add(f"payload-{payload}", packet(6, payload=payload), 2)
            groups.append(dict(listener=listener, cases=cases))
    return groups


if __name__ == "__main__":
    print(json.dumps(fixtures()))
