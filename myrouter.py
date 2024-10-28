#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *
from colorama import Fore, init


class Arp_table:
    def __init__(self, net):
        self.table = {}
        self.intf2mac_dic = {}
        for intf in net.interfaces():
            self.update_ip2mac(intf.ipaddr, intf.ethaddr)
        for intf in net.interfaces():
            self.intf2mac_dic[intf.name] = intf.ethaddr
        print()
        self.show()
        print()


    def show(self):
        for ip, mac in self.table.items():
            print(f"IP={str(ip):<15} MAC={mac}")


    def has_ip(self, ipaddr):
        return ipaddr in self.table


    def ip2mac(self, ipaddr):
        if ipaddr in self.table:
            return self.table[ipaddr]
        else:
            return None


    def intf2mac(self, intf):
        if intf in self.intf2mac_dic:
            return self.intf2mac_dic[intf]
        else:
            return None


    def update_ip2mac(self, ipaddr, mac):
        # if mac == "ff:ff:ff:ff:ff:ff":
        #     return
        self.table[ipaddr] = mac

        print(f"[Update]:\nIP={str(ipaddr):<15} MAC={mac}")
        # print("[New arp table]:")
        # self.show()
        # print()
        # TODO: Timeout


class ForwardingTable:
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        intfname2mac = {}
        for intf in net.interfaces():
            intfname2mac[intf.name] = intf.ethaddr
        self.table = []
        with open("forwarding_table.txt", "r", encoding="UTF-8") as f:
            for line in f:
                line = line.strip()
                ipPrefix, mask, nxtHop, intfname = line.split()
                self.table.append({
                    "ip": IPv4Address(ipPrefix),
                    "mask": IPv4Address(mask),
                    "nxtHop": IPv4Address(nxtHop),
                    "intfname": intfname2mac[intfname],
                    "name": intfname
                })
        for intf in net.interfaces():
            self.table.append({
                "ip": IPv4Address(intf.ipaddr),
                "mask": IPv4Address(intf.netmask),
                "nxtHop": IPv4Address("0.0.0.0"),
                "intfname": intf.ethaddr,
                "name": intf.name
            })
        for entry in self.table:
            print(str(entry["ip"]), str(entry["mask"]), str(entry["nxtHop"]), str(entry["intfname"]), str(entry["name"]))


    def lookup(self, ip):
        intf = None
        dst_ip = None
        max_prefix = 0
        for entry in self.table:
            prefix = entry["ip"]
            mask = entry["mask"]
            prefix_len = IPv4Network(f"192.0.0.0/{str(mask)}").prefixlen
            if (int(mask) & int(ip)) == (int(mask) & int(prefix)):
                if prefix_len > max_prefix:
                    max_prefix = prefix_len
                    intf = entry["intfname"]
                    dst_ip = entry["nxtHop"]
                    print(entry)
        if intf == None:
            print(f"Not found: {ip}")
        # if intf != None and dst_ip != None:
        print(f"[lookup]: {dst_ip} matches {max_prefix}")
        return intf, dst_ip


class UnfinishedArp:
    def __init__(self, arp_packet, packet, query_ip, outIntf, outIntf_mac):
        self.arp_packet = arp_packet
        self.packet = packet
        self.query_ip = query_ip
        self.outIntf = outIntf
        self.outIntf_mac = outIntf_mac
        self.query_cnt = 0
        self.last_query = 0

    
    def resolve(self, arp_reply):
        print(self.packet.headers())
        eth = self.packet.get_header(Ethernet)
        eth.dst = EthAddr(arp_reply.senderhwaddr)
        eth.src = EthAddr(self.outIntf_mac)

        ipv4hdr = self.packet.get_header(IPv4)
        ipv4hdr.ttl -= 1

        hdrs = []
        for hdr in self.packet.headers():
            if hdr in ["Ethernet", "IPv4"]:
                continue
            hdrs.append(self.packet.get_header(hdr))

        pkt = eth + ipv4hdr
        for hdr in hdrs:
            pkt += hdr
        return self.outIntf, pkt


class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.queue = []
        self.net = net
        self.arp_table = Arp_table(self.net)
        self.ft = ForwardingTable(self.net)
        self.intf_macs = []
        self.intf_ips  = []
        self.mac2ip = {}
        self.mac2name = {}
        self.ips = []
        for intf in net.interfaces():
            self.intf_macs.append(intf.ethaddr)
            self.intf_ips.append(intf.ipaddr)
            self.mac2ip[intf.ethaddr] = intf.ipaddr
            self.mac2name[intf.ethaddr] = intf.name
            self.ips.append(intf.ipaddr)


    def send(self, intf, packet):
        print(f"[Packet to be sent]: {packet}")
        self.net.send_packet(intf, packet)
        print("*****Done*******")

    
    def handle_none_arp(self, fromIntf, packet):
        ipv4 = packet.get_header(IPv4)
        eth = packet.get_header(Ethernet)
        src_mac, src_ip, dst_mac, dst_ip = eth.src, ipv4.src, eth.dst, ipv4.dst
        print(f"\n[Packet arrive]: {packet}\n{packet.headers()}")
        print(f"[Src]: IP={src_ip} MAC={src_mac}")
        print(f"[Dst]: IP={dst_ip} MAC={dst_mac}")

        if dst_mac not in [self.arp_table.intf2mac(fromIntf), "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"]:
            print(f"[Err]: Wrong arp format ({dst_mac} is not broadcast or incoming mac)")
            return

        # For the router itself. Drop it for now
        if dst_ip in self.intf_ips:
            return

        intf_mac, nxtHop = self.ft.lookup(dst_ip)

        # No match in forwarding table. Drop it for now
        if intf_mac == None and nxtHop == None:
            return

        if str(nxtHop) != "0.0.0.0":
            dst_ip = nxtHop
        print(f"[Forward]: dst ip {dst_ip} goes to {intf_mac}")

        # if "ICMP" in packet.headers() and not self.arp_table.has_ip(dst_ip):
        #     eth = packet.get_header(Ethernet)
        #     eth.dst = EthAddr("ff:ff:ff:ff:ff:ff")
        #     eth.src = EthAddr(intf_mac)
        #     ipv4hdr = packet.get_header(IPv4)
        #     ipv4hdr.ttl -= 1
        #     hdrs = []
        #     for hdr in packet.headers():
        #         if hdr in ["Ethernet", "IPv4"]:
        #             continue
        #         hdrs.append(packet.get_header(hdr))
        #     pkt = eth + ipv4hdr
        #     for hdr in hdrs:
        #         pkt += hdr
        #     self.send(self.mac2name[intf_mac], pkt)
        #     return

        if self.arp_table.has_ip(dst_ip):
            print(f"[Arp hit]: {dst_ip} 's mac is {self.arp_table.ip2mac(dst_ip)}")
            # assert(packet.headers() == ["Ethernet", "IPv4", "ICMP"])
            eth = packet.get_header(Ethernet)
            eth.dst = EthAddr(self.arp_table.ip2mac(dst_ip))
            eth.src = EthAddr(intf_mac)
            ipv4hdr = packet.get_header(IPv4)
            ipv4hdr.ttl -= 1
            hdrs = []
            for hdr in packet.headers():
                if hdr in ["Ethernet", "IPv4"]:
                    continue
                hdrs.append(packet.get_header(hdr))
            pkt = eth + ipv4hdr
            for hdr in hdrs:
                pkt += hdr
            self.send(self.mac2name[intf_mac], pkt)
        else:
            # check if the arp request has been sent
            # if any(event.query_ip == dst_ip for event in self.queue):
            #     return
            # ???
            # assert(packet.headers() == ["Ethernet", "IPv4", "ICMP"])
            print(f"[Arp miss]: {dst_ip} not in arp")
            self.arp_table.show()
            ether = Ethernet()
            ether.src = intf_mac
            ether.dst = "ff:ff:ff:ff:ff:ff"
            ether.ethertype = EtherType.ARP
            arp = Arp(
                operation=ArpOperation.Request,
                senderhwaddr=intf_mac,
                senderprotoaddr=self.mac2ip[intf_mac],
                targethwaddr="ff:ff:ff:ff:ff:ff",
                targetprotoaddr=dst_ip
            )
            arp_packet = ether + arp
            # if dst_ip not in self.ipwl:
            #     self.send(self.mac2name[intf_mac], arp_packet)
            #     self.ipwl.append(dst_ip)
            self.queue.append(UnfinishedArp(
                arp_packet,
                packet,
                dst_ip,
                self.mac2name[intf_mac],
                intf_mac
            ))


    def handle_arp(self, fromIntf, packet):
        arp = packet.get_header(Arp)
        src_mac, src_ip, dst_mac, dst_ip = arp.senderhwaddr, arp.senderprotoaddr, arp.targethwaddr, arp.targetprotoaddr

        eth = packet.get_header(Ethernet)
        if eth.src != src_mac or eth.dst != dst_mac:
            print(f"[Err]: Unmatched src/dst mac in arp")
            return

        print(f"\n[Packet arrive]: {packet}\n{packet.headers()}")
        print(f"[Src]: IP={src_ip} MAC={src_mac}")
        print(f"[Dst]: IP={dst_ip} MAC={dst_mac}")

        if dst_mac not in [self.arp_table.intf2mac(fromIntf), "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"]:
            print(f"[Err]: Wrong arp format ({dst_mac} is not broadcast or incoming mac)")
            return

        if not self.arp_table.has_ip(dst_ip):
            print("[Miss]: dst.ip is not in router's ports")
            return

        if arp.operation == ArpOperation.Reply and src_mac == "ff:ff:ff:ff:ff:ff":
            pass
        else:
            self.arp_table.update_ip2mac(src_ip, src_mac)

        if "Vlan" in packet.headers():
            print("[Dropped]: Vlan arp packet")
            return

        if arp.operation == ArpOperation.Request:
            if dst_ip not in self.ips:
                print(f"Can't reply for {dst_ip}")
                return
            print(f"[Hit-arp-request]: {dst_mac} -> {self.arp_table.ip2mac(dst_ip)}")
            dst_mac = self.arp_table.ip2mac(dst_ip)
            self.send(fromIntf, create_ip_arp_reply(
                dst_mac, src_mac,
                dst_ip,  src_ip
            ))
        elif arp.operation == ArpOperation.Reply:
            # ???????????????????
            if src_mac == "ff:ff:ff:ff:ff:ff":
                return
            # for event in self.queue:
            #     print(event.query_ip, event.packet)
            for event in self.queue[:]:
                if event.query_ip == src_ip:
                    outIntf, pkt = event.resolve(arp)
                    self.send(outIntf, pkt)
                    self.queue.remove(event)
        else:
            print("Not arp request or reply!!!")
            assert(0)


    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv

        # print(f"\nPacket: {packet}\n")

        if packet.has_header(IPv6):
            return

        if "UDP" in packet.headers():
            hdr = packet.get_header(UDP)
            if hdr.length < 8:
                return
            print(hdr)

        if packet.has_header(Arp):
            self.handle_arp(ifaceName, packet)
        else:
            self.handle_none_arp(ifaceName, packet)


    def process_queue(self):
        ipwl = set()
        # print(f"Now is {time.time()}")
        for event in self.queue:
            print(f"{event.query_ip}  {event.query_cnt} {event.packet.headers()} TIME: {event.last_query}")

        dead = set()
        for event in self.queue:
            if event.query_cnt >= 5 and time.time() - event.last_query > 1:
                dead.add(event.query_ip)
        for ip in dead:
            for ev in self.queue[:]:
                if ev.query_ip == ip:
                    self.queue.remove(ev)

        for event in self.queue:
            if event.last_query != 0 and time.time() - event.last_query <= 1:
                ipwl.add(event.query_ip)
        # print(ipwl)
        for event in self.queue:
            if event.query_ip in ipwl:
                continue
            print(f"--------Request {event.query_ip}  at  {time.time()}-----------")
            self.send(event.outIntf, event.arp_packet)
            event.last_query = time.time()
            event.query_cnt += 1
            ipwl.add(event.query_ip)


    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            self.process_queue()
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break
            self.handle_packet(recv)

        self.stop()


    def stop(self):
        self.net.shutdown()


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    # init(autoreset=True)
    router = Router(net)
    router.start()
