from scapy.contrib.pnio import *
from scapy.all import *

scapy.load_contrib("pnio")

def get_profisafe_pdu(controlByte, data, seed, vcn):
    