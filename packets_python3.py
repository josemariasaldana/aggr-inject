#from scapy.all import *
from kamene.all import * #https://github.com/phaethon/kamene
#from scapy.all import sr1, sr, srp1, send, sendp, hexdump, ETH_P_IP
#from scapy.layers.inet import Raw, Ether, TCP, IP, ICMP, arp#this worked for python2
from kamene.layers.inet import *
#from scapy.layers.inet import *
# scapy dot11.py is at https://github.com/secdev/scapy/blob/cdd0609db3790ba4c7d25d33c2d23c34a49d7907/scapy/layers/dot11.py
#from scapy.layers.dot11 import Dot11, LLC, SNAP, RadioTap, Dot11Beacon, Dot11Elt, Dot11ProbeResp
#from scapy.layers.dot11 import *
from kamene.layers.dot11 import Dot11, LLC, SNAP, RadioTap, Dot11Beacon, Dot11Elt, Dot11ProbeResp
from constants import *
from rpyutils_python3 import get_frequency, printd, Color, Level, clr, hex_offset_to_string
import random
import crcmod
from crcmod import mkCrcFun, Crc
import struct   # see https://docs.python.org/2/library/struct.html
import time
import sys

# Configuration
DEFAULT_SOURCE_IP = '10.0.0.2'
DEFAULT_DEST_IP = '10.0.0.1'
DEFAULT_SOURCE_MAC = 'ff:ff:ff:ff:ff:ff'
DEFAULT_DEST_MAC = 'ff:ff:ff:ff:ff:ff'
CHANNEL = 1
MONITOR_INTERFACE = 'mon1'


# 802.11 MAC CRC
def dot11crc(pkt):
    #crc_fun = crcmod.Crc(0b100000100110000010001110110110111, rev=True, initCrc=0x0, xorOut=0xFFFFFFFF) # this was valid for python2
    #crc_fun.update(str(pkt))   # this was valid for python2

    # FIXME: the next 2 lines do not work for python3
    crc_fun = crcmod.mkCrcFun(0b100000100110000010001110110110111, initCrc=0, xorOut=0xFFFFFFFF)
    crc_fun = Crc (crc_fun, 0)

    crc = struct.pack('<I', crc_fun.crcValue)
    return crc


# For testing purposes
class GarbagePacket():
    def __init__(self):
        self.data = None

    def set_delimiter_garbage(self):
        self.data = '\x4e' * 1024

    def set_null_garbage(self):
        self.data = '\x00' * 1024

    def __str__(self):
        return str(self.data)

    def dump_to_file(self):
        with open('ampdu.bin', 'w') as f:
            printd(clr(Color.YELLOW, "Dumped garbage packet"), Level.INFO)
            f.write(str(self) * 250)


# Normal 802.11 frame class
class Dot11Packet():
    def __init__(self, recv_mac, trans_mac, dst_mac):
        # the next line is the original one, and it workec well
        #self.rt = RadioTap(version=0, len=18, present='Flags+Channel+dBm_AntSignal+Antenna+VHT', notdecoded='\x00\x6c' + str(get_frequency(CHANNEL)) + '\xc0\x00\xc0\x01\x00\x00')

        my_notdecoded = ''
        my_notdecoded = my_notdecoded + '\x00' # flags 
        my_notdecoded = my_notdecoded + '\x6c' # 6C H = 108 D -> rate 54Mbps
        """
        I am totally unable to get the channel correctly
        channel_bytes = get_frequency(CHANNEL)
        print("channel_bytes: {}".format(channel_bytes))    # following the example print("{}. {} appears {} times.".format(i, key, wordBank[key]))
        print("channel_bytes: {}".format(channel_bytes.decode('ascii')))
        for my_bytes in bytes(channel_bytes):
            print(''.join('\\x{:02x}'.format(my_bytes)), end='', flush=True)
            my_notdecoded = my_notdecoded + join('{:02x}'.format(my_bytes))
        my_notdecoded = my_notdecoded + str(bytes(channel_bytes))     # channel. 4 bytes. This is not right. It is generating 6 bytes
        """
        my_notdecoded = my_notdecoded + '\x6c\x09'  # channel frequency. 2 bytes. 6c09 means 2412MHz (096Ch = 2412d)
        #my_notdecoded = my_notdecoded + '\xa8\x09'  # channel frequency. 2 bytes. a809 means 2472MHz (09A8h = 2472d)
        my_notdecoded = my_notdecoded + '\x00\x00'  # channel flags. 2 bytes
        my_notdecoded = my_notdecoded + '\xc0'  # dBm
        my_notdecoded = my_notdecoded + '\x00'  # antenna 0
        my_notdecoded = my_notdecoded + '\xc0'  # dBm
        my_notdecoded = my_notdecoded + '\x01'  # antenna 1
        my_notdecoded = my_notdecoded + '\x00'  # padding ¿?
        my_notdecoded = my_notdecoded + '\x00'  # padding ¿?   
        self.rt = RadioTap(version=0, len=18, present='Flags+Channel+dBm_AntSignal+Antenna+VHT', notdecoded=my_notdecoded)
        self.dot11hdr = Dot11(type="Data", subtype=DOT11_SUBTYPE_DATA, addr1=recv_mac, addr2=trans_mac, addr3=dst_mac, SC=0x3060, FCfield=0x01)
        self.data = self.rt / self.dot11hdr
        self.recv_mac = recv_mac
        self.trans_mac = trans_mac
        self.dst_mac = dst_mac

    def __str__(self):
        return str(self.data[RadioTap].payload)  # RadioTap information is only useful while sending (in monitor mode).

    # Higher layer packet. Add the MSDU and the CRC
    def add_msdu(self, msdu, msdu_len=-1):
        # Default msdu len
        if msdu_len == -1:
            msdu_len = len(msdu)

        mpdu_len = len(self.dot11hdr) + msdu_len + 4  # mac80211 + msdu + FCS

        # print the length of the padding
        print('MPDU length: {mpdu_len}')

        if mpdu_len % 4 != 0:
            frame_padding = "\x00" * (4 - (mpdu_len % 4))  # Align to 4 octets
            printd("Padding added: ", Level.INFO)
            #for character in str(frame_padding):        
                #print "\\x",character.encode('hex'),   #does not work in python3
            #printd("", Level.INFO)
        else:
            frame_padding = ""
            printd("No padding added", Level.INFO)
            
        sys.stdout.flush()


        mpdu_len <<= 4
        crc_fun = crcmod.mkCrcFun(0b100000111, rev=True, initCrc=0x00, xorOut=0xFF)

        crc = crc_fun(struct.pack('<H', mpdu_len))
        maccrc = dot11crc(str(self.dot11hdr / msdu))

        # the packet alreacy contains the 'rt' and the 'dot11hdr', so I add the other things
        self.data = self.data / msdu / maccrc / frame_padding


    def send(self):
        return sendp(self.data, iface=MONITOR_INTERFACE, verbose=False)


# 802.11 frame class with support for adding MSDUs to a single MPDU
class AMSDUPacket():
    def __init__(self, recv_mac, src_mac, dst_mac, ds=0x01):
        self.rt = RadioTap(len=18, present='Flags+Rate+Channel+dBm_AntSignal+Antenna', notdecoded='\x00\x6c' + get_frequency(CHANNEL) + '\xc0\x00\xc0\x01\x00\x00')
        self.dot11hdr = Dot11(type="Data", subtype=DOT11_SUBTYPE_QOS_DATA, addr1=recv_mac, addr2=src_mac, addr3=dst_mac, SC=0x3060, FCfield=ds) / Raw("\x80\x00")
        self.data = self.rt / self.dot11hdr
        self.num_subframes = 0
        self.recv_mac = recv_mac
        self.src_mac = src_mac
        self.dst_mac = dst_mac

    def __str__(self):
        return str(self.data[RadioTap].payload)

    def add_msdu(self, msdu):
        msdu_len = len(msdu)
        total_len = msdu_len + 6 + 6 + 2
        padding = "\x00" * (4 - (total_len % 4))  # Align to 4 octets

        if self.num_subframes > 0:
            self.data /= padding

        self.data = self.data / Ether(src=self.src_mac, dst=self.recv_mac, type=msdu_len) / msdu

        self.num_subframes += 1

    def send(self):
        return sendp(self.data, iface=MONITOR_INTERFACE, verbose=False)


"""
Total Aggregate (A-MPDU) length; the aggregate length is the number of bytes of
the entire aggregate. This length should be computed as:
delimiters = start_delim + pad_delim;
frame_pad = (frame_length % 4) ? (4 - (frame_length % 4)) : 0
agg_length = sum_of_all (frame_length + frame_pad + 4 * delimiters)
"""
# 802.11 frame class with support for adding multiple MPDUs to a single PHY frame
class AMPDUPacket():
    def __init__(self, recv_mac, src_mac, dst_mac, ds=0x01):    # 'ds' means from/to distribution system, etc
        # the next line is the original version
        self.rt = RadioTap(len=18, present='Flags+Rate+Channel+dBm_AntSignal+Antenna', notdecoded='\x00\x6c' + get_frequency(CHANNEL) + '\xc0\x00\xc0\x01\x00\x00')
        #self.rt = RadioTap(len=18, present='Flags+Rate+Channel+dBm_AntSignal+Antenna+MCS', notdecoded='\x00\x6c' + get_frequency(CHANNEL) + '\xc0\x00\xc0\x01\x00\x00')
        self.dot11hdr = Dot11(type="Data", subtype=DOT11_SUBTYPE_QOS_DATA, addr1=recv_mac, addr2=src_mac, addr3=dst_mac, SC=0x3060, FCfield=ds) / Raw("\x00\x00")
        self.data = self.rt  # initially I only add the Radiotap header. I will add the rest of the headers later
        self.num_subframes = 0
        self.recv_mac = recv_mac
        self.src_mac = src_mac
        self.dst_mac = dst_mac

    def __str__(self):
        return str(self.data[RadioTap].payload)

    # Higher layer packet
    def add_msdu(self, msdu, msdu_len=-1):
        # Default msdu len
        if msdu_len == -1:
            msdu_len = len(msdu)

        mpdu_len = len(self.dot11hdr) + msdu_len + 4  # mac80211 + msdu + FCS

        # print the length of the padding
        #print 'MPDU length: ', mpdu_len    #this worked in python2
        print('MPDU length: {mpdu_len}')

        if mpdu_len % 4 != 0:
            frame_padding = "\x00" * (4 - (mpdu_len % 4))  # Align to 4 octets
            printd("Padding added: ", Level.INFO)
            #for character in str(frame_padding):        
                #print "\\x",character.encode('hex'),   #does not work in python3
            #printd("", Level.INFO)
        else:
            frame_padding = ""
            #printd("No padding added", Level.INFO)

        sys.stdout.flush()

        mpdu_len <<= 4
        crc_fun = crcmod.mkCrcFun(0b100000111, rev=True, initCrc=0x00, xorOut=0xFF)

        crc = crc_fun(struct.pack('<H', mpdu_len))
        maccrc = dot11crc(str(self.dot11hdr / msdu))
        delim_sig = 0x4E

        #print('a-mpdu: len %d crc %02x delim %02x' % (mpdu_len >> 4, crc, delim_sig))
        #hexdump(maccrc)
        ampdu_header = struct.pack('<HBB', mpdu_len, crc, delim_sig) #'pack' returns a string containing the given values, packed according to the given format
        #hexdump(ampdu_header)

        self.data = self.data / ampdu_header / self.dot11hdr / msdu / maccrc / frame_padding

        self.num_subframes += 1

    def add_padding(self, times):  # Add padding delimiter (an extra delimiter indicating an empty subframe)
        for i in range(0, times):
            self.data /= "\x00\x00\x20\x4e"

    def add_padding_bogus(self, times):  # Add bogus padding
        for i in range(0, times):
            self.data /= "\xff\xff\xff\xff"

    def send(self):
        return sendp(self.data, iface=MONITOR_INTERFACE, verbose=False)

    def dump_to_file(self):
        with open('ampdu.bin', 'w') as f:
            for i in range(0, 1024):
                f.write(str(self))  # Try to shift position so our payload will land on correct offset


# ICMP Echo Request packet
def ping_packet(seq=0, src=DEFAULT_SOURCE_IP, dst=DEFAULT_DEST_IP, length=-1):
    icmp_packet = ICMP(seq=seq, type=8, code=0) / "XXXXXX"  # The "XXXXXX" is the payload of the ICMP
    icmp_packet = ICMP(icmp_packet.do_build())  # Force checksum calculation

    icmp_length = length
    if length == -1:
        icmp_length = len(icmp_packet)

    ping = LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03) \
               / SNAP(OUI=0x000000, code=ETH_P_IP) \
               / IP(src=src, dst=dst, len=(20 + icmp_length)) \
               / icmp_packet

    return ping


# ARP packet
def arp_packet(hwsrc, psrc, hwdst, pdst):
    arp_packet = ARP(hwsrc=hwsrc, psrc=psrc, hwdst=hwdst, pdst=pdst, op=1)
    arp = LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03) \
               / SNAP(OUI=0x000000, code=0x0806) \
               / arp_packet

    return arp


# TCP syn packet
def tcp_syn(src_ip, dst_ip, port):
    tcp_syn_p = TCP(dport=port, flags="S", window=29200, seq=random.randint(0, 100000), sport=random.randint(40000, 60000), options=[('MSS', 1460), ('SAckOK', ''), ('Timestamp', (147229543, 0)), ('NOP', None), ('WScale', 7)])

    syn = LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03) \
               / SNAP(OUI=0x000000, code=ETH_P_IP) \
               / IP(src=src_ip, dst=dst_ip, flags=0x02, tos=0x10, len=(20 + len(tcp_syn_p))) \
               / tcp_syn_p
    syn = LLC(str(syn))

    #syn.show()

    return syn


# 802.11 Beacon frame
# TODO: Fix me; duplicate code
def ssid_packet():
    ap_mac = '00:00:00:00:00:00'
    rt = RadioTap(len=18, present='Flags+Rate+Channel+dBm_AntSignal+Antenna', notdecoded='\x00\x6c' + get_frequency(CHANNEL) + '\xc0\x00\xc0\x01\x00\x00')
    beacon_packet = Dot11(subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=ap_mac, addr3=ap_mac) \
                 / Dot11Beacon(cap=0x2105)                                                           \
                 / Dot11Elt(ID='SSID', info="injected SSID")                                         \
                 / Dot11Elt(ID='Rates', info=AP_RATES)                                               \
                 / Dot11Elt(ID='DSset', info=chr(CHANNEL))

    # Update sequence number
    beacon_packet.SC = 0x3060

    # Update timestamp
    beacon_packet[Dot11Beacon].timestamp = time.time()

    mpdu_len = len(beacon_packet) + 4

    if mpdu_len % 4 != 0:
        padding = "\x00" * (4 - (mpdu_len % 4))  # Align to 4 octets
    else:
        padding = ""
    mpdu_len <<= 4
    crc_fun = crcmod.mkCrcFun(0b100000111, rev=True, initCrc=0x00, xorOut=0xFF)

    crc = crc_fun(struct.pack('<H', mpdu_len))
    maccrc = dot11crc(str(beacon_packet))
    delim_sig = 0x4E

    #print('a-mpdu: len %d crc %02x delim %02x' % (mpdu_len >> 4, crc, delim_sig))
    #hexdump(maccrc)
    ampdu_header = struct.pack('<HBB', mpdu_len, crc, delim_sig)
    #hexdump(ampdu_header)

    data = ampdu_header / beacon_packet / maccrc / padding
    data /= "\x00\x00\x20\x4e" * 8
    data = str(data)

    return data


# 802.11 Probe Response
# TODO: Fix me; duplicate code
def probe_response():
    rt = RadioTap(len=18, present='Flags+Rate+Channel+dBm_AntSignal+Antenna', notdecoded='\x00\x6c' + get_frequency(CHANNEL) + '\xc0\x00\xc0\x01\x00\x00')
    beacon_packet = Dot11(subtype=5, addr1='ff:ff:ff:ff:ff:ff', addr2="be:da:de:ad:be:ef", addr3="be:da:de:ad:be:ef", SC=0x3060) \
                    / Dot11ProbeResp(timestamp=time.time(), beacon_interval=0x0064, cap=0x2104) \
                    / Dot11Elt(ID='SSID', info="injected SSID") \
                    / Dot11Elt(ID='Rates', info=AP_RATES) \
                    / Dot11Elt(ID='DSset', info=chr(1))

    # Update sequence number
    beacon_packet.SC = 0x3060

    mpdu_len = len(beacon_packet) + 4

    if mpdu_len % 4 != 0:
        padding = "\x00" * (4 - (mpdu_len % 4))  # Align to 4 octets
    else:
        padding = ""
    mpdu_len <<= 4
    crc_fun = crcmod.mkCrcFun(0b100000111, rev=True, initCrc=0x00, xorOut=0xFF)

    crc = crc_fun(struct.pack('<H', mpdu_len))
    maccrc = dot11crc(str(beacon_packet))
    delim_sig = 0x4E

    #print('a-mpdu: len %d crc %02x delim %02x' % (mpdu_len >> 4, crc, delim_sig))
    #hexdump(maccrc)
    ampdu_header = struct.pack('<HBB', mpdu_len, crc, delim_sig)
    #hexdump(ampdu_header)

    data = ampdu_header / beacon_packet / maccrc / padding
    data /= "\x00\x00\x20\x4e" * 8
    data = str(data)

    return data
