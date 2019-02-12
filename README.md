aggr-inject
===========

I have forke this repo for a different purpose. I just wanted to inject AMPDUS with an ath9k card in monitor mode.

I have not succeeded so far.


You have to install some modules
--------------------------------

$ apt-get install python-pcapy
$ apt-get install scapy
$ apt-get install python-dev python-setuptools
$ apt-get install python-crcmod
$ apt-get install python-requests

To use hexdump
--------------
$ sudo apt-get install python-pip
$ sudo pip install hexdump


To run scapy in python3
-----------------------
root@minipc1:/home/proyecto/aggr-inject# apt install python3-pip
root@minipc1:/home/proyecto/aggr-inject# pip3 install scapy		#this installs scapy for python3
root@minipc1:/usr/local/lib/python3.4/dist-packages# pip3 install kamene

Other modules for python3
-------------------------
root@minipc1:/home/proyecto/aggr-inject# pip3 install hexdump
root@minipc1:/home/proyecto/aggr-inject# pip3 install crcmod

root@minipc1:/home/proyecto/aggr-inject# cd /usr/local/lib/python3.4/dist-packages/
root@minipc1:/usr/local/lib/python3.4/dist-packages# ls -l

To run the program
-------------------------
root@minipc1:/home/proyecto/aggr-inject# python aggr-inject.py
root@minipc1:/home/proyecto/aggr-inject# python3 aggr-inject.py		#this runs the program in python3


kamene	https://github.com/phaethon/kamene
	https://github.com/phaethon/kamene/blob/8868ef33ccf9ba5b2648b0f8ad4c44e61221c346/kamene/layers/dot11.py

scapy	https://github.com/secdev/scapy/blob/cdd0609db3790ba4c7d25d33c2d23c34a49d7907/scapy/layers/dot11.py

examples using scapy for 802.11
	https://programtalk.com/python-examples/scapy.layers.dot11.RadioTap/