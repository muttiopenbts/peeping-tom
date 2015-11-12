# peeping-tom
Proof of concept IP camera scanner and manager which is extendable with plugins

peeping-tom.py
Version 0.1

Intended purpose:
Scan a network for IP cameras and attempt to capture password.

Two modes of scanning available,
1 udp broadcast 255.255.255.255 and pickup all Arecont cameras listening.
2 scan an individual host or network range. e.g. 192.168.2/24 or 192.168.3.3

Extra features
Video stream to ascii art.
Change a camera's password.

The tool can also dictionary attack the camera's password using a file or it can go into Man-in-the-middle mode and capture the base64 password.

Enjoy.
