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

class Axis(pluginTypes.Cameras):
    def __init__(self):
        pluginTypes.Cameras.__init__(self)
        self.list_of_creds = [
                                        {'username':'admin', 'password':'admin'}, 
                                        {'username':'admin', 'password':''}, 
                                        {'username':'viewer', 'password':'viewer'}, 
                                        {'username':'root', 'password':''}, 
                                        {'username':'root', 'password':'pass'}, 
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
        print "Not supported yet.\n"
        return

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
        description = 'Axis'
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
        url = 'http://'+ip+'/view/viewer_index.shtml'
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
                m = re.search('realm=\"(AXIS)', auth_header)
                if m and m.group(1):
                    return 401
        else:
            return False

    def _doSetup(self, settings):
        self.sniff_timeout = 60 #scapy sniff timeout needs high value for mitm attack
        self.synflood_sleep_timer = 10

    #Return results and have a chance to format output
    def _doOutput(self):
        self.doDiscoveryBlockOutput()

    def _getFirmwareVersion(self, ip, username=None, password=None):
        pass

    def _doStream(self):
        pass

    def _getAsciiImage(self, ip, username=None, password=None):
        pass

    def _getMac(self, ip, username=None, password=None):
        pass

    def _getReleaseName(self, ip, username=None, password=None):
        pass
        
    def _getFullName(self, ip, username=None, password=None):
        pass
        
    def _isCameraLocked(self, ip):
        release_name = self._isCamera(ip)
        if release_name == 401:
            return True
        else:
            return False

    def _setPassword(self, ip, username=None, password=None, new_password=None):
        pass
