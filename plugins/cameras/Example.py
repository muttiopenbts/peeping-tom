import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.basicConfig()
import sys, getopt
sys.path.append('../')
import threading
from scapy.all import *
from Camera import Camera
from netaddr import *

import Cameras as pluginTypes

class Example(pluginTypes.Cameras):
    def __init__(self):
        pluginTypes.Cameras.__init__(self)

    #Required
    def _doSetup(self, settings):
        pass
        
    def _doDiscovery(self):
        #UDP Broadcast scan?
        if self.dip == '255.255.255.255':
            list_of_found_cameras = self.__doDiscoveryBroadcast()
        else:
            #scanning for single ip or list in file
            if self.dip is not None:
                ip_list = IPNetwork(self.dip)
                for myip in ip_list:
                    #restrict num of threads or we run out of mem
                    while threading.active_count() > self.threads:
                        if self.debug != '':
                            print "Waiting for free threads. %s threads used." % threading.active_count() 
                        time.sleep(2)
                    t1 = threading.Thread(target=self._getDetails, args=(str(myip), ))
                    t1.start()
            elif self.ip_file is not None:
                for myip in self.ip_file:
                    myip = myip.rstrip()
                    #restrict num of threads or we run out of mem
                    while threading.active_count() > self.threads:
                        if self.debug is not None:
                            print "Waiting for free threads. %s threads used." % threading.active_count() 
                        time.sleep(2)
                    t1 = threading.Thread(target=self._getDetails, args=(str(myip), ))
                    t1.start()
            #Wait till all threads are complete because scans my still be running when we reach this point
            while threading.active_count() > 1:
                if self.debug:
                    print "Active threads " + str(threading.active_count())
                time.sleep(2)
    
    #Required.
    #Return MAC address
    def __getMAC(self, pkt):
        pass

    #Required
    #Return results and have a chance to format output
    def _doOutput(self):
        pass
        
    def _doStream(self, ip, username=None, password=None):
        pass
        
    """
    Required
    """
    def _getDetails(self, ip, username=None, password=None):
        pass
    
    def _getFirmwareVersion(self):
        pass
        
    def _getFullName(self):
        pass
        
    def _getReleaseName(self):
        pass
        
    """
    Required
    Try to determine if ip address is a camera
    Return HTTP 200 if page existsl or return 401 if auth is required and realm matches. False if ip is not Arecont camera.
    """
    def _isCamera(self, ip, username=None, password=None):
        url = 'http://'+ip+'/home/monitoring.cgi'
        page = self.getHTML(url, username=username, password=password)
        if self.debug:
            print page
        if page is not None:
            if page.status_code == 200:
                return 200
            elif page.status_code == 401:
                auth_header = page.headers.get('www-authenticate')
                m = re.search('realm=\"(iPolis)', auth_header)
                if m and m.group(1):
                    return 401
        else:
            return False
        
    def _isCameraLocked(self, ip):
        page = self._isCamera(ip)
        if code == 401:
            return True
        else:
            return False

    #Required
    #Not implemented
    def _doCapturePassword(self):
        print "Not implemented yet."
        pass

    def _getMac(self, ip, username, password):
        pass
