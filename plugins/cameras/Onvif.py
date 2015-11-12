"""
Based on an awesome project to standardize security camera communication. ONVIF.
onvif.org
pip install onvif
"""
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.basicConfig()
import sys, getopt
sys.path.append('../')
import threading
from scapy.all import *
from Camera import Camera
from netaddr import *
import common # local lib file for common functions

if common.module_exists('onvif') is False:
    print "Module missing. Try #pip install onvif"
    sys.exit(1)
from onvif import ONVIFCamera
    
import Cameras as pluginTypes

class Onvif(pluginTypes.Cameras):
    def __init__(self):
        pluginTypes.Cameras.__init__(self)

    #Required
    def _doSetup(self, settings):
        pass
        
    def _doStream(self, ip, username=None, password=None):
        pass
        
    def _doDiscovery(self):
        #UDP Broadcast scan?
        if self.dip == '255.255.255.255':
            return "Not yet implemented"
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


    #Required
    #Return results and have a chance to format output
    def _doOutput(self):
        self.doDiscoveryBlockOutput()
        
    """
    Required
    """
    def _getDetails(self, ip, username=None, password=None):
        global found_cameras
        model = 'Locked'
        firmware = 'Locked'
        fullname = 'Locked'
        mac = 'Locked'
        description = 'ONVIF Compatible.'
        camera_state = self._isCamera(ip)
        
        if camera_state: #unprotected camera
            firmware = self._getFirmwareVersion(ip, username=username, password=password)
            fullname = self._getFullName(ip)
            model = self.getModel(ip)
            mac = self.__getInterfaces(ip, username=username, password=password)
            self.found_cameras.append( Camera(ip=ip, model=model, firmware=firmware,  fullname=fullname, mac=mac, username=username, password=password, description=description) )
    
    #Not working
    def __getInterfaces(self, ip, port=80, username='', password=''):
        try:
            if self.debug:
                print str(port) + username + password
            mycam = ONVIFCamera(ip, port, username, password, '/etc/onvif/wsdl/')
            resp = mycam.devicemgmt.GetNetworkInterfaces()
            if self.debug:
                print username + password
                print resp
            return str(resp.Name)
        except Exception as e:
            if self.debug:
                print e
        
    def _getFirmwareVersion(self, ip, port=80, username='', password=''):
        try:
            if self.debug:
                print str(port) + username + password
            mycam = ONVIFCamera(ip, port, username, password, '/etc/onvif/wsdl/')
            resp = mycam.devicemgmt.GetDeviceInformation()
            if self.debug:
                print username + password
                print resp
            return str(resp.FirmwareVersion)
        except Exception as e:
            if self.debug:
                print e

    def getModel(self, ip, port=80, username='', password=''):
        try:
            mycam = ONVIFCamera(ip, port, username, password, '/etc/onvif/wsdl/')
            resp = mycam.devicemgmt.GetDeviceInformation()
            return str(resp.Model)
        except Exception as e:
            if self.debug:
                print e
        
    def _getFullName(self, ip, port=80, username='', password=''):
        try:
            mycam = ONVIFCamera(ip, port, username, password, '/etc/onvif/wsdl/')
            resp = mycam.devicemgmt.GetHostname()
            return str(resp.Name)
        except Exception as e:
            if self.debug:
                print e
        
    def _getReleaseName(self):
        pass
        
    """
    Required
    Try to determine if ip address is a camera
    Return Boolean.
    """
    def _isCamera(self, ip, port=80, username='', password=''):
        fullname = self._getFullName(ip, port, username, password)

        if fullname is not None:
            return True
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
