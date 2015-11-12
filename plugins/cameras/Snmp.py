"""
Detect IP cameras using snmp.
pip install pysnmp --upgrade
pip install pysnmp-mids --upgrade
Get the latest version.
"""
import logging
logging.basicConfig()
import sys, getopt
sys.path.append('../')
import threading
from Camera import Camera
from netaddr import *
from pysnmp.entity.rfc3413.oneliner import cmdgen
import time
import re

import Cameras as pluginTypes

class Snmp(pluginTypes.Cameras):
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
        description = 'SNMP Compatible'
        camera_state = self._isCamera(ip)
        
        if camera_state: #unprotected camera
            firmware = self._getFirmwareVersion(ip, username=username, password=password)
            fullname = self._getFullName(ip)
            model = self.getModel(ip)
            mac = self._getMac(ip, username=username, password=password)
            self.found_cameras.append( Camera(ip=ip, model=model, firmware=firmware,  fullname=fullname, mac=mac, username=username, password=password, description=description) )
    
    def _getFirmwareVersion(self, ip, port=80, username='', password=''):
        pass
        
    def getModel(self, ip):
        mib = "1.3.6.1.2.1.1.5.0"
        return self.__getSnmp(ip, mib)
        
    def _getFullName(self, ip, port=161, username='', password=''):
        return self.__getSnmpName(ip, 0)
        
    def _getReleaseName(self):
        pass
        
    """
    Required
    Try to determine if ip address is a camera using snmp
    Return Boolean.
    """
    def _isCamera(self, ip, port=161, username='', password=''):
        fullname =  self._getFullName(ip, port, username, password)

        if fullname is not None:
            m = re.search('(camera|video)', fullname, re.I)#Test for string reply
            if m and m.group(1):
                return True
        else:
            return False
        
    def _isCameraLocked(self, ip):
        pass

    #Required
    #Not implemented
    def _doCapturePassword(self):
        print "Not implemented yet."
        pass
        
    def __getSnmp(self, ip, mib, port=161):
        errorIndication = None
        errorStatus = None
        errorIndex = None
        varBinds = None
        if self.timeout is not None:
            timeout = int(self.timeout)
        else:
            timeout = 1.5
        cmdGen = cmdgen.CommandGenerator()

        try:
            errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
                cmdgen.CommunityData('public'),
                cmdgen.UdpTransportTarget((ip, port), timeout=timeout),
                mib,
                lookupNames=True, lookupValues=True
            )
            # Check for errors and print out results
            if errorIndication:
                if self.debug:
                    print(errorIndication)
            elif errorStatus:
                if self.debug:
                    print(errorStatus)
            else:
                for name, val in varBinds:
                    if self.debug:
                        print('%s = %s' % (name.prettyPrint(), val.prettyPrint()))
                    return val.prettyPrint()
        except:
            if self.debug:
                print e
        
    def __getSnmpName(self, ip, mib, port=161):
        errorIndication = None
        errorStatus = None
        errorIndex = None
        varBinds = None
        if self.timeout is not None:
            timeout = int(self.timeout)
        else:
            timeout = 1.5
        cmdGen = cmdgen.CommandGenerator()

        try:
            errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
                cmdgen.CommunityData('public'),
                cmdgen.UdpTransportTarget((ip, port), timeout=timeout),
                cmdgen.MibVariable('SNMPv2-MIB', 'sysDescr', mib),
                lookupNames=True, lookupValues=True
            )

            # Check for errors and print out results
            if errorIndication is not None:
                if self.debug:
                    print(errorIndication)
            elif errorStatus:
                if self.debug:
                    print(errorStatus)
            else:
                for name, val in varBinds:
                    if self.debug:
                        print('%s = %s' % (name.prettyPrint(), val.prettyPrint()))
                    return val.prettyPrint()
        except Exception as e:
            if self.debug:
                print e

    def _getMac(self, ip, username=None, password=None):
        mib = "1.3.6.1.2.1.2.2.1.6.2" # snmpwalk -v2c -c public 10.46.172.179 |grep 85
        snmp_result = self.__getSnmp(ip, mib)
        m = re.search('([0-9a-fx]*)', snmp_result)
        if m is not None and m.group(1):
            return m.group(1)
