#!/usr/bin/env python
"""
POC
A simple IP camera scanner/MitM tool.
Only supports discovery mode for a few cameras.
Extendable via plugin architecture.
mkocbayi@gmail.com
Requires scapy installed.
"""
import sys, getopt
import logging
logging.basicConfig()
import os
import fcntl

#used for retrieving ip address of iface
import netifaces as ni

script_path = os.path.dirname(os.path.realpath(__file__))
sys.path.append(script_path + '/libs')
sys.path.append(script_path + '/plugins')
import xmlsettings
import datetime
from yapsy.PluginManager import PluginManager
from yapsy.PluginManager import PluginInfo
import socket
from struct import *
import struct
from signal import *

settings = {
    #mode of operation
    'mode':None, 
    'socket':None,
    'debug':None, 
    'timeout_param': 5, 
    'threads':3, 
    'sif': None, #Source interface used for scapy
    'pfile':None, 
    'dip':None, 
    'sip':None,
    'ip_file':None,  
    #timeout for http requests
    'timeout':5, 
    #Camera make for discovery, supports samsung and arecont
    'make':'arecont', 
    'list_of_creds': None, 
    'module': None, #module\plugin to run
    'username': None, #camera cred
    'password': None, #camera cred
    'new_password': None, #new camera cred
    'output_format': None, #output format
    'sniff_timeout': None
    }
PLUGINS_PLACE = script_path + '/plugins/cameras/'

def catchSignal(*args):
    print "\nBye!"
    #kills process even if threads are running
    os._exit(0)

for sig in (SIGABRT, SIGILL, SIGINT, SIGSEGV, SIGTERM):
    signal(sig, catchSignal)

def get_ip_address(ifname):
    return ni.ifaddresses(ifname) [2][0]['addr']

'''
Load up all plugins from plugin directory
'''
def doRun():
    settings = read_config()

    # Load the plugins from the plugin directory.
    manager = PluginManager()
    #TODO: set plugin path to subdir of main script folder.
    manager.setPluginPlaces([PLUGINS_PLACE])
    manager.collectPlugins()
    
    # Loop round the plugins and run discovery.
    for plugin in manager.getAllPlugins():
        plugin.plugin_object.doSetup(settings)
        plugin.plugin_object.doDiscovery()
        
    # Loop round the plugins and print results.
    for plugin in manager.getAllPlugins():
        plugin.plugin_object.doSetup(settings)
        plugin.plugin_object.doOutput()

'''
Load up all plugins from plugin directory
'''
def doRunModule(settings):
    settings = read_config()

    if settings['module'] == 'list':
        doPrintModuleNames()
        return
    elif settings['module'] == 'info':
        doPrintModuleInfo()
        return

    # Load the plugins from the plugin directory.
    manager = PluginManager()
    #TODO: set plugin path to subdir of main script folder.
    manager.setPluginPlaces([PLUGINS_PLACE])
    manager.collectPlugins()
    
    # Loop round the plugins and run discovery.
    for plugin in manager.getAllPlugins():
        if plugin.name == settings['module']:
            plugin.plugin_object.doSetup(settings)
            doRunMode(plugin=plugin) # control which modes can be run
            plugin.plugin_object.doOutput()
            return
    print "Module name not recognized. Try --help or --module list"

def doPrintModuleNames():
    settings = read_config()

    # Load the plugins from the plugin directory.
    manager = PluginManager()
    #TODO: set plugin path to subdir of main script folder.
    manager.setPluginPlaces([PLUGINS_PLACE])
    manager.collectPlugins()
    
    # Loop round the plugins and print names
    for plugin in manager.getAllPlugins():
        print plugin.name

def doPrintModuleInfo():
    settings = read_config()

    # Load the plugins from the plugin directory.
    manager = PluginManager()
    #TODO: set plugin path to subdir of main script folder.
    manager.setPluginPlaces([PLUGINS_PLACE])
    manager.collectPlugins()
    
    # Loop round the plugins and print names
    for plugin in manager.getAllPlugins():
        print plugin.name
        print plugin.description

'''
Read app settings from an xml config file and load values into plugins
'''
def read_config():
    return settings

def usage():
    print ' -------------------------------------------------------------------------'
    print ' Mutti K Nov 12th, 2014'
    print ' '
    print ' IP Camera Scanner'
    print ' Typical usage:'
    print ' <script.py> --debug <1> '+"\n"'\
    --dip <Camera IP|Subnet to scan|Local broadcast> '+"\n"'\
    --sip <local interface address>'+"\n"'\
    --threads <3> '+"\n"'\
    --pfile <password file> '+"\n"'\
    --sif <source interface> '+"\n"'\
    --mode <capture-password|discovery|smash-n-grab> '+"\n"'\
    --ipfile <ip file> '+"\n"'\
    --timeout <timeout in seconds>'+"\n"'\
    --username <user>'+"\n"'\
    --password <password>'+"\n"'\
    --module <plugin name>'
    print ' ./' + os.path.basename(__file__) + '--dip 255.255.255.255 --sif eth1'
    print ' or'
    print ' ./' + os.path.basename(__file__) + '--dip 255.255.255.255 --sip 10.47.172.203'
    print ' or'
    print ' ./' + os.path.basename(__file__) + '--dip 10.47.173.0/24 '
    print ' or'
    print ' ./' + os.path.basename(__file__) + '--dip 10.47.173.4 '
    print ' or'
    print ' ./' + os.path.basename(__file__) + '--dip 10.47.173.4 --mode password --sif eth1'
    print ' -------------------------------------------------------------------------'
    sys.exit(' ')

#How should the plugin\module run
def doRunMode(plugin=None):
    if settings['mode'] == 'capture-password':
        plugin.plugin_object.doCapturePassword()
    elif settings['mode'] == 'discovery':
        plugin.plugin_object.doDiscovery()
    elif settings['mode'] == 'smash-n-grab':
        plugin.plugin_object.doSmashAndGrab()
    elif settings['mode'] == 'stream':
        plugin.plugin_object.doStream()
    elif settings['mode'] == 'change-password':
        plugin.plugin_object.setPassword()
    else:
       print "Unrecognized mode specified. Try --help"
    
def main(argv):
    try:
      opts, args = getopt.getopt(argv,"h:s:d:v:t",
                                 ["sip=", 
                                 "debug=", 
                                 "dip=", 
                                 "threads=", 
                                 "pfile=", 
                                 "sif=",  
                                 "mode=", 
                                 'ipfile=', 
                                 "timeout=", 
                                 "module=", 
                                 "username=", 
                                 "new_password=", 
                                 "output-format=", 
                                 "password="])
    except getopt.GetoptError:
      usage()
      sys.exit(2)
    
    for opt, arg in opts:
        if opt == '-h':
            print '<script>.py -s <source ip> -c <destination ip>'
            sys.exit()
        elif opt in ("-s", "--sip"):
            #accept FQDN or IP
            settings['sip'] = socket.gethostbyname(arg)
        elif opt in ("--sif"):
            #accept interface name
            settings['sip'] = get_ip_address(arg)
            settings['sif'] = arg
        elif opt in ("--mode"):
            #script mode
            settings['mode'] = arg
        elif opt in ("-t", "--threads"):
            #number of threads for scanning
            settings['threads'] = arg
        elif opt in ("--pfile"):
            #password file list
            settings['pfile'] = arg
        elif opt in ("--ipfile"):
            #file of ip addresses
            settings['ip_file'] = arg
        elif opt in ("--module"):
            #Module to run
            settings['module'] = arg
        elif opt in ("--username"):
            #Module to run
            settings['username'] = arg
        elif opt in ("--password"):
            #Module to run
            settings['password'] = arg
        elif opt in ("--new_password"):
            #Module to run
            settings['new_password'] = arg
        elif opt in ("--output-format"):
            settings['output_format'] = arg
        elif opt in ("-d", "--dip"):
            #accept FQDN or IP
            try:
                settings['dip'] = socket.gethostbyname(arg)
            except:
                settings['dip'] = arg
        elif opt in ("-v", "--debug"):
            settings['debug'] = 1
        elif opt in ("--timeout"):
            settings['timeout'] = arg
        else:
            usage()
    if (settings['dip'] is not None or settings['ip_file'] is not None): #make sure we have ip address to scan
        read_config()
        doRunModule(settings)
    else:
        usage()
    
if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except Exception as e:
        print 'Cannot run program.\n', e
        if (settings['debug'] is not None):
            raise
