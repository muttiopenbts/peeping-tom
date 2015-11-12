"""
Class describing IP cameras.
"""
class Camera:
    def __init__(self, ip=None, mac=None, model=None, fullname=None, username=None, password=None, description=None, firmware=None):
        self.datetimestamp = None
        self.model = model # SNV-6050
        self.make = None #e.g. Samsung
        self.fullname = fullname
        self.description = description #Discovered using samsung plugin
        self.username = username #authc
        self.password = password
        self.ip = ip
        self.mac = mac
        self.locked = None
        self.firmware = firmware
