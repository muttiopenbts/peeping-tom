from yapsy.PluginManager import PluginManager

class PeepingTom():
    stderr = None
    stdin = None
    stdout = None
    output = []
    def __init__(self,username=None,password=None,host=None):
       	super(PeepingTom, self).__init__()
        #ip or dns target system running ssh
    	self.host = host
        #authentication credentials
    	self.username = username
    	self.password = password
    	self.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    	self.__doConnectHost()
    '''
    Load up all plugins from plugin directory
    '''
    def doRun():
        # Load the plugins from the plugin directory.
        manager = PluginManager()
        #TODO: set plugin path to subdir of main script folder.
        manager.setPluginPlaces([PLUGINS_PLACE])
        manager.collectPlugins()
        
        # Loop round the plugins and print their names.
        for plugin in manager.getAllPlugins():
            plugin.plugin_object.server = settings['server']
            plugin.plugin_object.doRun()
        
        # Loop round the plugins and print their names.
        for plugin in manager.getAllPlugins():
            plugin.plugin_object.doOutput()
    def __doConnectHost(self):
        self.connect(self.host, username=self.username, password=self.password)
    def	doCommand(self, command):
        #Flush an previous output
        self.stdout = []
        self.output = []
        self.stdin, self.stdout, self.stderr = super(ReachAround, self).exec_command(command)
        for line in self.stdout:
            self.output.append( str( line.strip('\n')) )
        return self.output

    #Return results and have a chance to format output
    def doOutput(self):
        for line in self.output:
            print line
