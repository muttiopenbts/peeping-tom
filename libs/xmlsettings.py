#
# python module xmlsettings.py
#
# Version: 1.0.0b
# Author:  Alejandro Lopez Correa
# Contact: alc@spika.net
# URL:     http://spika.net/py/xmlsettings/
# License: MIT License
#
# Tested with python 2.7 and 3.2
#
# Copyright (c) 2013 Alejandro Lopez Correa
#
# MIT License
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

#from __future__ import print_function # just for test() function at the end
import xml.dom.minidom

# -------------------------------------------------------------------
# convenience functions to provide compatibility with python 2 & 3

import platform

if platform.python_version().startswith( '3' ):
    def _to_string( x ):
        return str(x)
    def _write_file( fpath, doc ):
        txt = doc.toprettyxml()
        txt = '\n'.join( [line for line in txt.split('\n') if line.strip()] ) + '\n'
        open( fpath, 'wt', encoding='utf8' ).write( txt )
else:
    def _to_string( x ):
        return unicode(x)
    def _write_file( fpath, doc ):
        txt = doc.toprettyxml()
        txt = '\n'.join( [line for line in txt.split('\n') if line.strip()] ) + '\n'
        open( fpath, 'wb' ).write( txt.encode('utf8') )

# -------------------------------------------------------------------
# XMLSettingsUncached: main class that deals with xml dom

class XMLSettingsUncached( object ):
    def __init__( self, fpath ):
        try:
            self.doc = xml.dom.minidom.parse( fpath )
        except IOError:
            self.doc = xml.dom.minidom.parseString( '<root/>' )
        self.rootNode = self.doc.childNodes[0].nodeName
        self.fpath = fpath
        self.modified = False

    def save( self, **kwArgs ):
        if self.modified:
            fpath = kwArgs.get( 'fpath', self.fpath )
            _write_file( fpath, self.doc )
            self.modified = False

    def __get_node( self, path, **kwArgs ):
        path = self.rootNode + '/' + path.lstrip('/')
        createPath = kwArgs.get( 'createPath', False )
        node = self.doc
        for p in path.split('/'):
            ok = False
            for c in node.childNodes:
                if c.nodeName == p:
                    node = c
                    ok = True
                    break
            if not ok:
                if not createPath:
                    return None
                if node.childNodes and node.childNodes[0].nodeType == self.doc.TEXT_NODE:
                    node.removeChild( node.childNodes[0] )
                c = self.doc.createElementNS( None, p )
                node.appendChild( c )
                node = c
        return node

    def put( self, path, value ):
        if self.get( path, type(value)() ) == value:
            return
        
        node = self.__get_node( path, createPath=True )
        while node.childNodes:
            node.removeChild( node.childNodes[-1] )
        v = self.doc.createTextNode( _to_string(value) )
        node.appendChild( v )
        self.modified = True

    def put_attribute( self, path, attribute, value ):
        if self.get_attribute( path, attribute, type(value)() ) == value:
            return

        node = self.__get_node( path, createPath=True )
        node.setAttribute( attribute, _to_string(value) )
        self.modified = True

    def get( self, path, defValue ):
        node = self.__get_node( path )
        if node:
            if len(node.childNodes) == 1 and node.childNodes[0].nodeType == self.doc.TEXT_NODE:
                if defValue != None:
                    a = type(defValue)(node.childNodes[0].nodeValue)
                else:
                    a = node.childNodes[0].nodeValue
                return a
        return defValue
                
    def get_attribute( self, path, attribute, defValue ):
        node = self.__get_node( path )
        if node:
            a = node.getAttributeNode( attribute )
            if a:
                if defValue != None:
                    a = type(defValue)(a.value)
                else:
                    a = a.value
                return a
        return defValue

# -------------------------------------------------------------------
# XMLSettings: Cache layer on top of XMLSettingsUncached

class XMLSettings( object ):
    def __init__( self, fpath ):
        self.xml = XMLSettingsUncached( fpath )
        self.cache = dict()
        self.acache = dict()
    def save( self, **kwArgs ):
        return self.xml.save( **kwArgs )
    def put( self, path, value ):
        r = self.xml.put( path, value )
        self.cache.clear()
        self.acache.clear()
        self.cache[path] = value
        return r
    def put_attribute( self, path, attribute, value ):
        r = self.xml.put_attribute( path, attribute, value )
        self.cache.clear()
        self.acache.clear()
        self.acache[(path,attribute)] = value
        return r
    def get( self, path, defValue='' ):
        x = self.cache.get( path, None )
        if x == None:
            x = self.xml.get( path, None )
            if x == None:
                x = defValue
            else:
                if defValue != None:
                    x = type(defValue)(x)
                self.cache[path] = x
        return x
    def get_attribute( self, path, attribute, defValue='' ):
        x = self.acache.get( (path,attribute), None )
        if x == None:
            x = self.xml.get( path, attribute, None )
            if x == None:
                x = defValue
            else:
                if defValue != None:
                    x = type(defValue)(x)
                self.acache[(path,attribute)] = x

        return x

def test():
    country = 'Espa\xc3\x83a'.decode( 'utf8' ) # syntax compatible with python 2.7 & 3
    unicodeDefault = ''.decode( 'utf8' )
    
    xml = XMLSettings( 'config.xml' )
    xml.put( 'userdata/uname', 'xad' )
    xml.put( 'userdata/url', 'http:/example.domain.com' )
    xml.put( 'userdata/level', 32 )
    xml.put( 'userdata/country', country )
    xml.save()

    print( xml.get( 'userdata/level', 100 ) )
    print( xml.get( 'userdata/country', unicodeDefault ) )
