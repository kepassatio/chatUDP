#!/usr/bin/env python
# -*- coding: utf-8 -*-
import wx
from wx import xrc
from hashlib import sha1
from array import array
import urllib
import httplib
import string
import re
import time
import ConfigParser
import unicodedata
import wx.html as html
import socket
import sys,select

#Valores por defecto
FIC_INI = 'chat.ini'
SECCION_INI = 'CONFIG'
SECCION_CON = 'CONTACTOS'
MI_NUMERO = 0
estado = {}
contactos = {}
host = ''
port = 0
crypto = {}


"""
SimpleCrypt.py REV 3
Author: A.J. Mayorga
"""
class SimpleCrypt:
    def __init__(self, INITKEY, CYCLES=3, BLOCK_SZ=126, KEY_ADV=0, KEY_MAGNITUDE=1):
        self.cycles         = CYCLES
        self.block_sz       = BLOCK_SZ
        self.key_advance    = KEY_ADV
        self.key_magnitude  = KEY_MAGNITUDE
        self.key            = self.MSha(INITKEY)
        self.eKeys          = list()
        self.dKeys          = list()
        self.GenKeys()

    """
    Short hash method
    """
    def MSha(self, value):
        try:
            return sha1(value).digest()
        except:
            print "Exception due to ", value
            return None

    """
    Sets the start byte of a cycle key
    """
    def KeyAdvance(self, key):
        k = array('B', key)
        for x in range(self.key_advance):
            k.append(k[0])
            k.pop(0)
        return k

    """
    Sets the complexity & size of a cycle key
    based off the hash of the original supplied key
    """
    def SetKeyMagnitude(self, key):
        k = array('B', key)
        for i in range(self.key_magnitude):
            k += array('B', sha1(k).digest())
            k.reverse()
        k = self.KeyAdvance(k)
        return k

    """
    Generate our encryption and decryption cycle keys based off of the number
    of cycles chosen & key magnitude
    """
    def GenKeys(self):
        k = array('B', self.key)
        self.eKeys = list()
        self.dKeys = list()

        for c in range(self.cycles):
            k = sha1(k).digest()
            self.eKeys.append(self.SetKeyMagnitude(k))
            self.dKeys.append(self.SetKeyMagnitude(k))
        self.dKeys.reverse()

    """
    Set a start vector (initialization vector) of our data in a cycle
    the iv is determined by the first byte of the cycle key and the cycle mode
    aka cmode and will be different each cycle since a different key is used each
    cycle.
    Also the direction of or rather how the iv value is set depends on the cmode
    as well forward for encryption and backward for decryption.
    """
    def SetDataVector(self, data, params):
        vdata = array('B', data)
        cmode = params[0]
        cycle = params[1]
        iv = 0

        if   cmode == "Encrypt":
            iv = array('B', self.eKeys[cycle])[0]
        elif cmode == "Decrypt":
            iv = array('B', self.dKeys[cycle])[0]

        for x in range(iv):
            if  cmode == "Encrypt":
                vdata.append(vdata[0])
                vdata.pop(0)
            elif cmode == "Decrypt":
                v = vdata.pop(len(vdata)-1)
                vdata.insert(0,v)
        return vdata

    """
    Here the cycle key is rolled over the data(Xor). Should the
    data be longer than the key (which most times will be the case) the the first
    byte of the cycle key is moved to the end the key and is used again
    Think ring buffer
    """
    def Cycle(self, data, params):
        keyplaceholder  = 0 
        dataholder      = array('B')
        cycleKey        = array('B')
        cmode           = params[0]
        cycle           = params[1]

        if cmode == "Encrypt":
            cycleKey    = array('B', self.eKeys[cycle])
        elif cmode == "Decrypt":
            cycleKey    = array('B', self.dKeys[cycle])
        for i in range(len(data)):
            dataholder.append(data[i] ^ cycleKey[keyplaceholder])
            if keyplaceholder == len(cycleKey)-1:
                keyplaceholder = 0
                cycleKey.append(cycleKey[0])
                cycleKey.pop(0)
            else:
                keyplaceholder += 1
        return dataholder

    """
    Core element bring together all of the above for encryption
    *NOTE - trying to shove larger amounts of data in here wil give you issues
    call directly for strings or other small variable storage
    for large data blocks see below
    """
    def Encrypt(self, data):
        data = array('B', data)
        for cycle in range(self.cycles):
            params = ("Encrypt", cycle)
            data = self.Cycle(self.SetDataVector(data, params), params)
        return data.tostring()

    """
    Core of decryption
    """
    def Decrypt(self, data):
        data = array('B', data)
        for cycle in range(self.cycles):
            params = ("Decrypt", cycle)
            data = self.SetDataVector(self.Cycle(data, params), params)
        return data.tostring()

class chatUDPApp(wx.App):
    envioPendiente = False

    def OnInit(self):
        self.initialize()
        return True

    def OnText(self, evt):
        usuarioCadena = self.txtEntrada.GetValue()
        if len(usuarioCadena) == 0:
            #self.txtEscribiendo.SetLabel(unicode(''))
            self.txtEscribiendo.SetValue(unicode(''))
        if len(usuarioCadena) >= 1:
            usuarioCadena = usuarioCadena.encode("iso-8859-1")
            self.txtEscribiendo.SetValue(unicode(usuarioCadena+chr(95)))
        evt.Skip()

    def onMinimize(self, event):
        a = 0

    def OnClose(self, evt):
        self.finalize()
        evt.Skip()

    def OnKey(self, evt):
        code = evt.GetKeyCode()
        if code == wx.WXK_LEFT:
            self.objHtml.AppendToPage(unicode('izquierda <br />'))
        elif code in (wx.WXK_RETURN, 370):
            textoHTML = time.strftime("%H:%M:%S") + u' <strong><font face="dejavu sans" color="brown">T\xfa</font></strong>> ' + self.frame.txtEntrada.GetValue() + '<br />'
            self.frame.objHtml.AppendToPage(unicode(textoHTML))
            self.envioDatagrama(False)
            self.frame.txtEntrada.SetValue('')
        elif code == wx.WXK_ESCAPE:
            self.finalize()
            wx.GetApp().ExitMainLoop()
            evt.Skip()
        else:
            self.envioPendiente = True
        evt.Skip()

    def OnTimer(self, event):
        try:
            # Buffer size is 8192. Change as needed.
            message, address = self.sock.recvfrom(8192)
            if message:
                #print address[0], "> ", message
                decryp = SimpleCrypt(INITKEY=address[0], CYCLES=3, BLOCK_SZ=25, KEY_ADV=5, KEY_MAGNITUDE=1)
                if message[-1] == chr(95):
                    message = message[:len(message)-1]
                    message = decryp.Decrypt(message.decode('utf-8').decode('hex'))
                    self.frame.txtEscribiendo.SetValue(unicode(message.decode('utf-8')))
                else:
                    self.frame.txtEscribiendo.SetValue('')
                    message = decryp.Decrypt(message.decode('utf-8').decode('hex'))
                    textoHTML = time.strftime("%H:%M:%S") + ' <strong><font face="helvetica" color="green">' + contactos[address[0]] + '</font></strong>> ' + message.decode('utf-8') + '<br />'
                    self.frame.objHtml.AppendToPage(unicode(textoHTML))
        except:
            pass
        #Ahora enviamos el texto si hemos pulsado alguna tecla
        if self.envioPendiente:
            self.envioDatagrama(True)

    def envioDatagrama(self, pulsacion):
        usuarioCadena = self.frame.txtEntrada.GetValue()
        if len(usuarioCadena) >= 1:
            usuarioCadena = self.crypto.Encrypt(usuarioCadena.encode('utf-8')).encode('hex').encode('utf-8')
            if pulsacion:
                usuarioCadena = usuarioCadena + chr(95)
        self.sock.sendto(usuarioCadena, self.send_address)
        self.envioPendiente = False

    def initialize(self):
       # self.res = xrc.XmlResource('chat.xrc')
       # self.frame = self.res.LoadFrame(None, 'mainFrame')
       # self.panel = xrc.XRCCTRL(self.frame, 'panel')
       # self.txtEscribiendo = xrc.XRCCTRL(self.panel, 'txtEscribiendo')
       # self.txtEntrada = xrc.XRCCTRL(self.panel, 'txtEntrada')
       # self.objHtml = xrc.XRCCTRL(self.panel, 'objHtml')
       # self.frame.Bind(wx.EVT_CLOSE, self.OnClose, id=xrc.XRCID('mainFrame'))
       # self.Bind(wx.EVT_KEY_UP, self.OnKey)
       # self.Bind(wx.EVT_CLOSE, self.OnClose)
       # self.timer = wx.Timer(self)
       # self.Bind(wx.EVT_TIMER, self.OnTimer, self.timer)
       # self.timer.Start(100)
       # self.txtEntrada.SetFocus()
       # self.txtEntrada.SetSelection(-1, -1)
       # self.objHtml.AppendToPage('<p style="font-family: calibri, serif; font-size:14pt; font-style:italic">')
       # self.frame.SetDimensions(int(estado["x"]), int(estado["y"]), int(estado["width"]), int(estado["height"]))
       # self.sock = escuchaUDP(host, port)
       # self.crypto = crypto
       # #host = "10.0.2.15"
       # #host = "192.168.5.51"
       # self.send_address = ('192.168.5.51', int(3333)) # Set the address to send to
       # return True

        self.Bind(wx.EVT_KEY_UP, self.OnKey)
        self.Bind(wx.EVT_CLOSE, self.OnClose)
        self.timer = wx.Timer(self)
        self.Bind(wx.EVT_TIMER, self.OnTimer, self.timer)
        self.timer.Start(100)
        self.sock = escuchaUDP(host, port)
        self.crypto = crypto
        self.send_address = (host, port) # Set the address to send to

        #chat(None, -1, "A ver")
        self.frame = chat(None, -1, 'Chat a ' + host + ' escuchando en el puerto ' + estado["puerto"])
        return True

    def finalize(self):
        self.timer.Stop()
        self.sock.close()
        self.frame.finalize()
        return True

def LeerFicheroIni(fichero):
    config = ConfigParser.ConfigParser()
    estadoAux = {}
    if config.read(fichero):
        for clave in config.items(SECCION_INI):
            estadoAux[clave[0]] = config.get(SECCION_INI, clave[0])
        for clave in config.items(SECCION_CON):
            contactos[clave[0]] = config.get(SECCION_CON, clave[0])
    else:
        print("NO encuentro el fichero ")
    return estadoAux

def obtieneIPLocal():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('google.com', 0))
    return s.getsockname()[0]

def escuchaUDP(direccion, puerto):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)        # Create Datagram Socket (UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)     # Make Socket Reusable
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)     # Allow incoming broadcasts
    s.setblocking(False)                                        # Set socket to non-blocking mode
    s.bind(('', puerto))                                        #Accept Connections on port
    return s

def EscribirFicheroIni (fichero, estado):
    config = ConfigParser.ConfigParser()
    config.read(fichero)
    for clave in estado.items():
        config.set(SECCION_INI, clave[0], clave[1])
    f = open(fichero, "w")
    config.write(f)
    f.close()

class chat(wx.Frame):
    def __init__(self, parent, id, title):
       # wx.Frame.__init__(self, parent, id, title)

        self.envioPendiente = False
        self.res = xrc.XmlResource('chat.xrc')
        self.frame = self.res.LoadFrame(None, 'mainFrame')
        self.panel = xrc.XRCCTRL(self.frame, 'panel')
        self.txtEscribiendo = xrc.XRCCTRL(self.panel, 'txtEscribiendo')
        self.txtEntrada = xrc.XRCCTRL(self.panel, 'txtEntrada')
        self.objHtml = xrc.XRCCTRL(self.panel, 'objHtml')
        self.frame.Bind(wx.EVT_CLOSE, self.OnClose, id=xrc.XRCID('mainFrame'))
        self.txtEntrada.SetFocus()
        self.txtEntrada.SetSelection(-1, -1)
        self.objHtml.AppendToPage('<p style="font-family: calibri, serif; font-size:14pt; font-style:italic">')
        self.frame.SetDimensions(int(estado["x"]), int(estado["y"]), int(estado["width"]), int(estado["height"]))
        self.frame.SetTitle(title)
        self.sock = escuchaUDP(host, port)
        self.crypto = crypto
        self.frame.Show()

    def OnClose(self, evt):
        self.finalize()
        evt.Skip()

    def finalize(self):
        estado["x"] = self.frame.GetPosition().x
        estado["y"] = self.frame.GetPosition().y
        estado["width"] = self.frame.GetSize().width
        estado["height"] = self.frame.GetSize().height
        EscribirFicheroIni(FIC_INI, estado)
        return True

if __name__ == '__main__':
    estado = LeerFicheroIni(FIC_INI)
    MI_NUMERO = estado["mi_numero"]
    host = obtieneIPLocal()
    #Para pruebas borrar despues
    host = '192.168.5.51'
    #host = '192.168.0.40'
    #Inicializamos la clase para encriptar los mensajes. Comun a todos los remitentes
    crypto = SimpleCrypt(INITKEY=host, CYCLES=3, BLOCK_SZ=25, KEY_ADV=5, KEY_MAGNITUDE=1)
    port = int(estado["puerto"])
    print host
    print obtieneIPLocal()

    app = chatUDPApp()
    app.MainLoop()
