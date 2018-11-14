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
MI_CLAVE = ''
estado = {}
contactos = {}
ventanas = {}
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
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
            print ("Exception due to " + value)
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

def crearVentanaChat(ipDestino, puertoDestino):
	if not ipDestino in ventanas.keys():
		ventanas[ipDestino] = chat(None, ipDestino, 'Chat a ' + ipDestino + ' en el puerto ' + str(puertoDestino))
    
def LeerFicheroIni(fichero):
    config = ConfigParser.ConfigParser()
    estadoAux = {}
    contactoAux = {}
    if config.read(fichero):
        for clave in config.items(SECCION_INI):
            estadoAux[clave[0]] = config.get(SECCION_INI, clave[0])
        for clave in config.items(SECCION_CON):
            contactoAux[clave[0]] = config.get(SECCION_CON, clave[0])
    else:
        print("NO encuentro el fichero ")
    return estadoAux, contactoAux

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
	envioPendiente = False
	cryptoEnvio = None
	lineasHtml = 0

	def __init__(self, parent, id, title):
		self.destino = id
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
		self.crypto = crypto
		self.txtEntrada.Bind(wx.EVT_KEY_UP, self.OnKey)
		self.cryptoEnvio = SimpleCrypt(INITKEY=id, CYCLES=3, BLOCK_SZ=25, KEY_ADV=5, KEY_MAGNITUDE=1)
		self.send_address = (id, port)
		self.frame.Show()

	def OnClose(self, evt):
		self.finalize()
		evt.Skip()
		
	def OnKey(self, evt):
		code = evt.GetKeyCode()

		if code == wx.WXK_LEFT:
			self.objHtml.AppendToPage(unicode('izquierda <br />'))
		elif code in (wx.WXK_RETURN, 370):
			textoHTML = time.strftime("%H:%M:%S") + u' <strong><font face="dejavu sans" color="brown">T\xfa</font></strong>> ' + self.txtEntrada.GetValue() + '<br />'
			self.objHtml.AppendToPage(unicode(textoHTML))
			self.lineasHtml = self.lineasHtml + 1 
			self.objHtml.Scroll(0, self.lineasHtml)
			self.envioDatagrama(False)
			self.txtEntrada.SetValue('')
		elif code == wx.WXK_ESCAPE:
			self.frame.Close()
			#wx.GetApp().ExitMainLoop()
		else:
			self.envioPendiente = True
		evt.Skip()

	def OnText(self, evt):
		usuarioCadena = self.txtEntrada.GetValue()
		if len(usuarioCadena) == 0:
			self.txtEscribiendo.SetValue(unicode(''))
		if len(usuarioCadena) >= 1:
			usuarioCadena = usuarioCadena.encode("iso-8859-1")
			self.txtEscribiendo.SetValue(unicode(usuarioCadena+chr(95)))
		evt.Skip()

	def envioDatagrama(self, pulsacion):
		usuarioCadena = self.txtEntrada.GetValue()
		if len(usuarioCadena) >= 1:
			usuarioCadena = self.cryptoEnvio.Encrypt(usuarioCadena.encode('utf-8')).encode('hex').encode('utf-8')
			if pulsacion:
				usuarioCadena = usuarioCadena + chr(95)
		sock.sendto(usuarioCadena, self.send_address)
		self.envioPendiente = False

	def finalize(self):
		#estado["x"] = self.frame.GetPosition().x
		#estado["y"] = self.frame.GetPosition().y
		#estado["width"] = self.frame.GetSize().width
		#estado["height"] = self.frame.GetSize().height
		#EscribirFicheroIni(FIC_INI, estado)
		print ventanas.keys()
		del ventanas[self.destino]
		return True
		
	def mensajeRecibido(self, msg):
		if len(msg) == 0:
			self.txtEscribiendo.SetValue(unicode(''))
		elif msg[-1] == chr(95):
			msg = msg[:len(msg)-1]
			msg = self.cryptoEnvio.Decrypt(msg.decode('utf-8').decode('hex'))
			self.txtEscribiendo.SetValue(unicode(msg.decode('utf-8')))
		else:
			msg = self.cryptoEnvio.Decrypt(msg.decode('utf-8').decode('hex'))
			textoHTML = time.strftime("%H:%M:%S") + ' <strong><font face="helvetica" color="green">' + contactos[self.destino] + '</font></strong>> ' + msg.decode('utf-8') + '<br />'
			self.txtEscribiendo.SetValue(unicode(''))
			self.objHtml.AppendToPage(unicode(textoHTML))
			self.lineasHtml = self.lineasHtml + 1 
			self.objHtml.Scroll(0, self.lineasHtml)

class chatUDPApp(wx.App):
	def initialize(self):
		self.timer = wx.Timer(self)
		self.Bind(wx.EVT_TIMER, self.OnTimer, self.timer)
		self.timer.Start(100)
		self.crypto = crypto
		self.frame = principal(None, -1, 'Chat de ' + contactos[host] + ' escuchando en el puerto ' + estado["puerto"])
		#self.frame.Bind(wx.EVT_KEY_UP, self.OnKey)
		root = self.frame.objTree.AddRoot('Contactos')
		for contacto in contactos:
			os = self.frame.objTree.AppendItem(root, contactos[contacto])
			self.frame.objTree.SetPyData(os, contacto)
		self.frame.objTree.Expand(root)
		#self.frame = chat(None, -1, 'Chat a ' + host + ' escuchando en el puerto ' + estado["puerto"])
		return True

	def OnInit(self):
		self.initialize()
		return True

	def OnKey(self, evt):
		code = evt.GetKeyCode()
		print code
		if code == wx.WXK_LEFT:
			print "Left"
		elif code == wx.WXK_ESCAPE:
			self.finalize()
			wx.GetApp().ExitMainLoop()
		evt.Skip()

	def onMinimize(self, event):
		a = 0

	def OnClose(self, evt):
		self.finalize()
		evt.Skip()
		
	def OnSelChanged(self, event):
		'''Method called when selected item is changed
		'''
		item =  event.GetItem()
		# Display the selected item text in the text widget
		self.display.SetLabel(self.tree.GetItemText(item))

	def OnTimer(self, event):
		
		message = None
		try:
			# Buffer size is 8192. Change as needed.
			message, address = sock.recvfrom(8192)
		except:
			pass
			
		if message != None:
			crearVentanaChat(address[0], address[1])
			if message:
				ventanas[address[0]].mensajeRecibido(message)
				
		#Ahora enviamos el texto si hemos pulsado alguna tecla
		for ip,ventana in ventanas.iteritems():
			if ventana.envioPendiente:
				ventana.envioDatagrama(True)

	def finalize(self):
		# Guarda las coordenadas de la ventana principal
		estado["x"] = self.frame.GetPosition().x
		estado["y"] = self.frame.GetPosition().y
		estado["width"] = self.frame.GetSize().width
		estado["height"] = self.frame.GetSize().height
		EscribirFicheroIni(FIC_INI, estado)

		self.timer.Stop()
		sock.close()
		self.frame.finalize()
		return True

class principal(wx.Frame):
	def __init__(self, parent, id, title):
		self.res = xrc.XmlResource('principal.xrc')
		self.frame = self.res.LoadFrame(None, 'mainFrame')
		self.panel = xrc.XRCCTRL(self.frame, 'panel')
		self.objTree = xrc.XRCCTRL(self.frame, 'objTree')
		self.frame.Bind(wx.EVT_CLOSE, self.OnClose)
		self.objTree.Bind(wx.EVT_TREE_SEL_CHANGED, self.OnSelChanged)
		self.objTree.Bind(wx.EVT_KEY_UP, self.OnKey)
		self.frame.SetDimensions(int(estado["x"]), int(estado["y"]), int(estado["width"]), int(estado["height"]))
		self.frame.SetTitle(title)
		self.frame.Show()


	def OnClose(self, evt):
		self.finalize()
		evt.Skip()
		
	def OnKey(self, evt):
		code = evt.GetKeyCode()
		if code == wx.WXK_ESCAPE:
			self.finalize()
			wx.GetApp().ExitMainLoop()
		evt.Skip()

	def finalize(self):
		estado["x"] = self.frame.GetPosition().x
		estado["y"] = self.frame.GetPosition().y
		estado["width"] = self.frame.GetSize().width
		estado["height"] = self.frame.GetSize().height
		EscribirFicheroIni(FIC_INI, estado)
		return True
		
	def OnSelChanged(self, evt):
		item =  evt.GetItem()
		ip = self.objTree.GetPyData(item)
		# abrimos la ventana con la ip de contactos
		crearVentanaChat(ip, int(3333))
		evt.Skip()

if __name__ == '__main__':
    estado, contactos = LeerFicheroIni(FIC_INI)
    MI_NUMERO = estado["mi_numero"]
    host = obtieneIPLocal()
    #Para pruebas borrar despues
    #host = '192.168.5.51'
    #host = '192.168.0.40'
    #La clave por defecto es la IP
    MI_CLAVE = estado ["mi_clave"]
    if len(MI_CLAVE) == 0:
        MI_CLAVE = host
    #Inicializamos la clase para encriptar los mensajes. Comun a todos los remitentes
    crypto = SimpleCrypt(INITKEY=host, CYCLES=3, BLOCK_SZ=25, KEY_ADV=5, KEY_MAGNITUDE=1)
    port = int(estado["puerto"])
    sock = escuchaUDP(host, port)
    print host
    print obtieneIPLocal()

    app = chatUDPApp(0)
    app.MainLoop()
