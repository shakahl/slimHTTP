import ipaddress
import ssl, os, sys, random
from socket import *
try:
	from select import epoll, EPOLLIN
except:
	""" #!if windows
	Create a epoll() implementation that simulates the epoll() behavior.
	This so that the rest of the code doesn't need to worry weither or not epoll() exists.
	"""
	import select
	EPOLLIN = None
	class epoll():
		def __init__(self):
			self.sockets = {}
			self.monitoring = {}

		def unregister(self, fileno, *args, **kwargs):
			try:
				del(self.monitoring[fileno])
			except:
				pass

		def register(self, fileno, *args, **kwargs):
			self.monitoring[fileno] = True

		def poll(self, timeout=0.5, *args, **kwargs):
			try:
				return [[fileno, 1] for fileno in select.select(list(self.monitoring.keys()), [], [], timeout)[0]]
			except OSError:
				return []

class CertManager():
	def generate_key_and_cert(key_file, **kwargs):
		# TODO: Fallback is to use subprocess.Popen('openssl ....')
		#       since installing additional libraries isn't always possible.
		#       But a return of None is fine for now.
		try:
			from OpenSSL.crypto import load_certificate, load_privatekey, PKey, FILETYPE_PEM, TYPE_RSA, X509, X509Req, dump_certificate, dump_privatekey
			from OpenSSL._util import ffi as _ffi, lib as _lib
		except:
			return None

		"""
		Will join key and cert in the same .pem file if no cert_file is given.
		"""
		# https://gist.github.com/kyledrake/d7457a46a03d7408da31
		# https://github.com/cea-hpc/pcocc/blob/master/lib/pcocc/Tbon.py
		# https://www.pyopenssl.org/en/stable/api/crypto.html
		a_day = 60*60*24
		if not 'cert_file' in kwargs: kwargs['cert_file'] = None
		if not 'country' in kwargs: kwargs['country'] = 'SE'
		if not 'sate' in kwargs: kwargs['state'] = 'Stockholm'
		if not 'city' in kwargs: kwargs['city'] = 'Stockholm'
		if not 'organization' in kwargs: kwargs['organization'] = 'Evil Scientist'
		if not 'unit' in kwargs: kwargs['unit'] = 'Security'
		if not 'cn' in kwargs: kwargs['cn'] = 'server'
		if not 'email' in kwargs: kwargs['email'] = 'evil@scientist.cloud'
		if not 'expires' in kwargs: kwargs['expires'] = a_day*365
		if not 'key_size' in kwargs: kwargs['key_size'] = 4096
		if not 'ca' in kwargs: kwargs['ca'] = None

		priv_key = PKey()
		priv_key.generate_key(TYPE_RSA, kwargs['key_size'])
		serialnumber=random.getrandbits(64)

		if not kwargs['ca']:
			# If no ca cert/key was given, assume that we're trying
			# to set up a CA cert and key pair.
			certificate = X509()
			certificate.get_subject().C = kwargs['country']
			certificate.get_subject().ST = kwargs['state']
			certificate.get_subject().L = kwargs['city']
			certificate.get_subject().O = kwargs['organization']
			certificate.get_subject().OU = kwargs['unit']
			certificate.get_subject().CN = kwargs['cn']
			certificate.set_serial_number(serialnumber)
			certificate.gmtime_adj_notBefore(0)
			certificate.gmtime_adj_notAfter(kwargs['expires'])
			certificate.set_issuer(certificate.get_subject())
			certificate.set_pubkey(priv_key)
			certificate.sign(priv_key, 'sha512')
		else:
			# If a CA cert and key was given, assume we're creating a client
			# certificate that will be signed by the CA.
			req = X509Req()
			req.get_subject().C = kwargs['country']
			req.get_subject().ST = kwargs['state']
			req.get_subject().L = kwargs['city']
			req.get_subject().O = kwargs['organization']
			req.get_subject().OU = kwargs['unit']
			req.get_subject().CN = kwargs['cn']
			req.get_subject().emailAddress = kwargs['email']
			req.set_pubkey(priv_key)
			req.sign(priv_key, 'sha512')

			certificate = X509()
			certificate.set_serial_number(serialnumber)
			certificate.gmtime_adj_notBefore(0)
			certificate.gmtime_adj_notAfter(kwargs['expires'])
			certificate.set_issuer(kwargs['ca'].cert.get_subject())
			certificate.set_subject(req.get_subject())
			certificate.set_pubkey(req.get_pubkey())
			certificate.sign(kwargs['ca'].key, 'sha512')

		cert_dump = dump_certificate(FILETYPE_PEM, certificate)
		key_dump = dump_privatekey(FILETYPE_PEM, priv_key)

		if not os.path.isdir(os.path.abspath(os.path.dirname(key_file))):
			os.makedirs(os.path.abspath(os.path.dirname(key_file)))

		if not kwargs['cert_file']:
			with open(key_file, 'wb') as fh:
				fh.write(cert_dump)
				fh.write(key_dump)
		else:
			with open(key_file, 'wb') as fh:
				fh.write(key_dump)
			with open(kwargs['cert_file'], 'wb') as fh:
				fh.write(cert_dump)

		return priv_key, certificate

class ConfError(BaseException):
	def __init__(self, message):
		print(f'[Warn] {message}')

class DeliverHttp():
	def __init__(self, config=None):
		if not config: config = self.default_config()
		## If config doesn't pass inspection, raise the error message given by check_config()
		if (error_message := self.check_config(config)) is not True: raise error_message
		if not 'port' in config: config['port'] = 80
		if not 'addr' in config: config['addr'] = ''

		self.config = config

		self.sockets = {}
		self.sock = socket()
		self.sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
		self.sock.bind((config['addr'], config['port']))
		self.main_sock_fileno = self.sock.fileno()
		
		self.pollobj = epoll()
		self.pollobj.register(self.main_sock_fileno, EPOLLIN)

		self.sock.listen(10)
		# while drop_privileges() is None:
		# 	log('Waiting for privileges to drop.', once=True, level=5, origin='slimHTTP', function='http_serve')

	def log(self, *args, **kwargs):
		print('[LOG] '.join([str(x) for x in args]))

	def check_config(self, conf):
		if not 'web_root' in conf: return ConfError('Missing "web_root" in configuration.')
		if not 'index' in conf: return ConfError('Missing "index" in configuration.')
		if 'vhosts' in conf:
			for host in conf['vhosts']:
				if not 'web_root' in conf['vhosts'][host]: return ConfError(f'Missing "web_root" in vhost {host}\'s configuration.')
				if not 'index' in conf['vhosts'][host]: return ConfError(f'Missing "index" in vhost {host}\'s configuration.')
		return True

	def default_config(self):
		return {
			'web_root' : '/srv/http',
			'index' : 'index.html',
			'vhosts' : {
				
			},
			'port' : 80
		}

	def configuration(self, config=None, *args, **kwargs):
		if type(config) == dict:
			self.config = config
		elif config:
			staging_config = config(instance=self)
			if self.check_config(staging_config) is True:
				self.config = staging_config

	def method_GET(self, *args, **kwargs):
		pass#print(args, kwargs)

	def allow(self, allow_list, *args, **kwargs):
		staging_list = []
		for item in allow_list:
			if '/' in item:
				staging_list.append(ipaddress.ip_network(item, strict=False))
			else:
				staging_list.append(ipaddress.ip_address(item))
		self.allow_list = set(staging_list)
		return self.on_accept_callback

	def on_accept_callback(self, f, *args, **kwargs):
		self.on_accept = f

	def on_accept(self, *args, **kwargs):
		pass

	def on_close(self, f, *args, **kwargs):
		self.on_close_func = f

	def on_upgrade(self, f, *args, **kwargs):
		self.on_upgrade = f

	def on_upgrade_func(self, identity=None, *args, **kwargs):
		print('On upgrade:', identity, args, kwargs)

	def on_close_func(self, identity=None, *args, **kwargs):
		print('On close:', identity, args, kwargs)

	def poll(self, timeout=0.2):
		for socket, event_type in self.pollobj.poll(timeout):
			if socket == self.main_sock_fileno:
				ns, na = self.sock.accept()
				ip_address = ipaddress.ip_address(na[0])
				
				## Begin the allow/deny process
				allow = True
				if self.allow_list:
					allow = False
					for net in self.allow_list:
						if ip_address in net or ipaddress == net:
							allow = True
							break

				if not allow:
					print(na[0], 'not in allow_list')
					ns.close()
					continue

				
				print(ns, na)
			yield (event, obj)

class DeliverHttps(DeliverHttp):
	def __init__(self, config=None):
		if not config: config = self.default_config()
		DeliverHttp.__init__(self, config=config)

	def default_config(self):
		## TODO: generate cert if not existing.
		return {
			'web_root' : '/srv/http',
			'index' : 'index.html',
			'vhosts' : {
				
			},
			'port' : 443,
			'ssl' : {
				'cert' : 'cert.pem',
				'key' : 'key.pem'
			}
		}


HTTP = 0b0001
HTTPS = 0b0010
def host(mode=HTTPS, *args, **kwargs):
	"""
	host() is essentially just a router.
	It routes a mode and sets up a instance for serving HTTP or HTTPS.
	"""
	if mode == HTTPS:
		return DeliverHttps(*args, **kwargs)
	elif mode == HTTP:
		return DeliverHttp(*args, **kwargs)




from os.path import isfile, abspath
from mimetypes import guess_type # TODO: issue consern, doesn't handle bytes,
#								   requires us to decode the string before guessing type.
from json import dumps
from time import time, sleep
import importlib.util

def as_complex(o):
	if type(o) == bytes:
		return o.decode('UTF-8')
	return o

def drop_privileges():
	return True

class http_cliententity():
	def __init__(self, parent, sock, addr=None, on_close=None):
		self.info = {'addr' : addr}
		self.addr = addr

		self.data = b''

		self.upgraded = False
		self.keep_alive = False
		self.parent = parent
		self.socket = sock
		self.fileno = sock.fileno()
		self.id = self.info['addr'][0]

		if not on_close: on_close = self.close
		self.on_close = on_close

	def __repr__(self):
		return 'client[{}:{}]'.format(*self.info['addr'])

	def recv(self, buffert=8192):
		if self.parent.poll(fileno=self.socket.fileno()):
			try:
				d = self.socket.recv(buffert)
			#except ConnectionResetError:
			#	d = ''
			except: # There's to many errors that can be thrown here for the same reasons, SSL, OSError, Connection errors etc. They all mean the same thing, things broke and the client couldn't deliver data accordingly.
				d = ''
			if len(d) == 0:
				self.close()
				return None
			self.data += d
			return len(self.data)
		return None

	def close(self, *args, **kwargs):
		del(self.parent.sockets[self.fileno])
		self.parent.pollobj.unregister(self.fileno)
		self.socket.close()
		return True

	def send(self, d):
		self.respond(d)

	def respond(self, d):
		if d is None: d = b'HTTP/1.1 200 OK\r\n\r\n'

		if type(d) == dict: d = dumps(d)
		if type(d) != bytes: d = bytes(d, 'UTF-8')

		#print('>', d)
		try:
			self.socket.send(d)
		except OSError: # TODO: close socket and delete from poller
			return False
		return True

	def parse(self):
		return http_request(self, on_close=self.on_close).parse()

class http_serve():
	def __init__(self, modules={}, methods={}, upgrades={}, host='', port=80, on_close=None):
		self.sock = socket()
		self.sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
		self.sock.bind((host, port))
		self.ssl = False

		self.sockets = {}
		self.pollobj = epoll()
		self.modules = modules
		self.methods = methods
		self.upgrades = upgrades
		self.on_close = on_close

		while drop_privileges() is None:
			log('Waiting for privileges to drop.', once=True, level=5, origin='slimHTTP', function='http_serve')

		self.sock.listen(10)
		self.main_so_id = self.sock.fileno()
		self.pollobj.register(self.sock.fileno(), EPOLLIN)

	def accept(self, client_trap=http_cliententity):
		if self.poll(0.001, fileno=self.main_so_id):
			ns, na = self.sock.accept()
			if self.ssl:
				try:
					ns.do_handshake()
				except ssl.SSLError as e:
					## It's a notice, not a error. Started in Python3.7.2 - Not sure why.
					if e.errno == 1 and 'SSLV3_ALERT_CERTIFICATE_UNKNOWN' in e.args[1]:
						pass
			log('Accepting new client: {addr}'.format(**{'addr' : na[0]}), level=5, origin='slimHTTP', function='http_serve')
			ns_fileno = ns.fileno()
			if ns_fileno in self.sockets:
				self.sockets[ns_fileno].close()
				del self.sockets[ns_fileno]

			self.sockets[ns_fileno] = http_cliententity(self, ns, na, on_close=self.on_close)
			self.pollobj.register(ns_fileno, EPOLLIN)
			return self.sockets[ns_fileno]
		return None

	def poll(self, timeout=0.001, fileno=None):
		d = dict(self.pollobj.poll(timeout))
		if fileno: return d[fileno] if fileno in d else None
		return d

	def close(self, fileno=None):
		if fileno:
			try:
				log(f'closing fileno: {fileno}', level=5, origin='slimHTTP', function='http_serve')
				self.pollobj.unregister(fileno)
			except FileNotFoundError:
				pass # Already unregistered most likely.
			if fileno in self.sockets:
				self.sockets[fileno].close()
			return True
		else:
			for fileno in self.sockets:
				try:
					log(f'closing fileno: {fileno}', level=5, origin='slimHTTP', function='http_serve')
					self.pollobj.unregister(fileno)
					self.sockets[fileno].socket.close()
				except:
					pass
			self.pollobj.unregister(self.main_so_id)
			self.sock.close()

class https_serve(http_serve):
	def __init__(self, cert, key, *args, **kwargs):
		if not 'host' in kwargs: kwargs['host'] = ''
		if not 'port' in kwargs: kwargs['port'] = 443
		super(https_serve, self).__init__(*args, **kwargs)
		self.ssl = True
		self.pollobj.unregister(self.sock.fileno())

		context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
		context.load_cert_chain(cert, key)
		self.sock = context.wrap_socket(self.sock, server_side=True, do_handshake_on_connect=False)
		self.pollobj.register(self.sock.fileno(), EPOLLIN)

imported_paths = {}
def handle_py_request(path):
	old_version = False
	log(f'Request to "{path}"', level=4, origin='slimHTTP', function='handle_py_request')
	if path not in imported_paths:
		## https://justus.science/blog/2015/04/19/sys.modules-is-dangerous.html
		try:
			log(f'Loading : {path}', level=4, origin='slimHTTP')
			spec = importlib.util.spec_from_file_location(path, path)
			imported_paths[path] = importlib.util.module_from_spec(spec)
			spec.loader.exec_module(imported_paths[path])
			sys.modules[path] = imported_paths[path]
		except (SyntaxError, ModuleNotFoundError) as e:
			log(f'Failed to load file ({e}): {path}', level=2, origin='slimHTTP', function='handle_py_request')
			return None
	else:
		log(f'Reloading: {path}', level=4, origin='slimHTTP', function='handle_py_request')
		try:
			raise SyntaxError('https://github.com/Torxed/ADderall/issues/11')
		except SyntaxError as e:
			old_version = True
			log(f'Failed to reload requested file ({e}): {path}', level=2, origin='slimHTTP', function='handle_py_request')
	return old_version, imported_paths[f'{path}']

def get_file(root, path, headers={}, *args, **kwargs):
	real_path = abspath('{}/{}'.format(root, path))
	log('Trying to fetch "{}"'.format(real_path), level=5, origin='slimHTTP', function='get_file')
	if b'range' in headers:
		_, data_range = headers[b'range'].split(b'=',1)
		start, stop = [int(x) for x in data_range.split(b'-')]
		log('Limiting to range: {}-{}'.format(start, stop), level=5, origin='slimHTTP', function='get_file')
	else:
		start, stop = None, None

	extension = os.path.splitext(real_path)[1]

	if isfile(real_path) and extension != '.py':
		if not 'ignore_read' in kwargs or kwargs['ignore_read'] is False:
			with open(real_path, 'rb') as fh:
				if start:
					fh.seek(start)
				if stop:
					data = fh.read(stop-start)
				else:
					data = fh.read()
		else:
			data = b''
		
		filesize = os.stat(real_path).st_size
		log('Returning file content: {} (actual size: {})'.format(len(data), filesize), level=5, origin='slimHTTP', function='get_file')
		return real_path, filesize, data

	log(f'404 - Could\'t locate file {real_path}', level=3, origin='slimHTTP', function='get_file')

class http_request():
	def __init__(self, client, on_close=None):
		""" A dummy parser that will return 200 OK on everything. """
		self.client = client
		self.info = client.info
		self.headers = {}
		self.payload = b''
		self.methods = client.parent.methods
		self.ret_code = 200
		self.ret_data = {200 : b'HTTP/1.1 200 OK\r\n',
						 206 : b'HTTP/1.1 206 Partial Content\r\n',
						 302 : b'HTTP/1.1 302 Found\r\n',
						 404 : b'HTTP/1.1 404 Not Found\r\n'}
		self.ret_headers = {} # b'Content-Type' : 'plain/text' ?
		log('Setting up a parser for client: {}'.format(client), once=True, level=5, origin='slimHTTP', function='http_request')

		if len(self.methods) <= 0:
			log('No methods registered, using defaults.', once=True, level=5, origin='slimHTTP', function='http_request')
			self.methods = {} # Detach from parent map, otherwise we'll reuse old http_request() parsers
			self.methods[b'GET'] = self.GET
			self.methods[b'POST'] = self.POST
			self.methods[b'HEAD'] = self.HEAD
		else:
			self.methods = {b'GET' : self.GET, b'POST' : self.POST, b'HEAD' : self.HEAD, **self.methods}

		self.on_close = on_close

	def local_file(self, root, path, payload={}, headers={}, ignore_read=False, *args, **kwargs):
		extension = os.path.splitext(path)[1]
		if extension == '.py':
			if isfile(f'{root}/{path}'):
				response = handle_py_request(f'{root}/{path}')
				if response:
					old_version, handle = response

					response_data = handle.process(root=root, path=path, payload=payload, headers=headers, *args, **kwargs)
					if response_data:
						if len(response_data) == 1: response_data = {}, response_data # Assume payload, and pad with headers
						respond_headers, response = response_data

						if respond_headers:
							if b'_code' in respond_headers:
								self.ret_code = respond_headers[b'_code']
								del(respond_headers[b'_code']) # Ugly hack.. Don't like.. TODO! Fix!
							for header in respond_headers:
								self.ret_headers[header] = respond_headers[header]

							if not b'Content-Type' in respond_headers:
								self.ret_headers[b'Content-Type'] = b'text/html'

						else:
							self.ret_headers[b'Content-Type'] = b'text/html'
				else:
					response = b''
					self.ret_headers[b'Content-Type'] = b'plain/text'

				if not b'Content-Length' in self.ret_headers:
					self.ret_headers[b'Content-Length'] = bytes(str(len(response)), 'UTF-8')
				return response
			else:
				print(404)
				self.ret_code = 404
				data = None
		else:
			data = get_file(root, path, headers=headers, ignore_read=ignore_read)
			if data:
				path, length, data = data
				mime = guess_type(path)[0] #TODO: Deviates from bytes pattern. Replace guess_type()
				if not mime and path[-4:] == '.iso': mime = 'application/octet-stream'
				if b'range' in headers:
					_, data_range = headers[b'range'].split(b'=',1)
					start, stop = [int(x) for x in data_range.split(b'-')]
					self.ret_headers[b'Content-Range'] = bytes(f'bytes {start}-{stop}/{length}', 'UTF-8')
					self.ret_code = 206
				else:
					if mime == 'application/octet-stream':
						self.ret_headers[b'Accept-Ranges'] = b'bytes'

				self.ret_headers[b'Content-Type'] = bytes(mime, 'UTF-8') if mime else b'plain/text'
				self.ret_headers[b'Content-Length'] = bytes(str(len(data)), 'UTF-8')
			else:
				self.ret_code = 404
				data = None

		return data

	def PUT(self):
		return None

	def HEAD(self, request=None, headers={}, payload={}, root='./'):
		return self.local_file(root=root, path=headers[b'path'], headers=headers, payload=payload, ignore_read=True)

	def GET(self, request=None, headers={}, payload={}, root='./'):
		return self.local_file(root=root, path=headers[b'path'], headers=headers, payload=payload)

	def POST(self, request=None, headers={}, payload={}, root='./'):
		return self.local_file(root=root, path=headers[b'path'], headers=headers, payload=payload)

	def build_headers(self):
		x = b''
		if self.ret_code in self.ret_data:
			x += self.ret_data[self.ret_code]# + self.build_headers() + (response if response else b'')
		else:
			return b'HTTP/1.1 500 Internal Server Error\r\n\r\n'

		for key, val in self.ret_headers.items():
			if type(key) != bytes: key = bytes(key, 'UTF-8')
			if type(val) != bytes: val = bytes(val, 'UTF-8')
			x += key + b': ' + val + b'\r\n'
		
		return x + b'\r\n'

	def parse(self):
		# self.client.data is the client data.
		# it is inehrited by the client() class and
		# updated in real time.
		if b'\r\n\r\n' in self.client.data:
			header, self.payload = self.client.data.split(b'\r\n\r\n') # Copy and split the data so we're not working on live data.
			method, header = header.split(b'\r\n',1)
			for item in header.split(b'\r\n'):
				if b':' in item:
					key, val = item.split(b':',1)
					self.headers[key.strip().lower()] = val.strip()

			method, path, proto = method.split(b' ', 2)
			path_payload = {}
			if b'?' in path:
				path, payload = path.split(b'?', 1)
				for item in payload.split(b'&'):
					if b'=' in item:
						k, v = item.split(b'=',1)
						path_payload[k.lower()] = v

			self.headers[b'path'] = path.decode('UTF-8')
			self.headers[b'method'] = method
			self.headers[b'path_payload'] = path_payload

			web_root = config['slimhttp']['web_root']
			if b'host' in self.headers and 'vhosts' in config['slimhttp'] and self.headers[b'host'].decode('UTF-8') in config['slimhttp']['vhosts']:
				if 'web_root' in config['slimhttp']['vhosts'][self.headers[b'host'].decode('UTF-8')]:
					web_root = config['slimhttp']['vhosts'][self.headers[b'host'].decode('UTF-8')]['web_root']

			if self.headers[b'path'][-1] == '/':
				vhost_specific_index = False
				if b'host' in self.headers and 'vhosts' in config['slimhttp'] and self.headers[b'host'].decode('UTF-8') in config['slimhttp']['vhosts']:
					if 'index' in config['slimhttp']['vhosts'][self.headers[b'host'].decode('UTF-8')]:
						index_files = config['slimhttp']['vhosts'][self.headers[b'host'].decode('UTF-8')]['index']
						if type(index_files) == str:
							self.headers[b'path'] += index_files
							vhost_specific_index = True
						elif type(index_files) in (list, tuple):
							for file in index_files:
								if isfile(web_root + '/' + self.headers[b'path'] + file):
									self.headers[b'path'] += file
									vhost_specific_index = True
									break

				if not vhost_specific_index:
					if type(config['slimhttp']['index']) == str:
						self.headers[b'path'] += config['slimhttp']['index']
					elif type(config['slimhttp']['index']) in (list, tuple):
						for index in config['slimhttp']['index']:
							if isfile(web_root + '/' + index):
								self.headers[b'path'] += index
								break

					#self.headers[b'upgrade'].lower() == b'websocket' and \
			if b'upgrade' in self.headers and b'connection' in self.headers and \
					b'upgrade' in self.headers[b'connection'].lower() and \
					self.headers[b'upgrade'].lower() in self.client.parent.upgrades:
				log('{} wants to upgrade with {}'.format(self.client, self.headers[b'upgrade']), level=5, origin='slimHTTP', function='parse')
				upgraded = self.client.parent.upgrades[self.headers[b'upgrade'].lower()].upgrade(self.client, self.headers, self.payload, self.on_close)
				if upgraded:
					log('Client has been upgraded!', level=5, origin='slimHTTP', function='parse')
					self.client.parent.sockets[self.client.socket.fileno()] = upgraded

			elif method in self.methods:
				if b'host' in self.headers:
					host = self.headers[b'host'].decode('UTF-8')
				else:
					host = 'default'
				log('{} sent a "{}" request to path "[{}/]{} @ {}"'.format(self.client, method.decode('UTF-8'), web_root,self.headers[b'path'], host), once=True, level=5, origin='slimHTTP', function='parse')
				response = self.methods[method](request=self, headers=self.headers, payload=self.payload, root=web_root)
				if type(response) == dict: response = dumps(response)
				if type(response) == str: response = bytes(response, 'UTF-8')
				return self.build_headers() + response if response else self.build_headers()
			else:
				log('Can\'t handle {} method.'.format(method), once=True, level=2, origin='slimHTTP', function='parse')
		else:
			log('Not enough data yet.', once=True, level=1, origin='slimHTTP', function='parse')

		return None
