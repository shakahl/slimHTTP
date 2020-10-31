import ssl, os, sys, random, json, glob
import ipaddress
import importlib.util, traceback
from os.path import isfile, abspath
from json import dumps
from time import time#, sleep
from mimetypes import guess_type # TODO: issue consern, doesn't handle bytes,
								 # requires us to decode the string before guessing type.
try:
	from OpenSSL.crypto import load_certificate, SSL, crypto, load_privatekey, PKey, FILETYPE_PEM, TYPE_RSA, X509, X509Req, dump_certificate, dump_privatekey
	from OpenSSL._util import ffi as _ffi, lib as _lib
except:
	class MOCK_CERT_STORE():
		def __init__(self):
			pass
		def add_cert(self, *args, **kwargs):
			pass

	class SSL():
		"""
		This is *not* a crypto implementation!
		
		This is a mock class to get the native lib `ssl` to behave like `PyOpenSSL.SSL`.
		The net result should be a transparent experience for programmers by default opting out of `PyOpenSSL`.

		.. warning::

			PyOpenSSL is optional, but certain expectations of behavior might be scewed if you don't have it.
			Most importantly, some flags will have no affect unless the optional dependency is met - but the behavior
			of the function-call should remain largely the same.

		"""
		TLSv1_2_METHOD = 0b110
		VERIFY_PEER = 0b1
		VERIFY_FAIL_IF_NO_PEER_CERT = 0b10
		MODE_RELEASE_BUFFERS = 0b10000
		def __init__(self):
			self.key = None
			self.cert = None
		def Context(*args, **kwargs):
			return SSL()
		def set_verify(self, *args, **kwargs):
			pass
		def set_verify_depth(self, *args, **kwargs):
			pass
		def use_privatekey_file(self, path, *args, **kwargs):
			self.key = path
		def use_certificate_file(self, path, *args, **kwargs):
			self.cert = path
		def set_default_verify_paths(self, *args, **kwargs):
			pass
		def set_mode(self, *args, **kwargs):
			pass
		def load_verify_locations(self, *args, **kwargs):
			pass
		def get_cert_store(self, *args, **kwargs):
			return MOCK_CERT_STORE()
		def Connection(context, socket):
			if type(context) == SSL:
				new_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
				new_context.load_cert_chain(context.cert, context.key)
				context = new_context
			return context.wrap_socket(socket, server_side=True)

from socket import *
try:
	from select import epoll, EPOLLIN
except:
	import select
	EPOLLIN = None
	class epoll():
		""" #!if windows
		Create a epoll() implementation that simulates the epoll() behavior.
		This so that the rest of the code doesn't need to worry weither we're using select() or epoll().
		"""
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

		def poll(self, timeout=0.05, *args, **kwargs):
			try:
				return [[fileno, 1] for fileno in select.select(list(self.monitoring.keys()), [], [], timeout)[0]]
			except OSError:
				return []

def splitall(path):
	"""
	`os.path.split` but splits the entire path
	into a list of individual pieces.
	Essentially a `str.split('/')` but OS independent.

	More or less a solution for of https://stackoverflow.com/questions/3167154/how-to-split-a-dos-path-into-its-components-in-python
	based on the answer here: https://stackoverflow.com/a/22444703/929999

	Another proposed solution would be (https://stackoverflow.com/a/16595356/929999):
		path = os.path.normpath(path)
		path.split(os.sep)

	Down-side is the empty entry for /root/test.txt but not for C:\root\test.txt
	(inconsistency)

	:param path: A *Nix or Windows path
	:type path: str

	:return: A list of the paths element, where the root will be '/' or 'C:\\' depending on platform.
	:rtype: str
	"""
	allparts = []
	while 1:
		parts = os.path.split(path)
		if parts[0] == path:  # sentinel for absolute paths
			allparts.insert(0, parts[0])
			break
		elif parts[1] == path: # sentinel for relative paths
			allparts.insert(0, parts[1])
			break
		else:
			path = parts[0]
			allparts.insert(0, parts[1])
	return allparts
os.path.splitall = splitall

def safepath(root, path):
	"""
	Attempts to make a path safe, as well as remove any traces of
	the current working directory after resolve to keep relative paths intact.

	:param root: The "jail" in which to constrain the path too
	:type root: str

	:param path: The relative or absolute path from root
	:type path: str

	:return: A safe(root+clean(path)) joined string representation of path
	:rtype: str
	"""
	root_abs = os.path.abspath(root)
	path_abs = os.path.abspath(os.path.join(*os.path.splitall(path)[1:]))
	cwd = os.getcwd()

	# Check if the resolved requested path shares a common pathway with the current working directory.
	# And if so, strip it away because the next os.path.join() will mess things up otherwise.
	common_pathway = os.path.commonprefix([cwd, path_abs])
	if common_pathway:
		path_abs = path_abs[len(common_pathway):]

		# If the new path doesn't start with / we'll have to add it
		# otherwise the next splitall() will assume the wrong thing.
		# And that assumption is important to not mess up other normal paths that will start with /
		start_of_abs_path = os.path.splitall(path_abs)[0]
		if start_of_abs_path[0] not in ('\\', '.', '/') and ':\\' not in start_of_abs_path:
			path_abs = os.path.join('/', start_of_abs_path)

	# Safely join the root and path (minus the leading / of path)
	return os.path.join(root_abs, *os.path.splitall(path_abs)[1:])
os.path.safepath = safepath

GLOBAL_POLL_TIMEOUT = 0.001
MAX_MEM_ALLOC = 1024*50
HTTP = 0b0001
HTTPS = 0b0010
instances = {}
def server(mode=HTTPS, *args, **kwargs):
	"""
	server() is essentially just a router to the appropriate class for the mode selected.
	It will create a instance of :ref:`~slimHTTP.HTTP_SERVER` or :ref:`~slimHTTP.HTTPS_SERVER` based on `mode`.

	:param mode: Which mode to instanciate (`1` == HTTP, `2` == HTTPS)
	:type mode: int

	:return: A instance corresponding to the `mode` selected
	:rtype: :ref:`~slimHTTP.HTTP_SERVER` or :ref:`~slimHTTP.HTTPS_SERVER`
	"""
	if mode == HTTPS:
		instance = HTTPS_SERVER(*args, **kwargs)
	elif mode == HTTP:
		instance = HTTP_SERVER(*args, **kwargs)
		
	instances[f'{instance.config["addr"]}:{instance.config["port"]}'] = instance
	return instance

def host(*args, **kwargs):
	"""
	Legacy function, re-routes to server()
	"""
	print('[Warn] Deprecated function host() called, use server(mode=<mode>) instead.')
	return server(*args, **kwargs)

def drop_privileges():
	"""
	#TODO: implement

	Drops the startup privileges to a more suitable production privilege.

	:return: The result of the priv-drop
	:rtype: bool
	"""
	return True

def UTF8_DICT(d):
	result = {}
	for key, val in d.items():
		if type(key) == bytes: key = key.decode('UTF-8')
		if type(val) == bytes: val = val.decode('UTF-8')
		result[key] = val
	return result

class FILE():
	"""
	Whenever a file is to be delivered back, this helper class
	can make some return codes and headers easier to use.

	Simply put, a class-instance of this class will be yielded
	up the event chain, picked up and `.data` or `.chunk` will be
	returned to the client/user.

	:param request: The request object for the current triggering request
	:type request: :ref:`~slimHTTP.HTTP_REQUEST`

	:param path: The path to the file requested
	:type path: str
	"""
	def __init__(self, request, path):
		# TODO: Grab the path from the request object?
		self.request = request
		self._path = path
		self.fh = None
		self.headers_sent = False
		
		if os.path.isfile(self.path):
			self.request.ret_code = 200
			self.size = os.stat(self.path).st_size
		else:
			self.request.ret_code = 404
			self.size = -1

	def __repr__(self):
		return f'<slimHTTP.FILE object "{self.path}" at {id(self)}>'

	def __enter__(self, *args, **kwargs):
		"""
		Opens the requested file in a context mode if not already opened.
		Will automatically be closed by exiting the context *(__exit__)*.

		:return: The `FILE()` instance itself
		:rtype: :ref:`~slimHTTP.FILE`
		"""
		if not os.path.isfile(self.path): return self
		if not self.fh: self.fh = open(self.path, 'rb')

		return self

	def __exit__(self, *args, **kwargs):
		if self.fh:
			self.fh.close()

	@property
	def mime(self):
		"""
		Returns the guessed mime-type of the requested file.
		Certain file-ending specifics are also implemented due to the lack
		of support from the builting `mimetype.guess_type` library.

		:return: The mime-type of the file-ending of the requested file
		:rtype: str
		"""
		mime = guess_type(self.path)[0] #TODO: Deviates from bytes pattern. Replace guess_type()
		if not mime and self.path[-4:] == '.iso': mime = 'application/octet-stream'
		return mime

	@property
	def headers(self):
		"""
		The headers needed for the corresponding requested file.

		:return: A dictionary of headers needed to deliver the file safely.
		:rtype: dict
		"""
		return {
			b'Content-Type' : bytes(self.mime, 'UTF-8') if self.mime else b'plain/text',
			b'Content-Length' : str(self.size)
		}

	@property
	def path(self):
		"""
		An absolute path of the requested path.

		:return: A `os.path.abspath` rendering.
		:rtype: str
		"""
		return os.path.abspath(self._path)
	
	@property
	def data(self, size=-1):
		"""
		Returns the entierty of the requested file.
		Does take an optional parameter of `size` to limit the ammount of data returned.

		:param size: Limits the ammount of data returned
		:type size: int

		:return: The contents of the file in byte-representation
		:rtype: bytes
		"""
		if not self.fh: return None
		yield self.fh.read(size)

	@property
	def chunk(self, size=-1):
		"""
		Returns the entierty of the requested file.
		Does take an optional parameter of `size` to limit the ammount of data returned.

		:param size: Limits the ammount of data returned
		:type size: int

		:return: The contents of the file in byte-representation
		:rtype: bytes
		"""
		if not self.fh: return None
		return self.fh.read(size)

class STREAM_CHUNKED(FILE):
	"""
	Behaves in similar fasion to :ref:`~slimHTTP.FILE`, but also supports
	streaming content. It keeps track of the current position of the file
	as well as implements `.data` and `.chunk` into two different methods.

	.. note::

	    This class has not been tested with streaming content. Only large files.

	:param request: The current :ref:`~slimHTTP.HTTP_REQUEST` object from the client
	:type request: :ref:`~slimHTTP.HTTP_REQUEST`

	:param path: The path to the file requested
	:type path: str
	"""
	def __init__(self, request, path, start=0, chunksize=MAX_MEM_ALLOC):
		super(STREAM_CHUNKED, self).__init__(request, path)
		if not 'STREAM_CHUNKED' in request.session_storage:
			request.session_storage['STREAM_CHUNKED'] = self
			self.headers_sent = False
			self.chunksize = chunksize
		else:
			if not start: start = request.session_storage['STREAM_CHUNKED'].pos
			self.headers_sent = request.session_storage['STREAM_CHUNKED'].headers_sent
			self.chunksize = request.session_storage['STREAM_CHUNKED'].chunksize

		self.pos = start
		self.EOF = False
		# self.ret_code = 206

	def __repr__(self):
		return f'<slimHTTP.STREAM_CHUNKED object "{self.path}" at {id(self)}>'

	def __enter__(self, *args, **kwargs):
		if not self.fh: self.fh = open(self.path, 'rb')

		self.fh.seek(self.pos)
		return self

	def __exit__(self, *args, **kwargs):
		if self.pos >= self.size:
			self.fh.close()
			self.fh = None

	@property
	def headers(self):
		return {
			b'Content-Type' : bytes(self.mime, 'UTF-8') if self.mime else b'plain/text',
			#b'Content-Length' : str(self.size),
			b'Transfer-Encoding' : b'chunked'
		}

	@property
	def data(self):
		while self.fh.tell() < self.size:
			self.pos += self.chunksize # Safe to move forward before yielding due to __enter__
			yield self.fh.read(self.chunksize)

	@property
	def chunk(self):
		self.pos += self.chunksize
		chunk = self.fh.read(self.chunksize)
		if len(chunk) <= 0:
			self.EOF = True
		return chunk

class CertManager():
	"""
	CertManager() is a class to handle creation of certificates.
	It attempts to use the *optional* PyOpenSSL library, if that fails,
	the backup option is to attempt a subprocess.Popen() call to openssl.

	.. warning::

	    Work in progress, most certanly contains errors and issues if *(optionally)* PyOpenSSL isn't present.
	"""
	def generate_key_and_cert(key_file, **kwargs):
		# TODO: Fallback is to use subprocess.Popen('openssl ....')
		#       since installing additional libraries isn't always possible.
		#       But a return of None is fine for now.
		try:
			from OpenSSL.crypto import load_certificate, SSL, crypto, load_privatekey, PKey, FILETYPE_PEM, TYPE_RSA, X509, X509Req, dump_certificate, dump_privatekey
			from OpenSSL._util import ffi as _ffi, lib as _lib
		except:
			return None

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

class InvalidFrame(BaseException):
	pass

class slimHTTP_Error(BaseException):
	pass

class ModuleError(BaseException):
	def __init__(self, message, path):
		print(f'[Error] {message} in {path}')
		self.message = message
		self.path = path

class ConfError(BaseException):
	def __init__(self, message):
		print(f'[Warn] {message}')

class NotYetImplemented(BaseException):
	def __init__(self, message):
		print(f'[Warn] {message}')

class UpgradeIssue(BaseException):
	def __init__(self, message):
		print(f'[Error] {message}')

class Events():
	"""
	Events.<CONST> is a helper class to indicate which event is triggered.
	Events are passed up through the event chain deep from within slimHTTP.

	These events can be caught in your main `.poll()` loop, and react to different events.
	"""
	SERVER_ACCEPT = 0b10000000
	SERVER_CLOSE = 0b10000001
	SERVER_RESTART = 0b00000010

	CLIENT_DATA = 0b01000000
	CLIENT_REQUEST = 0b01000001
	CLIENT_RESPONSE_DATA = 0b01000010
	CLIENT_UPGRADED = 0b01000011
	CLIENT_UPGRADE_ISSUE = 0b01000100
	CLIENT_URL_ROUTED = 0b01000101
	CLIENT_DATA_FRAGMENTED = 0b01000110
	CLIENT_RESPONSE_PROXY_DATA = 0b01000111

	WS_CLIENT_DATA = 0b11000000
	WS_CLIENT_REQUEST = 0b11000001
	WS_CLIENT_COMPLETE_FRAME = 0b11000010
	WS_CLIENT_INCOMPLETE_FRAME = 0b11000011
	WS_CLIENT_ROUTED = 0b11000100

	NOT_YET_IMPLEMENTED = 0b00000000
	INVALID_DATA = 0b00000001

	DATA_EVENTS = (CLIENT_RESPONSE_DATA, CLIENT_URL_ROUTED, CLIENT_RESPONSE_PROXY_DATA)

	def convert(_int):
		def_map = {v: k for k, v in Events.__dict__.items() if not k.startswith('__') and k != 'convert'}
		return def_map[_int] if _int in def_map else None

class _Sys():
	modules = {}
	specs = {}
class VirtualStorage():
	"""
	A virtual storage to simulate `sys.modules` but instead be accessed with
	`internal.sys.storage` for a internal *"sys"* reference bound to the slimHTTP session.
	"""
	def __init__(self):
		self.sys = _Sys()
		self.storage = {}
internal = VirtualStorage()

class Imported():
	"""
	A wrapper for `import <module>` that instead works like `Imported(<module>)`.
	It also supports absolute paths, as well as context management:

	.. code-block::python

        with Imported('/path/to/time.py') as time:
            time.time()

	.. warning::

	    Each time the `Imported()` is contextualized, it reloads the source code.
	    Any data saved in the previous instance will get wiped, for the most part.
	"""
	def __init__(self, path, namespace=None):
		if not namespace:
			namespace = os.path.splitext(os.path.basename(path))[0]
		self.namespace = namespace

		self._path = path
		self.spec = None
		self.imported = None
		if namespace in internal.sys.modules:
			self.imported = internal.sys.modules[namespace]
			self.spec = internal.sys.specs[namespace]

	def __repr__(self):
	#	if self.imported:
	#		return self.imported.__repr__()
	#	else:
		return f"<loaded-module '{os.path.splitext(os.path.basename(self._path))[0]}' from '{self.path}' (Imported-wrapped)>"

	def __enter__(self, *args, **kwargs):
		"""
		Opens a context to the absolute-module.
		Errors are caught and through as a :ref:`~slimHTTP.ModuleError`.

		.. warning::
		
			It will re-load the code and thus re-instanciate the memory-space for the module.
			So any persistant data or sessions **needs** to be stowewd away between imports.
			Session files *(`pickle.dump()`)* is a good option *(or god forbid, `__builtins__['storage'] ...` is an option for in-memory stuff)*.
		"""

		# import_id = uniqueue_id()
		# virtual.sys.modules[absolute_path] = Imported(self.CLIENT_IDENTITY.server, absolute_path, import_id, spec, imported)
		# sys.modules[import_id+'.py'] = imported
		if not self.spec and not self.imported:
			self.spec = internal.sys.specs[self.namespace] = importlib.util.spec_from_file_location(self.namespace, self.path)
			self.imported = internal.sys.modules[self.namespace] = importlib.util.module_from_spec(self.spec)

		try:
			self.spec.loader.exec_module(self.imported)
		except Exception as e:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			raise ModuleError(traceback.format_exc(), self.path)

		return self.imported

	def __exit__(self, *args, **kwargs):
		# TODO: https://stackoverflow.com/questions/28157929/how-to-safely-handle-an-exception-inside-a-context-manager
		if len(args) >= 2 and args[1]:
			if len(args) >= 3:
				fname = os.path.split(args[2].tb_frame.f_code.co_filename)[1]
				print(f'Fatal error in Imported({self.path}), {fname}@{args[2].tb_lineno}: {args[1]}')
			else:
				print(args)

	@property
	def path(self):
		return os.path.abspath(self._path)

class ROUTE_HANDLER():
	"""
	Stub function that will act as a gateway between
	@http.<function> and the in-memory route that is stored.

	I might be using annotations wrong, but this will store
	a route (/url/something) and connect it with a given function
	by the programmer.
	"""
	def __init__(self, route):
		self.route = route
		self.parser = None

	def gateway(self, f):
		self.parser = f

class HTTP_RESPONSE():
	"""
	Forms a HTTP response to the requesting client.
	This class is usually used by `GET` or `POST` functions.
	Or if a `.py` module is called, the return from the `on_request` function
	within the `.py` module could potentially be a `HTTP_RESPONSE`.

	slimHTTP is designed to recognize a `HTTP_RESPONSE` object, and automatically
	send the `HTTP_RESPONSE.build()` to the end user.

	:param headers: Any initial headers to load the response with (optional)
	:type headers: dict

	:param payload: The payload to supply the user with
	:type payload: bytes
	"""
	def __init__(self, headers={}, payload=b'', *args, **kwargs):
		self.headers = headers
		self.payload = payload
		self.args = args
		self.kwargs = kwargs
		if not 'ret_code' in self.kwargs: self.kwargs['ret_code'] = 200

		self.ret_code_mapper = {200 : b'HTTP/1.1 200 OK\r\n',
								204 : b'HTTP/1.1 204 No Content\r\n',
								206 : b'HTTP/1.1 206 Partial Content\r\n',
								301 : b'HTTP/1.0 301 Moved Permanently\r\n',
								307 : b'HTTP/1.1 307 Temporary Redirect\r\n',
								302 : b'HTTP/1.1 302 Found\r\n',
								404 : b'HTTP/1.1 404 Not Found\r\n',
								418 : b'HTTP/1.0 I\'m a teapot\r\n'}

	def build_headers(self, additional_headers={}):
		x = b''
		if 'ret_code' in self.kwargs and self.kwargs['ret_code'] in self.ret_code_mapper:
			x += self.ret_code_mapper[self.kwargs['ret_code']]
		else:
			return b'HTTP/1.1 500 Internal Server Error\r\n\r\n'

		if not 'content-length' in [key.lower() for key in self.headers.keys()]:
			self.headers['Content-Length'] = str(len(self.payload))

		for key, val in {**self.headers, **additional_headers}.items():
			if type(key) != bytes: key = bytes(key, 'UTF-8')
			if type(val) != bytes: val = bytes(val, 'UTF-8')
			x += key + b': ' + val + b'\r\n'
		
		return x + b'\r\n'

	def clean_payload(self):
		tmp = {k.lower(): v for k,v in self.headers.items()}
		if 'content-type' in tmp and tmp['content-type'] == 'application/json' and type(self.payload) not in (bytes, str):
			self.payload = json.dumps(self.payload)
		if type(self.payload) != bytes:
			self.payload = bytes(self.payload, 'UTF-8') # TODO: Swap UTF-8 for a configurable encoding..

	def build(self):
		self.clean_payload()
		ret = self.build_headers()
		ret += self.payload
		return ret

class HTTP_SERVER():
	"""
	HTTP_SERVER is normally instanciated with :py:meth:`slimhttpd.host` which would
	safely spin up a HTTP / HTTPS server with all the correct arguments.

	In case of manual control, this class is the main server instance in charge
	of keeping the `"addr":port` open and accepting new connections. It contains a main
	event loop, which can be polled in order to accept new clients.

	It's also in charge of polling client identities for new events and lift them up
	to the caller of :py:func:`slimhttpd.HTTP_SERVER.poll`.
	"""
	def __init__(self, *args, **kwargs):
		"""
		`__init__` takes ambigious arguments through `**kwargs`.
		They are passed down to `HTTP_SERVER.config` transparently and used later.

		Some values are used upon `__init__` however, since they are part of the
		initiation process, those arguments are:

		:param addr: Address to listen on, default `0.0.0.0`.
		:type addr: str
		:param port: Port to listen on, default `80` unless HTTPS mode, in which case default is `443`.
		:type port: int
		"""
		self.default_port = 80
		if not 'port' in kwargs: kwargs['port'] = self.default_port
		if not 'addr' in kwargs: kwargs['addr'] = ''

		self.config = {**self.default_config(), **kwargs}
		self.allow_list = None
		## If config doesn't pass inspection, raise the error message given by check_config()
		if (config_error := self.check_config(self.config)) is not True:
			raise config_error

		self.sockets = {}
		self.streams = {}
		self.setup_socket()
		self.main_sock_fileno = self.sock.fileno()
		
		self.pollobj = epoll()
		self.pollobj.register(self.main_sock_fileno, EPOLLIN)

		self.sock.listen(10)

		self.upgraders = {}
		self.on_upgrade_pre_func = None
		self.methods = {
			b'GET' : self.GET_func
		}
		self.routes = {
			None : {} # Default vhost routes
		}

		# while drop_privileges() is None:
		#   log('Waiting for privileges to drop.', once=True, level=5, origin='slimHTTP', function='http_serve')

	def setup_socket(self):
		self.sock = socket()
		self.sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
		try:
			self.sock.bind((self.config['addr'], self.config['port']))
			self.log(f"Bound to {self.config['addr']}:{self.config['port']}")
		except:
			raise slimHTTP_Error(f'Address already in use: {":".join((self.config["addr"], str(self.config["port"])))}')

	def log(self, *args, **kwargs):
		"""
		A simple print wrapper, placeholder for more advanced logging in the future.
		Joins any `*args` together and safely calls :func:'str' on each argument.
		"""
		print('[LOG] '.join([str(x) for x in args]))

		# TODO: Dump raw requests/logs to a .pcap:  (Optional, if scapy is precent)
		# 
		# from scapy.all import wrpcap, Ether, IP, UDP
		# packet = Ether() / IP(dst="1.2.3.4") / UDP(dport=123)
		# wrpcap('foo.pcap', [packet])

	def check_config(self, conf):
		"""
		Makes sure that the given configuration *(either upon startup via `**kwargs` or
		during annotation override of configuration (`@http.configuration`))* is correct.

		#TODO: Verify that 'proxy' mode endpoints aren't ourself, because that **will** hand slimHTTP. (https://github.com/Torxed/slimHTTP/issues/11)

		:param conf: Dictionary representing a valid configuration. #TODO: Add a doc on documentation :P
		:type conf: dict
		"""
		if not 'web_root' in conf: return ConfError('Missing "web_root" in configuration.')
		if not 'index' in conf: return ConfError('Missing "index" in configuration.')
		if not 'port' in conf: conf['port'] = self.default_port
		if not 'addr' in conf: conf['addr'] = ''
		if 'vhosts' in conf:
			for host in conf['vhosts']:
				if 'proxy' in conf['vhosts'][host]:
					if not ':' in conf['vhosts'][host]['proxy']: return ConfError(f'Missing port number in proxy definition for vhost {host}: "{conf["vhosts"][host]["proxy"]}"')
					continue
				if 'module' in conf['vhosts'][host]:
					if not os.path.isfile(conf['vhosts'][host]['module']): return ConfError(f"Missing module for vhost {host}: {os.path.abspath(conf['vhosts'][host]['module'])}")
					if not os.path.splitext(conf['vhosts'][host]['module'])[1] == '.py': return ConfError(f"vhost {host}'s module is not a python module: {conf['vhosts'][host]['module']}")
					continue
				if not 'web_root' in conf['vhosts'][host]: return ConfError(f'Missing "web_root" in vhost {host}\'s configuration.')
				if not 'index' in conf['vhosts'][host]: return ConfError(f'Missing "index" in vhost {host}\'s configuration.')
		return True

	def unregister(self, identity):
		"""
		Unregisters a :py:class:`slimhttpd.HTTP_CLIENT_IDENTITY`  s socket by calling `self.pollobj.unregister`
		on the client identity socket fileno.

		:param identity: Any valid `*_CLIENT_IDENTITY` handler.
		:type identity: :py:class:`slimhttpd.HTTP_CLIENT_IDENTITY` or :py:class:`spiderWeb.WS_CLIENT_IDENTITY`
		"""
		self.pollobj.unregister(identity.fileno)

	def default_config(self):
		"""
		Returns a simple but sane default configuration in case no one is given.
		Defaults to hosting the `web_root` to the `/srv/http` folder.

		:return: {'web_root' : '/srv/http', 'index' : 'index.html', 'vhosts' : { }, 'port' : 80}
		:rtype: dict
		"""
		return {
			'web_root' : '/srv/http',
			'index' : 'index.html',
			'vhosts' : {
				
			},
			'port' : 80
		}

	def configuration(self, config=None, *args, **kwargs):
		"""
		A decorator which can be set with a `@http.configuration` annotation as well as directly called.
		Using the decorator leaves some room for processing configuration before being returned
		to this function, in cases where configuration-checks needs to be isolated to a function
		in order to make the code neat.::


			@app.configuration
			def config():
				return {
					"web_root" : "./web-root",
					"index" : "index.html"
				}

		.. warning::
			The following hook would be called after socket setup.
			There is there for no point in adding `addr` or `port` to this configuration as the socket
			layer has already been set up.

		:param config: Dictionary representing a valid configuration which will be checked with :py:func:`slimhttpd.HTTP_SERVER.check_config`.
		:type config: dict
		"""
		# TODO: Merge instead of replace config?
		if type(config) == dict:
			self.config = config
		elif config:
			staging_config = config(instance=self)
			if self.check_config(staging_config) is True:
				self.config = staging_config

	def GET(self, f, *args, **kwargs):
		self.methods[b'GET'] = f

	def GET_func(self, request):
		"""
		The built-in `GET` function for slimHTTP.
		This can be overridden with `@http.GET`.

		It serves static files under whatever configuration was given on startup.
		As well as support `.py` file handling.

		:param request: The current request from the end user
		:type request: :ref:`~slimHTTP.HTTP_REQUEST`

		:return: The contents of the file in byte-representation
		:rtype: bytes
		"""

		# Join the web_root with the requested URL safely(?) passed through os.path.abspath() removing the initial / or C:\ part.
		path = os.path.safepath(request.web_root, request.headers[b'URL'])
		extension = os.path.splitext(path)[1]

		if extension == '.py':
			if isfile(path):
				try:
					loaded_module = Imported(path)
					request.CLIENT_IDENTITY.server.log(f'Routing {request.CLIENT_IDENTITY}\'s GET request to {loaded_module} @ {request.vhost}"')
					with loaded_module as module:
						# Double-check so that the imported module didn't inject something
						# into the route options for the specific vhost.
						if request.vhost in request.CLIENT_IDENTITY.server.routes and request.headers[b'URL'] in request.CLIENT_IDENTITY.server.routes[request.vhost]:
							return request.CLIENT_IDENTITY.server.routes[request.vhost][request.headers[b'URL']].parser(request)
						elif hasattr(module, 'on_request'):
							return module.on_request(request)
				except ModuleError as e:
					print(e.message)
					request.CLIENT_IDENTITY.close()
			else:
				request.ret_code = 404
				return
		else:
			## We're dealing with a normal, non .py file.
			F_OBJ = FILE(request, path)
			file_size = bytes(str(F_OBJ.size), 'UTF-8')

			if b'range' in request.headers:
				_, data_range = request.headers[b'range'].split(b'=',1)
				start, stop = data_range.split(b'-', 1)
				start = int(start.decode('UTF-8'))
				if len(stop) == 0:
					stop = file_size
					chunksize = 8192
				else:
					stop = int(stop.decode('UTF-8'))
					chunksize = min(stop-start, 8192)

				request.response_headers[b'Content-Range'] = bytes(f'bytes {start}-{stop}/{file_size}', 'UTF-8')
				F_OBJ = STREAM_CHUNKED(request, path, start, chunksize=chunksize)
			elif F_OBJ.mime == 'application/octet-stream':
				## TODO: Not tested
				request.response_headers[b'Accept-Ranges'] = b'bytes'
				F_OBJ = STREAM_CHUNKED(request, path)
			elif F_OBJ.size >= MAX_MEM_ALLOC:
				F_OBJ = STREAM_CHUNKED(request, path)

			return F_OBJ

		return None

	def REQUESTED_METHOD(self, request):
		"""
		A gateway between what method *(GET, POST, OPTIONS etc)* the user requested,
		and the supported methods within the :ref:`~slimHTTP.HTTP_SERVER` instance.

		It also takes care of appending the `index` file if a non-specific file was given.
		*(This function is run post-mortem of a `@http.route` was not found)*

		.. warning::

		    There are some "auto magic" in this function that might be confusing. If the method is given
		    a string, this function tries to append headers. It also converts `dict` into `json.dumps`.

		:param request: The current request from the end user
		:type request: :ref:`~slimHTTP.HTTP_REQUEST`

		:return: A client response data event
		:rtype: :ref:`~slimHTTP.Events.CLIENT_RESPONSE_DATA` events
		"""

		# If the request *ends* on a /
		# replace it with the index file from either vhosts or default to anything if vhosts non existing.
		if request.headers[b'URL'][-1] == '/':
			if request.vhost and 'index' in self.config['vhosts'][request.vhost]:
				index_files = self.config['vhosts'][request.vhost]['index']
				if (_ := request.locate_index_file(index_files, return_any=False)):
					request.headers[b'URL'] += _
		if request.headers[b'URL'][-1] == '/':
			request.headers[b'URL'] += request.locate_index_file(self.config['index'], return_any=True)

		if request.headers[b'METHOD'] in self.methods:
			response = self.methods[request.headers[b'METHOD']](request)

			if type(response) == dict: response = json.dumps(response)
			if type(response) == str: response = request.build_headers() + bytes(response, 'UTF-8')
			if type(response) not in (FILE, STREAM_CHUNKED, bytes): response = request.build_headers() 
			yield (Events.CLIENT_RESPONSE_DATA, response)

	def allow(self, allow_list, *args, **kwargs):
		"""
		Determainates who is allowed or not allowed onto the server.

		.. warning::

		    Have not been extensively tested.

		:param allow_list: A list of `<ip>/<subnet>` or just `<ip>` of allowed hosts.
		:type allow_list: list

		:return: Returns the `on_accept` callback.
		:rtype: :ref:`~slimHTTP.HTTP_SERVER.on_accept_callback`
		"""

		staging_list = []
		for item in allow_list:
			if '/' in item:
				staging_list.append(ipaddress.ip_network(item, strict=False))
			else:
				staging_list.append(ipaddress.ip_address(item))
		self.allow_list = set(staging_list)
		return self.on_accept_callback

	def on_accept_callback(self, f, *args, **kwargs):
		if f:
			self.on_accept = f

	def on_accept(self, f, *args, **kwargs):
		self.on_accept_func = f

	def on_accept_func(self, socket, ip, source_port, *args, **kwargs):
		return HTTP_CLIENT_IDENTITY(self, socket, ip, source_port, on_close=self.on_close_func)

	def on_close(self, f, *args, **kwargs):
		self.on_close_func = f

	def on_upgrade(self, f, *args, **kwargs):
		self.on_upgrade_func = f

	def on_upgrade_func(self, request, *args, **kwargs):
		return None

	# def on_upgrade(self, methods, *args, **kwargs):
	#   self.upgraders = {**self.upgraders, **methods}
	#   return self.on_upgrade_router

	# def on_upgrade_router(self, f, *args, **kwargs):
	#   self.on_upgrade_pre_func = f

	# def on_upgrade_func(self, request, *args, **kwargs):
	#   if self.on_upgrade_pre_func:
	#       if self.on_upgrade_pre_func(request):
	#           return None
	#
	#   if (upgrader := request.headers[b'upgrade'].lower().decode('UTF-8')) in self.upgraders:
	#       return self.upgraders[upgrader](request)

	def on_close_func(self, CLIENT_IDENTITY, *args, **kwargs):
		self.pollobj.unregister(CLIENT_IDENTITY.fileno)
		CLIENT_IDENTITY.socket.close()
		del(self.sockets[CLIENT_IDENTITY.fileno])

	# @route
	def route(self, url, vhost=None, *args, **kwargs):
		"""
		A decorator for statically define HTTP request path's:

		.. code-block::python

			@app.route('/auth/login')
			def route_handler(request):
				print(request.headers)

		.. note::

		    The above example will handle both GET and POST (any user-defined method actually)

		:param timeout: is in seconds
		:type timeout: integer
		:param fileno: Limits the return events to a specific socket/client fileno.
		:type fileno: integer

		:return: `tuple(Events.<type>, EVENT_DATA)`
		:rtype: iterator
		"""
		if not vhost in self.routes: self.routes[vhost] = {}

		self.routes[vhost][url] = ROUTE_HANDLER(url)
		return self.routes[vhost][url].gateway

	def process_new_client(self, socket, address):
		return socket, address

	def poll(self, timeout=GLOBAL_POLL_TIMEOUT, fileno=None):
		"""
		poll is to be called from the main event loop. poll will process any queues
		in need of processing, such as accepting new clients and check for data in
		any of the poll-objects (client sockets/identeties). A basic example of a main event loop would be::

		.. code-block::python

			import slimhttpd

			http = slimhttpd.host(slimhttpd.HTTP)

			while 1:
				for event, event_data in http.poll():
					pass

		:param timeout: is in seconds
		:type timeout: integer
		:param fileno: Limits the return events to a specific socket/client fileno.
		:type fileno: integer

		:return: `tuple(Events.<type>, EVENT_DATA)`
		:rtype: iterator
		"""
		for left_over in self.sockets:
			if self.sockets[left_over].has_data():
				#yield self.do_the_dance(left_over)
				for dance_event_id, dance_event_data in self.do_the_dance(left_over): # Then yield whatever result came from that data
					yield dance_event_id, dance_event_data

		for stream_socket in list(self.streams.keys()):
			for file_event, file_data in self.handle_file_objects(self.streams[stream_socket], stream_socket):
				yield file_event, file_data
			try:
				if self.streams[stream_socket].EOF:
					self.sockets[stream_socket].close()
					del(self.streams[stream_socket])
			except KeyError:
				pass # Socket was removed during processing (we're single threaded, but loops do occur.)

		for socket_fileno, event_type in self.pollobj.poll(timeout):
			if fileno:
				if socket_fileno == fileno:
					yield (socket_fileno, event_type)
			else:
				if socket_fileno == self.main_sock_fileno:
					client_socket, client_address = self.sock.accept()
					try:
						client_socket, client_address = self.process_new_client(client_socket, client_address)
					except Exception as e:
						self.log(e)
						client_socket.close()
						continue

					client_fileno = client_socket.fileno()
					ip_address = ipaddress.ip_address(client_address[0])
					
					## Begin the allow/deny process
					allow = True
					if self.allow_list:
						allow = False
						for net in self.allow_list:
							if ip_address in net or ipaddress == net:
								allow = True
								break

					if not allow:
						print(client_address[0], 'not in allow_list')
						client_socket.close()
						continue

					identity = self.on_accept_func(socket=client_socket, ip=client_address[0], source_port=client_address[1])
					if not identity:
						identity = HTTP_CLIENT_IDENTITY(self, client_socket, client_address, on_close=self.on_close_func)

					self.sockets[client_fileno] = identity
					self.pollobj.register(client_fileno, EPOLLIN)
					yield (Events.SERVER_ACCEPT, identity)
				else:
					## Check for data
					for client_event, client_event_data in self.sockets[socket_fileno].poll(timeout, force_recieve=True):
						yield (client_event, client_event_data) # Yield the events back up the stack

						if client_event == Events.CLIENT_DATA:
							for dance_event_id, dance_event_data in self.do_the_dance(socket_fileno): # Then yield whatever result came from that data
								yield dance_event_id, dance_event_data

								if type(dance_event_data) in (FILE, STREAM_CHUNKED):
									for file_event, file_data in self.handle_file_objects(dance_event_data, socket_fileno):
										yield file_event, file_data

									if type(dance_event_data) is STREAM_CHUNKED:
										self.streams[socket_fileno] = dance_event_data


	def handle_file_objects(self, response_obj, fileno):
		"""
		This function gets called whenever a :ref:`~slimHTTP.FILE` or :ref:`~slimHTTP.STREAM_CHUNKED` is yielded up the event stack.

		:param request: The current request from the end user
		:type request: :ref:`~slimHTTP.HTTP_REQUEST`

		:return: A client response data event
		:rtype: :ref:`~slimHTTP.Events.CLIENT_RESPONSE_DATA` events
		"""

		with response_obj as FILE_OBJ:
			if not (chunk := FILE_OBJ.chunk):
				chunk = b''

			if not FILE_OBJ.headers_sent:
				FILE_OBJ.headers_sent = True
				if type(response_obj) == STREAM_CHUNKED:
					partial_data = FILE_OBJ.request.build_headers(FILE_OBJ.headers) + bytes(f"{hex(len(chunk))[2:]}\r\n", 'UTF-8') + chunk + b'\r\n'
				elif type(response_obj) == FILE:
					partial_data = FILE_OBJ.request.build_headers(FILE_OBJ.headers) + chunk

			elif len(chunk) and type(response_obj) == STREAM_CHUNKED:
				partial_data = bytes(f"{hex(len(chunk))[2:]}\r\n", 'UTF-8') + chunk + b'\r\n'
			elif type(response_obj) == STREAM_CHUNKED:
				partial_data = b'0\r\n\r\n'
				response_obj.EOF = True
			else:
				print(' * * * Should never come here * * *')

			yield (Events.CLIENT_RESPONSE_DATA, partial_data)
			try:
				self.sockets[fileno].send(partial_data)
			except Exception as e:
				if fileno in self.sockets:
					self.sockets[fileno].keep_alive = False
				return

	def do_the_dance(self, fileno):
		self.log(f'Request from {self.sockets[fileno]}')
		for parse_event, client_parsed_data in self.sockets[fileno].build_request():
			yield (parse_event, client_parsed_data)

			if parse_event == Events.CLIENT_REQUEST:
				for response_event, client_response_data in client_parsed_data.parse():
					yield (response_event, client_response_data)

					if response_event in Events.DATA_EVENTS and client_response_data:
						if fileno in self.sockets:
							if type(client_response_data) is bytes:
								self.sockets[fileno].send(client_response_data)
							elif type(client_response_data) is HTTP_RESPONSE:
								self.sockets[fileno].send(client_response_data.build())
							elif type(client_response_data) is STREAM_CHUNKED:
								self.sockets[fileno].keep_alive = True # TODO: Move this to some more logical place
						else:
							break # The client has already recieved data, and was not setup for continius connections. so Keep-Alive has kicked in.

					if fileno in self.sockets:
						if not self.sockets[fileno].keep_alive:
							self.sockets[fileno].close()

class HTTPS_SERVER(HTTP_SERVER):
	def __init__(self, *args, **kwargs):
		self.default_port = 443
		if not 'port' in kwargs: kwargs['port'] = self.default_port
		HTTP_SERVER.__init__(self, *args, **kwargs)

	def run(self):
		while 1:
			for event, event_data in self.poll():
				pass

	def check_config(self, conf):
		if not os.path.isfile(conf['ssl']['cert']):
			raise ConfError(f"Certificate for HTTPS does not exist: {conf['ssl']['cert']}")
		if not os.path.isfile(conf['ssl']['key']):
			raise ConfError(f"Keyfile for HTTPS does not exist: {conf['ssl']['key']}")
		return HTTP_SERVER.check_config(self, conf)

	def default_config(self):
		"""
		Returns a simple but sane default configuration in case no one is given.
		Defaults to hosting the `web_root` to the `/srv/http` folder.

		:return: {'web_root' : '/srv/http', 'index' : 'index.html', 'vhosts' : { }, 'port' : 443}
		:rtype: dict
		"""
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

	def setup_socket(self):
		self.sock = socket()
		self.sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
		#self.sock = 
		try:
			self.sock.bind((self.config['addr'], self.config['port']))
			self.log(f"Bound to {self.config['addr']}:{self.config['port']}")
		except:
			raise slimHTTP_Error(f'Address already in use: {":".join((self.config["addr"], str(self.config["port"])))}')

	def certificate_verification(self, conn, cert, errnum, depth, ret_code):
		cert_hash = cert.get_subject().hash()
		cert_info = dict(cert.get_subject().get_components())
		cert_serial = cert.get_serial_number()
		
		# cert = ['_from_raw_x509_ptr', '_get_boundary_time', '_get_name', '_issuer_invalidator', '_set_boundary_time', '_set_name', '_subject_invalidator', '_x509', 'add_extensions', 'digest', 'from_cryptography', 'get_extension', 'get_extension_count', 'get_issuer', 'get_notAfter', 'get_notBefore', 'get_pubkey', 'get_serial_number', 'get_signature_algorithm', 'get_subject', 'get_version', 'gmtime_adj_notAfter', 'gmtime_adj_notBefore', 'has_expired', 'set_issuer', 'set_notAfter', 'set_notBefore', 'set_pubkey', 'set_serial_number', 'set_subject', 'set_version', 'sign', 'subject_name_hash', 'to_cryptography']
		if cert_info[b'CN'] == b'Some Common Name':
			return True
		return False

	def process_new_client(self, socket, address):
		context = SSL.Context(SSL.TLSv1_2_METHOD) # TLSv1_METHOD
		context.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, self.certificate_verification)
		context.set_verify_depth(9)

		#context.verify_mode = ssl.CERT_REQUIRED # CERT_OPTIONAL # CERT_REQUIRED
		#context.load_cert_chain(self.cert, self.key)
		context.use_privatekey_file(self.config['ssl']['key'])
		context.use_certificate_file(self.config['ssl']['cert'])
		context.set_default_verify_paths()

		context.set_mode(SSL.MODE_RELEASE_BUFFERS)
		# openssl x509 -noout -hash -in cert.pem
		# openssl version -d (place certs here or load manually)
		context.load_verify_locations(None, capath='./certs/')
		store = context.get_cert_store()
		for cert in glob.glob('./certs/*.cer'):
			x509 = crypto.load_certificate(cert)
			store.add_cert(x509)
		#   context.load_verify_locations(cafile=cert)

		socket = SSL.Connection(context, socket)
		try:
			socket.set_accept_state()
		except:
			pass # Hard to emulate this in the mock function, so this function simply doesn't exist.

		return socket, address

class HTTP_CLIENT_IDENTITY():
	"""
	client identity passed as a reference.
	"""
	def __init__(self, server, socket, address, source_port, on_close=None):
		self.server = server
		self.socket = socket
		self.fileno = socket.fileno()
		self.buffer_size = 8192
		self.address = address
		self.source_port = source_port
		self.closing = False
		self.keep_alive = False

		if on_close: self.on_close = on_close

		self.buffer = b''
		self.request = HTTP_REQUEST(self)

	def close(self):
		if not self.closing:
			self.on_close(self)
			self.closing = True

	def on_close(self, *args, **kwargs):
		self.closing = True
		self.server.on_close_func(self)

	def poll(self, timeout=GLOBAL_POLL_TIMEOUT, force_recieve=False):
		"""
		@force_recieve: If the caller knows there's data, we can override
		the polling event and skip straight to data recieving.
		"""
		if force_recieve or list(self.server.poll(timeout, fileno=self.fileno)):
			try:
				d = self.socket.recv(self.buffer_size)
			except: # There's to many errors that can be thrown here for differnet reasons, SSL, OSError, Connection errors etc.
					# They all mean the same thing, things broke and the client couldn't deliver data accordingly so eject.
				d = ''

			if len(d) == 0:
				self.on_close(self)
				return None

			self.buffer += d
			yield (Events.CLIENT_DATA, len(self.buffer))

	def send(self, data):
		return self.socket.send(data)

	def build_request(self):
		try:
			yield (Events.CLIENT_REQUEST, self.request)
		except Exception as e:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			self.server.log(f'Fatal error in HTTP_REQUEST from {self}, {fname}@{exc_tb.tb_lineno}: {e}')
			self.server.log(traceback.format_exc())

	def has_data(self):
		if self.closing: return False
		return True if len(self.buffer) else False

	def __repr__(self):
		return f'<slimhttpd.HTTP_CLIENT_IDENTITY @ {self.address}:{self.source_port}.{self.fileno}>'

class HTTP_PROXY_REQUEST():
	"""
	Turns a HTTP Request into a Reverse Proxy request,
	based on :class:`~slimHTTP.HTTP_REQUEST` identifying the requested host
	to be a vhost with the appropriate `vhost` configuration for a reverse proxy.
	"""
	def __init__(self, CLIENT_IDENTITY, ORIGINAL_REQUEST):
		self.CLIENT_IDENTITY = CLIENT_IDENTITY
		self.ORIGINAL_REQUEST = ORIGINAL_REQUEST
		self.config = self.CLIENT_IDENTITY.server.config
		self.vhost = self.ORIGINAL_REQUEST.vhost

	def __repr__(self, *args, **kwargs):
		return f"<HTTP_PROXY_REQUEST client={self.CLIENT_IDENTITY} vhost={self.vhost}, proxy={self.config['vhosts'][self.vhost]['proxy']}>"

	def parse(self):
		poller = epoll()
		sock = socket()
		sock.settimeout(0.02)
		proxy, proxy_port = self.config['vhosts'][self.vhost]['proxy'].split(':',1)
		try:
			sock.connect((proxy, int(proxy_port)))
		except:
			# We timed out, or the proxy was to slow to respond.
			self.CLIENT_IDENTITY.server.log(f'{self} was to slow to connect/respond. Aborting proxy and sending back empty response to requester.')
			return None
		sock.settimeout(None)
		if 'ssl' in self.config['vhosts'][self.vhost] and self.config['vhosts'][self.vhost]['ssl']:
			context = ssl.create_default_context()
			sock = context.wrap_socket(sock, server_hostname=proxy)
		poller.register(sock.fileno(), EPOLLIN)
		sock.send(self.CLIENT_IDENTITY.buffer)
		self.CLIENT_IDENTITY.server.log(f'Request sent for: {self}')

		data_buffer = b''
		# TODO: this will lock the entire application,
		#       some how we'll have to improve this.
		#       But for small scale stuff this will do, at least for testing.
		while poller.poll(0.02):
			tmp = sock.recv(8192)
			if len(tmp) <= 0: break
			data_buffer += tmp
		poller.unregister(sock.fileno())
		sock.close()
		return data_buffer

class HTTP_REQUEST():
	"""
	General request formatter passed as an object throughout the event stack.
	"""
	def __init__(self, CLIENT_IDENTITY):
		""" A dummy parser that will return 200 OK on everything. """
		self.CLIENT_IDENTITY = CLIENT_IDENTITY
		self._headers = {}
		self._method = None
		self._payload = b''
		self.ret_code = 200 # Default return code.
		self.ret_code_mapper = {200 : b'HTTP/1.1 200 OK\r\n',
								206 : b'HTTP/1.1 206 Partial Content\r\n',
								302 : b'HTTP/1.1 302 Found\r\n',
								404 : b'HTTP/1.1 404 Not Found\r\n',
								418 : b'HTTP/1.0 I\'m a teapot\r\n'}
		self.response_headers = {}
		self.session_storage = {}
		self.web_root = self.CLIENT_IDENTITY.server.config['web_root']

	@property
	def data(self):
		if b'content-type' in self._headers:
			if self._headers[b'content-type'] == b'application/json':
				return json.loads(self.payload.decode('UTF-8'))
		return self.payload

	def build_request_headers(self, data):
		## Parse the headers
		if b'\r\n' in data:
			METHOD, header = data.split(b'\r\n',1)
			for item in header.split(b'\r\n'):
				if b':' in item:
					key, val = item.split(b':',1)
					self._headers[key.strip().lower()] = val.strip()
		else:
			METHOD, self._headers = data, {}

		if len(METHOD) > 1024 or METHOD[:50].count(b' ') < 2 :
			raise InvalidFrame(f"An invalid method was given: {METHOD[:100]}")

		METHOD, URL, proto = METHOD.split(b' ', 2)
		URI_QUERY = {}
		if b'?' in URL:
			URL, QUERIES = URL.split(b'?', 1)
			for item in QUERIES.split(b'&'):
				if b'=' in item:
					k, v = item.split(b'=',1)
					URI_QUERY[k.lower()] = v

		try:
			self._headers[b'URL'] = URL.decode('UTF-8') #TODO: Remove decode and keep the original, use self.url instead, use @property instead.
		except UnicodeDecodeError:
			raise InvalidFrame(f"An invalid URL was given: {URL[:100]}")
		self._headers[b'METHOD'] = METHOD
		self._headers[b'URI_QUERY'] = URI_QUERY

		self.vhost = None

	@property
	def headers(self):
		return self._headers # TODO: Decode with UTF8_DICT()

	@property
	def method(self):
		return self._headers[b'METHOD'].decode('UTF-8')

	@property
	def query(self):
		return UTF8_DICT(self._headers[b'URI_QUERY'])

	@property
	def path_params(self):
		return self.query()

	@property
	def url(self):
		try:
			return self._headers[b'URL'].decode('UTF-8')
		except:
			return self._headers[b'URL']

	@property
	def payload(self):
		return self._payload

	@property
	def path(self):
		class path_storage:
			def __init__(self, request):
				self.query = request.query()
				self.params = self.query

		return path_storage(self)
	

	def locate_index_file(self, index_files, return_any=True):
		if type(index_files) == str:
			if isfile(self.web_root + self._headers[b'URL'] + index_files):
				return index_files
			if return_any:
				return index_files
		elif type(index_files) in (list, tuple):
			for file in index_files:
				if isfile(self.web_root + self._headers[b'URL'] + file):
					if not return_any:
						return file
					break
			if return_any:
				return file

	def build_headers(self, additional_headers={}):
		x = b''
		if self.ret_code in self.ret_code_mapper:
			x += self.ret_code_mapper[self.ret_code]# + self.build_headers() + (response if response else b'')
		else:
			return b'HTTP/1.1 500 Internal Server Error\r\n\r\n'

		for key, val in {**self.response_headers, **additional_headers}.items():
			if type(key) != bytes: key = bytes(key, 'UTF-8')
			if type(val) != bytes: val = bytes(val, 'UTF-8')
			x += key + b': ' + val + b'\r\n'
		
		return x + b'\r\n'

	def parse(self):
		"""
		Split the HTTP data into headers and body.
		"""
		if b'\r\n\r\n' in self.CLIENT_IDENTITY.buffer:
			header, remainder = self.CLIENT_IDENTITY.buffer.split(b'\r\n\r\n', 1) # Copy and split the data so we're not working on live data.
#           self.CLIENT_IDENTITY.server.log(f'Request from {self.CLIENT_IDENTITY} being parsed: {header[:2048]} ({remainder[:2048]})')
			self._payload = b''

			try:
				self.build_request_headers(header)
			except InvalidFrame as e:
				return (Events.INVALID_DATA, e)

			if self._headers[b'METHOD'] == b'POST':
				if b'content-length' in self._headers:
					content_length = int(self._headers[b'content-length'].decode('UTF-8'))
					self._payload = remainder[:content_length]

					if len(self._payload) < content_length:
						return (Events.CLIENT_DATA_FRAGMENTED, self)

					self.CLIENT_IDENTITY.buffer = remainder[content_length:] # Add any extended data outside of Content-Length back to the buffer
				else:
					return (Events.NOT_YET_IMPLEMENTED, NotYetImplemented('POST without Content-Length isn\'t supported yet.'))

			_config = self.CLIENT_IDENTITY.server.config
			if b'host' in self._headers and 'vhosts' in _config and self._headers[b'host'].decode('UTF-8') in _config['vhosts']:
				self.vhost = self._headers[b'host'].decode('UTF-8')
				if 'web_root' in _config['vhosts'][self.vhost]:
					self.web_root = _config['vhosts'][self.vhost]['web_root']

			# Find suitable upgrades if any
			if {b'upgrade', b'connection'}.issubset(set(self._headers)) and b'upgrade' in self._headers[b'connection'].lower():
				requested_upgrade_method = self._headers[b'upgrade'].lower()
				new_identity = self.CLIENT_IDENTITY.server.on_upgrade_func(self)
				if new_identity:
					self.CLIENT_IDENTITY.server.log(f'{self.CLIENT_IDENTITY} has been upgraded to {new_identity}')
					self.CLIENT_IDENTITY.server.sockets[self.CLIENT_IDENTITY.fileno] = new_identity
					yield (Events.CLIENT_UPGRADED, new_identity)
				else:
					yield (Events.CLIENT_UPGRADE_ISSUE, UpgradeIssue(f'Could not upgrade client {self.CLIENT_IDENTITY} with desired upgrader: {requested_upgrade_method}'))
					return

			# Check for @app.route definitions (self.routes in the server object).
			elif self.vhost in self.CLIENT_IDENTITY.server.routes and self._headers[b'URL'] in self.CLIENT_IDENTITY.server.routes[self.vhost]:
				yield (Events.CLIENT_URL_ROUTED, self.CLIENT_IDENTITY.server.routes[self.vhost][self._headers[b'URL']].parser(self))

			# Check vhost specifics:
			if self.vhost:
				if 'proxy' in _config['vhosts'][self.vhost]:
					proxy_object = HTTP_PROXY_REQUEST(self.CLIENT_IDENTITY, self)
					yield (Events.CLIENT_RESPONSE_PROXY_DATA, proxy_object.parse())

					return
				elif 'module' in _config['vhosts'][self.vhost]:
					try:
						loaded_module = Imported(_config['vhosts'][self.vhost]['module'])
						self.CLIENT_IDENTITY.server.log(f'Routing {self.CLIENT_IDENTITY} to {loaded_module} @ {self.vhost}"')

						with loaded_module as module:
							# Double-check so that the imported module didn't inject something
							# into the route options for the specific vhost.
							if self.vhost in self.CLIENT_IDENTITY.server.routes and self._headers[b'URL'] in self.CLIENT_IDENTITY.server.routes[self.vhost]:
								yield (Events.CLIENT_URL_ROUTED, self.CLIENT_IDENTITY.server.routes[self.vhost][self._headers[b'URL']].parser(self))
							elif hasattr(module, 'on_request'):
								yield (Events.CLIENT_RESPONSE_DATA, module.on_request(self))
					except ModuleError as e:
						print(e.message)
					finally:
						return self.CLIENT_IDENTITY.close()

			# Lastly, handle the request as one of the builtins (POST, GET)
			if len(self._headers[b'URL']) and (response := self.CLIENT_IDENTITY.server.REQUESTED_METHOD(self)):
				self.CLIENT_IDENTITY.server.log(f'{self.CLIENT_IDENTITY} sent a "{self._headers[b"METHOD"].decode("UTF-8")}" request to path "[{self.web_root}/]{self._headers[b"URL"]} @ {self.vhost}"')

				for event, event_data in response:
					yield event, event_data
