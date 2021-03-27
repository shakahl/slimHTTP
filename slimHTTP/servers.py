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
		self.debuggable_routes = {}

		# while drop_privileges() is None:
		#   log('Waiting for privileges to drop.', once=True, level=5, origin='slimHTTP', function='http_serve')

	def is_debuggable(self, url :str):
		if len(self.debuggable_routes) == 0:
			return True

		if url in self.debuggable_routes:
			return True

		return False

	def debug(self, url):
		self.debuggable_routes[url] = True

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
		logger = logging.getLogger(__name__)
		if 'level' in kwargs:
			if type(kwargs['level']) == str:
				if kwargs['level'].lower() == 'critical':
					kwargs['level'] = logging.CRITICAL
				elif kwargs['level'].lower() == 'erro':
					kwargs['level'] = logging.ERROR
				elif kwargs['level'].lower() == 'warning':
					kwargs['level'] = logging.WARNING
				elif kwargs['level'].lower() == 'info':
					kwargs['level'] = logging.INFO
				elif kwargs['level'].lower() == 'debug':
					kwargs['level'] = logging.DEBUG
				# elif kwargs['level'].lower() == 'notset':
				# 	kwargs['level'] = logging.NOTSET
			elif type(kwargs['level']) == int:
				if not kwargs['level'] in (0, 10, 20, 30, 40, 50):
					raise LoggerError(f"Unable to automatically detect the correct log level for: {args} | {kwargs}")
			else:
				raise LoggerError(f"Unknown level definition: {kwargs['level']}")
		else:
			kwargs['level'] = logging.INFO

		logger.log(kwargs['level'], ''.join([str(x) for x in args]))

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
		try:
			path = os.path.safepath(request.web_root, request.headers[b'URL'])
		except:
			request.ret_code = 404
			return

		extension = os.path.splitext(path)[1]

		# Only allow .py files marked as executable to execute as a module.
		# This to avoid .py files intended for downloads to be executed.
		if extension == '.py' and os.access(path, os.X_OK):
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
		for left_over in list(self.sockets.keys()):
			if self.sockets[left_over].has_data():
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

	def run(self):
		while 1:
			for event, event_data in self.poll():
				pass

class HTTPS_SERVER(HTTP_SERVER):
	def __init__(self, *args, **kwargs):
		self.default_port = 443
		if not 'port' in kwargs: kwargs['port'] = self.default_port
		HTTP_SERVER.__init__(self, *args, **kwargs)

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