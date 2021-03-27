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