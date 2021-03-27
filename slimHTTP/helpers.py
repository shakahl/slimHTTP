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