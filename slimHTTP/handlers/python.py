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