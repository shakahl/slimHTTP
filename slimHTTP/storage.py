
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