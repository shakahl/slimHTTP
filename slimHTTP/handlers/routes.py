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