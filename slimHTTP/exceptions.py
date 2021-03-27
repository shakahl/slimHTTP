class LoggerError(BaseException):
	pass
	
class InvalidFrame(BaseException):
	pass

class slimHTTP_Error(BaseException):
	pass

class ModuleError(BaseException):
	def __init__(self, message, path):
		self.message = message
		self.path = path

class ConfError(BaseException):
	def __init__(self, message):
		self.message = message
		pass

class NotYetImplemented(BaseException):
	def __init__(self, message):
		self.message = message
		pass

class UpgradeIssue(BaseException):
	def __init__(self, message):
		self.message = message
		pass