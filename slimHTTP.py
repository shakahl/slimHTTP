

server
  |
  |-- request
  |      |
  |      |-- response


if server -> request.poll():
	if not: close()
	if exception: close()
	else: send(response)


class Server():
	def __init__(self):
		pass

	def poll(self) -> None:
		for client in self.pool:
			client :HTTP_CLIENT_IDENTITY

			client.poll()
			client.current_request.poll()

			if client.end_session and not client.closed:
				client.close()

			if client.closed:
				return self.delete(client)

	def on_request(self):
		pass

	def on_response(self):
		pass

	def on_close(sef):
		pass

	def on_proxy_response(self):
		pass

	def on_proxy_request(self):
		pass
