import slimhttpd

http = slimhttpd.host(slimhttpd.HTTP, port=80, web_root='./web_root', index='index.html')

@http.route('/verify/index.html')
def auth_handler(request):
	return slimhttpd.HTTP_RESPONSE(ret_code=307, headers={'Location' : '/verification_failed.html'}, payload=b'')

while 1:
	for event, *event_data in http.poll():
		pass
