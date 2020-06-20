import slimhttpd

http = slimhttpd.host(slimhttpd.HTTPS)

@http.configuration
def config(instance):
	return {
		'web_root' : './',
		'index' : 'index.html',
		'cert' : 'cert.pem',
		'key' : 'key.pem'
	}

while 1:
	for event, *event_data in http.poll():
		pass