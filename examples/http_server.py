import slimhttpd

http = slimhttpd.host(slimhttpd.HTTP)

while 1:
	for event, *event_data in http.poll():
		pass