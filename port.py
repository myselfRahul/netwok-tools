import socket

print ("Creating socket..."),
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print ("Done.")

web= input ("Enter web url to connect\n")
print ("Looking up port number..."),

port = socket.getservbyname('http', 'tcp')
print ("Done.")

print ("Connecting to remote host on port %d..." % port),
s.connect((web, port))


print ("Done.")

print ("Connected from", s.getsockname())
print ("Connected to", s.getpeername())
