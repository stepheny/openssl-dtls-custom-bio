CFLAGS=-g
LDFLAGS=-lssl -lcrypto
LIBS=cbio.o util.o

.PHONY: all clean certs delete-certs

all: server client certs

server: server.c $(LIBS)
	cc -o $@ $^ $(CFLAGS) $(LDFLAGS)

client: client.c $(LIBS)
	cc -o $@ $^ $(CFLAGS) $(LDFLAGS) -lreadline

certs: root-key.pem root-ca.pem \
server-key.pem server-csr.pem server-cert.pem \
client-key.pem client-csr.pem client-cert.pem

clean: delete-certs
	rm -f cbio.o util.o server client

delete-certs:
	rm -f *.pem *.srl

%-key.pem:
	openssl ecparam -name secp384r1 -genkey -noout -out $@

%-cert.pem: %-csr.pem root-ca.pem root-key.pem
	openssl x509 -req -in $< -out $@ -CA root-ca.pem -CAkey root-key.pem -days 7

%-csr.pem: %-key.pem
	openssl req -new -key $< -out $@ -subj /CN=test_$*/

root-ca.pem: root-key.pem
	openssl req -new -x509 -nodes -days 7 -key $< -out $@ -subj /CN=test_rootCA/
	test -f root-ca.srl || echo 00 > root-ca.srl

