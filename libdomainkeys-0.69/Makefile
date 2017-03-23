CC=gcc
CFLAGS=-DBIND_8_COMPAT -O2
#CFLAGS += -DDK_DEBUG -DDK_HASH_BUFF -Wall
#CFLAGS += -DUNIXWARE
INCS=-I.
LIBS=-L. -ldomainkeys -lcrypto
MAKE=make

dktest: dktest.o libdomainkeys.a dns.lib socket.lib
	$(CC) $(CFLAGS) -o dktest dktest.o $(LIBS) `cat dns.lib` `cat socket.lib`

dktest.o: dktest.c domainkeys.h
	$(CC) $(CFLAGS) -c dktest.c $(INCS)

testtrace: testtrace.o dktrace.o dktrace.h
	$(CC) $(CFLAGS) -o testtrace testtrace.o dktrace.o

dktrace.o: dktrace.c dktrace.h

makeheader: makeheader.c
	$(CC) $(CFLAGS) -o makeheader makeheader.c
domainkeys.o: domainkeys.c
	$(CC) $(CFLAGS) -c domainkeys.c $(INCS)
dns_txt.o: dns_txt.c
	$(CC) $(CFLAGS) -c dns_txt.c
dnstest.o: dnstest.c
	$(CC) $(CFLAGS) -c dnstest.c
dnstest: dnstest.o dns_txt.o
	$(CC) $(CFLAGS) -o dnstest dnstest.o dns_txt.o
dns.lib: dnstest.c
	(if $(MAKE) dnstest >/dev/null 2>&1; then echo -lresolv; else echo ""; fi) >dns.lib
	 rm -f dnstest

socktest.o: socktest.c
	$(CC) $(CFLAGS) -c socktest.c
socktest: socktest.o
	$(CC) $(CFLAGS) -o socktest socktest.o -lsocket
socket.lib: socktest.c
	(if $(MAKE) socktest >/dev/null 2>&1; then echo -lsocket -lnsl; else echo ""; fi) >socket.lib
	rm -f socktest

domainkeys.h: domainkeys.c makeheader
	./makeheader <domainkeys.c >domainkeys.h

libdomainkeys.a: domainkeys.o dns_txt.o dktrace.o
	rm -f libdomainkeys.a
	ar cr libdomainkeys.a domainkeys.o dns_txt.o dktrace.o
	ranlib libdomainkeys.a

python: domainkeys_wrap.o _domainkeys.so

domainkeys_wrap.o: domainkeys.h domainkeys.i domainkeys_wrap.c
	#swig -python -module domainkeys domainkeys.i
	$(CC) $(CFLAGS) -c domainkeys_wrap.c  -I/usr/include/python2.4/

_domainkeys.so: domainkeys.o dns_txt.o dktrace.o domainkeys_wrap.o
	ld -shared domainkeys.o dns_txt.o dktrace.o domainkeys_wrap.o -lcrypto `cat dns.lib` -o _domainkeys.so

clean:
	rm -f *.o *.so libdomainkeys.a dns.lib dnstest socktest makeheader dktest testtrace domainkeys.h

# 
distributionfile:
	sh makedistribution.sh
