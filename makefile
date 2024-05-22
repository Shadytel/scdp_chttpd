chttpd : chttpd.c
	gcc chttpd.c -o chttpd -L /usr/lib/ -lmicrohttpd -lsqlite3
sample : sample_generator.c
	gcc sample_generator.c -o sample_generator -lsqlite3
clean :
	rm -rf chttpd sample_generator
