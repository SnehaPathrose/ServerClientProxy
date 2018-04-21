pbproxy: pbproxy.c aes.c client.c server.c pbproxy.h
	 gcc -o pbproxy pbproxy.c aes.c client.c server.c pbproxy.h -lcrypto
