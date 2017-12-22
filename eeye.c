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

#define TIMEOUT 3

char buf2[8192];

const char first[] =
"\x00\x00\x00\x57\xFF\x53\x4D\x42\x72\x00\x00\x00\x00\x08\x01\xC8"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x65\x45"
"\x79\x65\x00\x00\x00\x34\x00\x02\x4C\x41\x4E\x4D\x41\x4E\x31\x2E"
"\x30\x00\x02\x57\x69\x6E\x64\x6F\x77\x73\x20\x66\x6F\x72\x20\x57"
"\x6F\x72\x6B\x67\x72\x6F\x75\x70\x73\x20\x33\x2E\x31\x61\x00\x02"
"\x4E\x54\x20\x4C\x4D\x20\x30\x2E\x31\x32\x00";

const char second[] = 
"\x00\x00\x00\x9E\xFF\x53\x4D\x42\x73\x00\x00\x00\x00\x08\x01\xC8"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFE"
"\x00\x00\x00\x00\x0C\xFF\x00\x00\x00\x01\x40\x02\x00\x01\x00\x00"
"\x00\x00\x00\x44\x00\x00\x00\x00\x00\x5C\x00\x00\x80\x63\x00\x60"
"\x61\x06\x81\x06\x2B\x06\x01\x05\x05\x02\xA0\x56\x30\x54\xA0\x1A"
"\x30\x18\x06\x0A\x2B\x06\x01\x03\x86\xAA\x95\xF2\x33\x06\x06\x0A"
"\x2B\x06\x01\x04\x01\x82\x37\x02\x02\x0A\xA2\x36\x04\x34\x4E\x54"
"\x4C\x4D\x53\x53\x50\x00\x01\x00\x00\x00\x97\x82\x08\xE0\x00\x20"
"\x20\x20\x20\x00\x20\x20\x00\x00\x20\x20\x20\x20\x20\x20\x20\x20"
"\x20\x20\x00\x00\x00\x00\x20\x20\x00\x00\x20\x20\x00\x20\x20\x20"
"\x20\x00"
;



int main(int argc, char *argv[]) {
	struct sockaddr_in addr;
	int s, port = 0,  mu;
	char *host = NULL;
	struct timeval tv;

        if (argc < 3) {
                fprintf(stderr, "Use: %s [ip] [port]\n", argv[0]);
                exit(1);
        }
	

	host = argv[1];
	port = atoi(argv[2]);
	if ((port < 1) || (port > 65535)) {
		fprintf(stderr, "port no good...setting it to 445\n", port);
		port = 445;
	}

        memset(&tv, 0, sizeof(tv));
        tv.tv_sec = TIMEOUT;
        tv.tv_usec = 0;


	memset(&addr, 0, sizeof(addr));


	signal(SIGPIPE, SIG_IGN); 

	if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "Socket error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

        setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(host);
	if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stdout, "no connection: %s\n", strerror(errno));
		exit(0);
	}

        write(s,first,sizeof(first)-1);
        mu=recv(s,buf2,sizeof(buf2),0);
	write(s, second, sizeof(second)-1);
        mu=recv(s,buf2,sizeof(buf2),0);
	(mu < 40) ? fprintf(stderr,"not vulnerable\n") : fprintf(stderr,"VULNERABLE\n");
	exit(1);
}

