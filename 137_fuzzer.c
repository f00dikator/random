
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

char buf[8192];


const char dacrap[] =
"\x94\x3D\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4B\x41"
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21"
"\x00\x01";

#define CRAPLEN (sizeof(dacrap)-1)



int send_crap() {
	memcpy(buf, dacrap, CRAPLEN);
	return CRAPLEN;
}



void corruptor(char *buf, int len) {
int cb, i, l;

	cb = rand()%6+1; /* bytes to corrupt */

	for (i=0; i < cb; i++)
	{
		l = rand()%len;
		buf[l] = rand()%256;
	}
}



void diffit() {
int i;
	printf("OVERFLOW PACKET:\n");
	for (i=0; i < CRAPLEN; i++) {
                        printf("0x%2x ", buf[i]);
                        if ( (i > 0) && ((i % 16) == 0) ) printf("\n");
	}
}




int main(int argc, char *argv[]) {
	struct sockaddr_in addr;
	int s, port = 0, first = 1, len, counter, totalcounter;
	char *host = NULL;
	unsigned int seed;
	struct timeval tv;

	printf("Generic Protocol fuzzer\n\n");
	
	if (argc != 3) {
		fprintf(stderr, "Use: %s [ip] [port]\n", argv[0]);
		exit(1);
	}

	host = argv[1];
	port = atoi(argv[2]);
	if ((port < 1) || (port > 65535)) {
		fprintf(stderr, "Port out of range (%d)\n", port);
		exit(1);
	}

	gettimeofday(&tv, NULL);
	seed = (getpid() ^ tv.tv_sec) + (tv.tv_usec * 1000);

	printf("seed = %u\n", seed);
	srand(seed);

	memset(&addr, 0, sizeof(addr));


	signal(SIGPIPE, SIG_IGN); /* Ignore SIGPIPE */
        counter = 0;
        fprintf(stderr, "Fuzzing...\n");
        while(1) {
            counter++;
	    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		fprintf(stderr, "Socket error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	    }
	    addr.sin_family = AF_INET;
	    addr.sin_port = htons(port);
	    addr.sin_addr.s_addr = inet_addr(host);
	    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "Unable to connect: %s\n", strerror(errno));
		if (!first) {
			diffit();
                        totalcounter++;
                }
		if (totalcounter > 3) exit(EXIT_FAILURE);
	    }
	    first = 0;
	    if ( (counter % 100) == 0) {fprintf(stdout,"counter=%d\n",counter); fflush(stdout); }

	    len = send_crap();
	    corruptor(buf, len);         /* puts 1-17 random bytes into buf */
	    write(s, buf, len);
            totalcounter = 0;
	    usleep(1000); /* wait.. */
	    close(s);
        }
	
	exit(EXIT_SUCCESS);
}

