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
"\x11\x02\xE5\x42\x0A\x0A\x0A\x07\x00\x8A\x00\xBB\x00\x00\x20\x45"
"\x49\x45\x42\x45\x4D\x45\x4A\x45\x46\x43\x41\x43\x41\x43\x41\x43"
"\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x00"
"\x20\x46\x48\x45\x50\x46\x43\x45\x4C\x45\x48\x46\x43\x45\x50\x46"
"\x46\x46\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x42"
"\x4F\x00\xFF\x53\x4D\x42\x25\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x11\x00\x00\x21\x00\x00\x00\x00\x00\x00\x00\x00\x00\xE8"
"\x03\x00\x00\x00\x00\x00\x00\x00\x00\x21\x00\x56\x00\x03\x00\x01"
"\x00\x00\x00\x02\x00\x32\x00\x5C\x4D\x41\x49\x4C\x53\x4C\x4F\x54"
"\x5C\x42\x52\x4F\x57\x53\x45\x00\x0F\x00\x80\xFC\x0A\x00\x48\x41"
"\x4C\x49\x45\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00"
"\x03\x10\x05\x00\x0F\x01\x55\xAA\x00";

#define CRAPLEN (sizeof(dacrap)-1)



int send_crap() {
	memcpy(buf, dacrap, CRAPLEN);
	return CRAPLEN;
}



void corruptor(char *buf, int len) {
int cb, i, l;

	cb = rand() % 8 + 1; /* bytes to corrupt */

	for (i=0; i < cb; i++)
	{
		l = rand()%len;
		buf[l] = rand()%256;
	}
}



void diffit() {
        int i;
        printf("DIFF:\n");
	for (i=0; i < CRAPLEN; i++) {
            if (buf[i] != dacrap[i]) {
	        printf("Offset %d: 0x%x -> 0x%x\n", i, dacrap[i], buf[i]);
	    }
	    printf("*****\n");
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
	    if ( (counter % 100) == 0) {printf("."); fflush(stdout); counter = 1;}

	    len = send_crap();
	    corruptor(buf, len);         /* puts 1-17 random bytes into buf */
	    write(s, buf, len);
            totalcounter = 0;
	    usleep(1000); /* wait.. */
	    close(s);
        }
	
	exit(EXIT_SUCCESS);
}

