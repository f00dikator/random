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

char buf[8192];
char buf2[8192];
const char req[] = "\x5C\x73\x74\x61\x74\x75\x73\x5C";
//Offset 19: 0x6b -> 0x64
//Offset 21: 0x2d -> 0xbb
//Offset 23: 0x27 -> 0x4c
//Offset 28: 0x53 -> 0x71
//Offset 32: 0x25 -> 0x59
//Offset 34: 0x4b -> 0x22
//
const char dacrap[] =
"\xFE\xFE\x01\x00\x00\x00\x00\x63\x6B\x7D\x30\x24\x21\x6E\x3A\x40"
"\x7D\x43\x7B\x64\x74\xBB\x6F\x4C\x7B\x37\x33\x40\x71\x58\x73\x5B"
"\x59\x2A\x22\x3E\x39\x74\x34";


#define CRAPLEN (sizeof(dacrap)-1)



int send_crap() {
	memcpy(buf, dacrap, CRAPLEN);
	return CRAPLEN;
}



void corruptor(char *buf, int len) {
int cb, i, l;

	cb = rand()%15+1; /* bytes to corrupt */

	for (i=0; i < cb; i++)
	{
		l = rand()%len;
		buf[l] = rand()%256;
	}
}




void diffit() {
int i;
        printf("DIFF:\n");
        for (i=0; i < CRAPLEN; i++)
        {
                if (buf[i] != dacrap[i])
                        printf("Offset %d: 0x%x -> 0x%x\n", i, dacrap[i] & 0x000000FF, buf[i] & 0x000000FF);
        }
        printf("*****\n");
}






int main(int argc, char *argv[]) {
	struct sockaddr_in addr;
	int s, port = 0, first = 1, len, counter, totalcounter, mu, last, seeder;
	char *host = NULL;
	unsigned int seed;
	struct timeval tv;

	memset(&tv, 0, sizeof(tv));
	tv.tv_sec = TIMEOUT;
	tv.tv_usec = 0;

	printf("Generic Protocol fuzzer\n\n");

        if (argc < 3) {
                fprintf(stderr, "Use: %s [ip] [port] <seed>\n", argv[0]);
                exit(1);
        }
	

	host = argv[1];
	port = atoi(argv[2]);
	if ((port < 1) || (port > 65535)) {
		fprintf(stderr, "Port out of range (%d)\n", port);
		exit(1);
	}

	memset(&addr, 0, sizeof(addr));


	signal(SIGPIPE, SIG_IGN); /* Ignore SIGPIPE */
        counter = 0;
        fprintf(stderr, "Fuzzing...\n");
        while(1) {
            counter++;
	    if (counter > 8140) exit(0);
	    if (counter < 5000) {                     //remove
		    memset (&buf, 0, sizeof(buf));
		    len = send_crap();
		    corruptor(buf, len);              // remove
	    } else {                                //remove
	        if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		    fprintf(stderr, "Socket error: %s\n", strerror(errno));
		    exit(EXIT_FAILURE);
	        }
	        setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
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
                write(s, req, sizeof(req) -1);
	        len = send_crap();
	        corruptor(buf, len);         /* puts 1-17 random bytes into buf */
	        write(s, buf, len);
	        memset(&buf2, 0, sizeof(buf2));
                mu=recv(s,buf2,sizeof(buf),0);
                if ( (mu != last) && (counter > 1) ) {
                    fprintf(stderr, "return buffer from scanned host just changed Counter=%d\n", counter);
                    fprintf(stderr, "expected %d return bytes...received %d bytes\n", last, mu);
                    diffit();
                }
                last = mu;
                totalcounter = 0;
	        close(s);
	    }                          // remove if counter crap-ola
        }
	
	exit(EXIT_SUCCESS);
}

