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
const char req[] = "\xff\xff\xff\xff\x02\x67\x65\x74\x69\x6e\x66\x6f\x20\x78\x78\x78";

const char req2[] = "\xff\xff\xff\xff\x02\x67\x65\x74\x63\x68\x61\x6c\x6c\x65\x6e\x67\x65\x00";

char dacrap[140] = "\xff\xff\xff\xff\x02\x63\x6f\x6e\x6e\x65\x63\x74\x20\x00\xa0\x44\x74\x30"
                      "\x8e\x05\x0c\xc7\x26\xc3";  // add another 113


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
	int s, port = 0, first = 1, len, counter, totalcounter, mu, last, phi;
	char *host = NULL;
	unsigned int seed;
	struct timeval tv;
        
	memset(&tv, 0, sizeof(tv));
	tv.tv_sec = TIMEOUT;
	tv.tv_usec = 0;

	printf("Generic Protocol fuzzer\n\n");

        if (argc < 3) {
                fprintf(stderr, "Use: %s [ip] [port]\n", argv[0]);
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
	    for (phi=24; phi<137; phi++) {dacrap[phi] = rand() % 256;}
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
	    usleep (500);
	    write(s,req2, sizeof(req2) - 1);
	    memset(&buf,0,sizeof(buf));
	    len = send_crap();
	    corruptor(buf, len);         /* puts 1-17 random bytes into buf */
	    write(s, buf, len);
	    memset(&buf2, 0, sizeof(buf2));
            mu=recv(s,buf2,sizeof(buf2),0);
            if ( (mu != last) && (counter > 1) ) {
                    fprintf(stderr, "return buffer from scanned host just changed Counter=%d\n", counter);
                    fprintf(stderr, "expected %d return bytes...received %d bytes\n", last, mu);
                    diffit();
            }
            last = mu;
            totalcounter = 0;
	    close(s);
        }
	
	exit(EXIT_SUCCESS);
}

