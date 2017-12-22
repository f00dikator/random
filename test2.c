/* jwlampe - private */
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

#define TIMEOUT 3

const char dacrap[] =
"\x85\x00\x00\x44\x20\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43"
"\x41\x43\x41\x43\x41\xFC\xA0\x43\x41\x43\x41\x43\x41\x43\x41\x43"
"\x41\x43\x41\x43\x8F\x00\x20\x43\x0E\x43\x41\x43\x41\x43\x41\x43"
"\x41\x43\xB3\xB4\x41\x43\x41\x43\x41\x43\x91\xCF\x41\x0A\x41\x43"
"\x19\x43\xC5\x6E\x41\x41\x41\x00"
;

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




void diff() {
int i;
        printf("DIFF:\n");
        for (i=0; i < CRAPLEN; i++)
        {
                if (buf[i] != dacrap[i])
                        printf("Offset %d: 0x%x -> 0x%x\n", i, dacrap[i], buf[i]);
        }
        printf("*****");
}






int main(int argc, char *argv[]) {
	struct sockaddr_in addr;
	int s, port = 0, first = 1, len, counter, totalcounter, mu, last, seeder;
	char *host = NULL;
	unsigned int seed;
	struct timeval tv;

	printf("Generic Protocol fuzzer\n\n");

        if (argc < 3) {
                fprintf(stderr, "Use: %s [ip] [port] <seed>\n", argv[0]);
                exit(1);
        }
	

	host = argv[1];
	port = atoi(argv[2]);
	if (argc == 4) seeder = atoi(argv[3]);
	if ((port < 1) || (port > 65535)) {
		fprintf(stderr, "Port out of range (%d)\n", port);
		exit(1);
	}

        if (seeder) {
	        seed = seeder;
	} else {
	        gettimeofday(&tv, NULL);
	        seed = (getpid() ^ tv.tv_sec) + (tv.tv_usec * 1000);
	}

	printf("seed = %u\n", seed);
	srand(seed);

        memset(&tv, 0, sizeof(tv));
        tv.tv_sec = TIMEOUT;
        tv.tv_usec = 0;
				
	memset(&addr, 0, sizeof(addr));


	signal(SIGPIPE, SIG_IGN); /* Ignore SIGPIPE */
        counter = totalcounter = 0;
        fprintf(stderr, "Fuzzing...\n");
        while(1) {
	    if (totalcounter > 3) exit(0);
            counter++;
	    if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "Socket error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	    }
	    //setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
	    addr.sin_family = AF_INET;
	    addr.sin_port = htons(port);
	    addr.sin_addr.s_addr = inet_addr(host);
	    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "Unable to connect: %s\n", strerror(errno));
		if (!first) {
			diff();
                        totalcounter++;
                }
	    }
	    first = 0;
	    if ( (counter % 100) == 0) {printf("."); fflush(stdout); counter = 1;}

	    len = send_crap();
	    corruptor(buf, len);         
	    write(s, buf, len);
            /*mu=recv(s,buf,sizeof(buf),0);
            if ( (mu != last) && (counter > 1) ) {
                    fprintf(stderr, "return buffer from scanned host just changed.  Counter=%d\n", counter);
                    fprintf(stderr, "expected %d return bytes...received %d bytes", last, mu);
                    diff();
		    //totalcounter++;
            }
            last = mu;
	    */
	    usleep(250);
	    close(s);
        }
	
	exit(EXIT_SUCCESS);
}

