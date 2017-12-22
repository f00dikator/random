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
"\x01\x00\x00\x00\xCE\xFA\x0B\xB0\xA0\x00\x00\x00\x4D\x4D\x53\x20"
"\x14\x00\x00\x00\x00\x00\x00\x00\xF8\x53\xE3\xA5\x9B\xC4\x00\x40"
"\x12\x00\x00\x00\x01\x00\x03\x00\xF0\xF0\xF0\xF0\x0B\x00\x04\x00"
"\x1C\x00\x03\x00\x4E\x00\x53\x00\x50\x00\x6C\x00\x61\x00\x79\x00"
"\x65\x00\x72\x00\x2F\x00\x34\x00\x2E\x00\x31\x00\x2E\x00\x30\x00"
"\x2E\x00\x33\x00\x38\x00\x35\x00\x37\x00\x3B\x00\x20\x00\x7B\x00"
"\x30\x00\x32\x00\x64\x00\x30\x00\x63\x00\x32\x00\x63\x00\x30\x00"
"\x2D\x00\x62\x00\x35\x00\x30\x00\x37\x00\x2D\x00\x31\x00\x31\x00"
"\x64\x00\x32\x00\x2D\x00\x39\x00\x61\x00\x61\x00\x38\x00\x2D\x00"
"\x62\x00\x37\x00\x30\x00\x66\x00\x33\x00\x30\x00\x34\x00\x34\x00"
"\x61\x00\x65\x00\x37\x00\x65\x00\x7D\x00\x00\x00\x00\x00\x00\x00"
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




void diffit() {
int i;
        printf("DIFF:\n");
        for (i=0; i < CRAPLEN; i++)
        {
                if (buf[i] != dacrap[i])
                        printf("Offset %d: 0x%x -> 0x%x\n", i, dacrap[i], buf[i]);
        }
        printf("*****\n");
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
        setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv)); 

	memset(&addr, 0, sizeof(addr));


	signal(SIGPIPE, SIG_IGN); /* Ignore SIGPIPE */
        counter = 0;
        fprintf(stderr, "Fuzzing...\n");
        while(1) {
            counter++;
	    if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
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

	    len = send_crap();
	    corruptor(buf, len);         /* puts 1-17 random bytes into buf */
	    write(s, buf, len);
            mu=recv(s,buf,sizeof(buf),0);
            if ( (mu != last) && (counter > 1) ) {
                    fprintf(stderr, "return buffer from scanned host just changed Counter=%d\n", counter);
                    fprintf(stderr, "expected %d return bytes...received %d bytes\n", last, mu);
                    diffit();
            }
            last = mu;
	    close(s);
        }
	
	exit(EXIT_SUCCESS);
}

