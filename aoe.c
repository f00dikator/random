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
"\x90\x00\xB0\xFA\x02\x00\x08\xFC\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x70\x6C\x61\x79\x01\x00\x0E\x00\x50\x00\x00\x00"
"\x44\x00\x00\x00\x20\xE7\xE5\x29\xE8\x5C\x45\x4E\xB0\x23\x71\x35"
"\xF1\x82\x0D\x68\x01\x5B\xD7\x00\x8C\x7A\xD3\x11\xA2\xD5\x00\x60"
"\x97\xBA\x65\x50\x08\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\xB7\x4D\x22\x02\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x5C\x00\x00\x00"
"\x66\x30\x30\x64\x69\x6B\x61\x74\x6F\x72\x27\x73\x20\x47\x61\x6D"
"\x65\x00\x5B\x66\x30\x30\x64\x69\x6B\x61\x74\x6F\x72\x5D\x00\x00"
;

#define CRAPLEN (sizeof(dacrap)-1)



int send_crap() {
	memcpy(buf, dacrap, CRAPLEN);
	return CRAPLEN;
}



void corruptor(char *buf, int len) {
int cb, i, l;

	cb = rand()%15+1; /* bytes to corrupt */
/*
	for (i=0; i < cb; i++)
	{
		l = rand()%len;
		buf[l] = rand()%256;
	}
	*/
}




void diffit() {
int i;
        printf("DIFF:\n");
        for (i=0; i < CRAPLEN; i++)
        {
                if (buf[i] != dacrap[i])
                        printf("Offset %d: 0x%d -> 0x%d\n", i, dacrap[i], buf[i]);
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
			exit(0);
		}
	    }
	    first = 0;

	    len = send_crap();
	    corruptor(buf, len);         /* puts 1-17 random bytes into buf */

	    write(s, buf, len);
            mu=recv(s,buf,sizeof(buf),0);
	    /*if (mu >= 0)
	    {
		    fprintf(stderr, "Counter %d : mu = %d\n", counter, mu);
		    diffit();
		    exit(0);
	    } */

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

