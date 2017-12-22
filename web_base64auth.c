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

char buf[18192];
char buf2[512];

#define TIMEOUT 3

/* 47 45 54 20 2F 20 48 54 54 50 2F 31 2E 31 0D 0A  GET / HTTP/1.1..
 * 41 75 74 68 6F 72 69 7A 61 74 69 6F 6E 3A 20 4E  Authorization: N
 * 65 67 6F 74 69 61 74 65 20 24 52 67 33 4C 34 4B  egotiate $Rg3L4K
 * 76 79 33 57 71 31 54 34 50 47 72 4A 41 53 77 33  vy3Wq1T4PGrJASw3
 * 51 55 31 58 4D 31 57 66 44 31 57 34 55 53 36 64  QU1XM1WfD1W4US6d
 * 49 63 35 51 3D 0D 0A 48 6F 73 74 3A 20 31 39 32  Ic5Q=..Host: 192
 * 2E 31 36 38 2E 31 35 2E 39 37 0D 0A 0D 0A        .168.15.97....
 *
 */
const char dacrap[] =
"\x47\x45\x54\x20\x2F\x20\x48\x54\x54\x50\x2F\x31\x2E\x31\x0D\x0A"
"\x41\x75\x74\x68\x6F\x72\x69\x7A\x61\x74\x69\x6F\x6E\x3A\x20\x4E"
"\x65\x67\x6F\x74\x69\x61\x74\x65\x20\x24\x52\x67\x33\x4C\x34\x4B"
"\x76\x79\x33\x57\x71\x31\x54\x34\x50\x47\x72\x4A\x41\x53\x77\x33"
"\x51\x55\x31\x58\x4D\x31\x57\x66\x44\x31\x57\x34\x55\x53\x36\x64"
"\x49\x63\x35\x51\x3D\x0D\x0A\x48\x6F\x73\x74\x3A\x20\x31\x39\x32"
"\x2E\x31\x36\x38\x2E\x31\x35\x2E\x39\x37\x0D\x0A\x0D\x0A";


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
		if (l > 41) buf[l] = rand()%256;
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
	int s, port = 0, first = 1, len, counter, totalcounter, mu, last, seeder, qu;
	char *host = NULL;
	char foobar[100000];
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
            memset(&buf2, 0, sizeof(buf2));
	    memset(&buf, 0, sizeof(buf));
	    len = send_crap();
	    corruptor(buf, len);         /* puts 1-17 random bytes into buf */
	    for (qu = 0; qu < rand() % 100000 ; qu++) {         // start new
		    foobar[qu] = rand() % 256;
            }
	    strncat(buf, foobar, sizeof(foobar));
	    write(s, buf, sizeof(buf) - 1);        // end new
            mu=recv(s,buf2,sizeof(buf2),0);
	    if (mu > 0) {
                if ( (mu != last) && (counter > 1) ) {
                    if (! strstr(buf2, "HTTP/1.1 500 Server Error")) {
			    if (! strstr(buf2, "HTTP/1.1 400 Bad Request")) {
			        fprintf(stdout, "WHOAH! ... We got a server non-500 response\n");
				fprintf(stdout, "incoming buffer has size of %d\n", mu);
				fprintf(stderr, "WHOAH! ... We got a server non-500 response\n");
				fprintf(stderr, "incoming buffer has size of %d\n", mu);
			        fprintf(stdout, "Returned buffer was %s\n\n\n", buf2);
				fprintf(stderr, "Returned buffer was %s\n\n\n", buf2);
                                diffit();
			    }
		    }
                }
	    }
            last = mu;
	    close(s);
        }
	
	exit(EXIT_SUCCESS);
}

