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

const char dacrap[] =
"\x80\x67\x01\x03\x01\x00\x4E\x00\x00\x00\x10\x01\x00\x80\x03\x00"
"\x80\x07\x00\xC0\x06\x00\x40\x02\x00\x80\x04\x00\x80\x00\x00\x39"
"\x00\x00\x38\x00\x00\x35\x00\x00\x33\x00\x00\x32\x00\x00\x04\x00"
"\x00\x05\x00\x00\x2F\x00\x00\x16\x00\x00\x13\x00\xFE\xFF\x00\x00"
"\x0A\x00\x00\x15\x00\x00\x12\x00\xFE\xFE\x00\x00\x09\x00\x00\x64"
"\x00\x00\x62\x00\x00\x03\x00\x00\x06\xA5\x59\x79\x83\xD4\x64\xEA"
"\xD1\x43\xF8\x57\x5A\x76\xAC\x94\x5D";

const char second[] = 
"\x16\x03\x01\x00\x86\x10\x00\x00\x82\x00\x80\x7E\xD4\xDE\xEE\x19"
"\x6F\xAA\x03\xE8\xF5\x88\x5C\xEF\x2D\xC7\xAD\x62\x86\x81\x59\x2D"
"\x13\x20\xD9\xE4\xCD\xB7\xF5\x78\x35\xBC\xD1\xF7\xEB\xE9\x41\x6F"
"\xD7\x17\xE6\x3F\xF3\x08\x39\x98\x38\x91\x0E\x2C\x36\x40\x0A\x2B"
"\x9B\x41\x27\xDC\x5A\x70\xAA\x14\x67\xE1\x3F\x56\xFA\x98\xB9\x6D"
"\x98\xF9\xEB\xB6\xBD\x34\xEA\xC0\xED\xF6\x5A\x5E\x10\x48\x57\xA5"
"\x32\xEB\xC2\x60\x8A\x72\x37\x40\x94\x7B\x51\x70\x21\x33\x0F\x0E"
"\x47\xF4\xA4\x0A\x74\x22\x2C\xF6\xFE\x50\xF9\xFE\xAF\xC0\xEC\x62"
"\x90\x4E\xBF\xB6\xDC\xA2\x76\x2F\x62\xB7\x90\x14\x03\x01\x00\x01"
"\x01\x16\x03\x01\x00\x30\xBD\xE9\xEC\x41\xAD\x85\x96\x62\x3E\xC0"
"\x7F\x99\x04\x71\x6B\xD6\x1E\xC7\x25\xE8\x60\x24\xB3\x1C\xB4\x6B"
"\x97\x7A\x97\x5B\xEC\xB3\xF6\xEE\x37\x70\x80\x7F\x18\x60\x66\xED"
"\x91\x1D\xB6\x4D\xEE\xF6"
;

#define CRAPLEN (sizeof(dacrap)-1)

int offsetz[CRAPLEN + 1] = {};


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
		{
                        printf("Offset %d: 0x%x -> 0x%x\n", i, dacrap[i] & 0x000000FF, buf[i] & 0x000000FF);
			offsetz[i]++;
		}
        }
        printf("*****\n");
}


void handle_offsetz()
{
	int zeta;
	for (zeta=0; zeta<=CRAPLEN; zeta++)
	{
		printf("OFFSET: %d\t%d\n", zeta, offsetz[zeta]);
	}
}



int main(int argc, char *argv[]) {
	struct sockaddr_in addr;
	int s, port = 0, len, counter, totalcounter, mu, last, seeder, x;
	char *host = NULL;
	unsigned int seed;
	struct timeval tv;

	printf("Generic Protocol fuzzer [propz to syzop]\n\n");

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

	for (s=0; s<=CRAPLEN; s++)
	{
		offsetz[s] = 0;
	}

        memset(&tv, 0, sizeof(tv));
        tv.tv_sec = TIMEOUT;
        tv.tv_usec = 0;


	memset(&addr, 0, sizeof(addr));


	signal(SIGPIPE, SIG_IGN); /* Ignore SIGPIPE */
        counter = 0;
        fprintf(stdout, "Fuzzing...\n");
        while(1) {
            counter++;
	    if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "Socket error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	    }
            setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));        //recv timeout
	    setsockopt(s,IPPROTO_TCP,TCP_NODELAY,&x,sizeof(x));         //disable nagles alg.

	    addr.sin_family = AF_INET;
	    addr.sin_port = htons(port);
	    addr.sin_addr.s_addr = inet_addr(host);
	    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                sleep(1);
                if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		    fprintf(stdout, "Unable to connect: %s\n", strerror(errno));
	            diffit();
		    handle_offsetz();
                    exit(0);
                }
	    }

	    len = send_crap();
	    corruptor(buf, len);         /* puts 1-17 random bytes into buf */
	    write(s, buf, len);
	    usleep(1000);
            write(s, second, sizeof(second) - 1);
            memset (&buf2, 0, sizeof(buf2));
            mu=recv(s,buf2,sizeof(buf2),0);
            if ( (mu != last) && (counter > 1) ) {
                    fprintf(stdout, "return buffer from scanned host just changed Counter=%d\n", counter);
                    fprintf(stdout, "expected %d return bytes...received %d bytes\n", last, mu);
                    diffit();
            }
            last = mu;
            totalcounter = 0;
	    close(s);
        }
	
	exit(EXIT_SUCCESS);
}

