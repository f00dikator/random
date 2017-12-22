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
"\x80\x7A\x01\x03\x01\x00\x51\x00\x00\x00\x20\x00\x00\x16\x00\x00"
"\x13\x00\x00\x0A\x07\x00\xC0\x00\x00\x66\x00\x00\x05\x00\x00\x04"
"\x03\x00\x80\x01\x00\x80\x08\x00\x80\x00\x00\x65\x00\x00\x64\x00"
"\x00\x63\x00\x00\x62\x00\x00\x61\x00\x00\x60\x00\x00\x15\x00\x00"
"\x12\x00\x00\x09\x06\x00\x40\x00\x00\x14\x00\x00\x11\x00\x00\x08"
"\x00\x00\x06\x00\x00\x03\x04\x00\x80\x02\x00\x80\x65\xC4\xFF\xCD"
"\x05\xAE\x9E\x6C\xD9\xC8\x46\x28\x61\xE3\xE8\xB8\x7E\xEC\x6B\xD8"
"\x37\x7A\x16\x3E\x98\x60\xC5\x10\x5D\x3A\xB7\xB7";

const char dacrap[] = 
"\x16\x03\x01\x00\x86\x10\x00\x00\x82\x00\x80\x19\xA3\xB4\x51\xDD"
"\x63\x67\xE9\x87\xCC\x76\x4A\x08\xB6\xBC\x34\xAD\x3B\x14\xF3\x9B"
"\xB6\x9F\xA4\x23\x88\xF1\x9E\x82\xF8\x01\xF5\x91\x3A\xE7\xA7\xED"
"\x45\x42\x76\x77\x80\xB7\xC1\x79\x6F\xC8\x43\x23\x2A\x0B\xEA\x60"
"\xC0\x83\x15\x1A\x96\x5C\x4E\xA8\xF6\x5B\x35\x59\x65\x3A\xB3\x5B"
"\xA3\xCD\x04\x55\x69\xA6\x8B\x95\xE6\xC5\xB4\x65\x9D\x48\x81\xC0"
"\x80\xCB\xF2\xB8\x36\x42\x43\x27\xD6\xCB\xF1\xA8\x55\x2F\xBE\xDD"
"\xFE\x60\x71\xA6\xF2\xBE\xC7\x6C\x4D\x44\x4C\xF7\x3A\x66\xBE\xB8"
"\xF9\xB9\x27\x8D\x02\x1C\x82\xFB\xDA\xC2\x4A\x14\x03\x01\x00\x01"
"\x01\x16\x03\x01\x00\x28\xC4\xD1\x52\x23\x4D\x2A\x34\x9B\xA3\x4C"
"\x82\xF4\xB1\xB7\xEA\x6B\x8B\x41\x4B\xC0\x90\x03\x79\x92\x0F\x69"
"\x63\x52\xB3\xFB\x92\x91\xE0\x61\xD0\xEC\xD4\x7C\x02\x58";

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
                    exit(0);
                }
	    }

	    len = send_crap();
	    corruptor(buf, len);         /* puts 1-17 random bytes into buf */
	    write(s, init, sizeof(init) -1);
	    usleep(1000);
	    write(s, buf, len);
	    write(s,buf, rand() % len);   //new stuff
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

