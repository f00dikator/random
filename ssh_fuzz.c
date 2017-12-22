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
"\x53\x53\x48\x2D\x32\x2E\x30\x2D\x4E\x65\x73\x73\x75\x73\x0A";

const char dacrap[] =
"\x00\x00\x00\xC4\x07\x14\x1E\xB0\x3A\x01\x80\xE2\x99\x1E\x6A\xA4"
"\x78\xAB\xBB\x4C\x1A\xD6\x00\x00\x00\x3D\x64\x69\x66\x66\x69\x65"
"\x2D\x68\x65\x6C\x6C\x6D\x61\x6E\x2D\x67\x72\x6F\x75\x70\x2D\x65"
"\x78\x63\x68\x61\x6E\x67\x65\x2D\x73\x68\x61\x31\x2C\x64\x69\x66"
"\x66\x69\x65\x2D\x68\x65\x6C\x6C\x6D\x61\x6E\x2D\x67\x72\x6F\x75"
"\x70\x31\x2D\x73\x68\x61\x31\x00\x00\x00\x0F\x73\x73\x68\x2D\x72"
"\x73\x61\x2C\x73\x73\x68\x2D\x64\x73\x73\x00\x00\x00\x0C\x62\x6C"
"\x6F\x77\x66\x69\x73\x68\x2D\x63\x62\x63\x00\x00\x00\x0C\x62\x6C"
"\x6F\x77\x66\x69\x73\x68\x2D\x63\x62\x63\x00\x00\x00\x09\x68\x6D"
"\x61\x63\x2D\x73\x68\x61\x31\x00\x00\x00\x09\x68\x6D\x61\x63\x2D"
"\x73\x68\x61\x31\x00\x00\x00\x04\x6E\x6F\x6E\x65\x00\x00\x00\x04"
"\x6E\x6F\x6E\x65\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00";



#define CRAPLEN (sizeof(dacrap)-1)



int send_crap() {
	memcpy(buf, dacrap, CRAPLEN);
	return CRAPLEN;
}



void corruptor(char *buf, int len) {
int cb, i, l;

	cb = rand()%8+1; /* bytes to corrupt */

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
	    write(s, init, sizeof(init) - 1);
	    mu=recv(s,buf2,sizeof(buf2),0);
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

