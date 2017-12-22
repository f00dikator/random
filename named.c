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
char buf2[1024];

#define TIMEOUT 3

const char dacrap[] =
"\x00\x02\x81\x80\x00\x01\x00\x09\x00\x09\x00\x00\x03\x77\x77\x77"
"\x05\x79\x61\x68\x6F\x6F\x03\x63\x6F\x6D\x00\x00\x01\x00\x01\xC0"
"\x0C\x00\x05\x00\x01\x00\x00\x07\x08\x00\x16\x03\x77\x77\x77\x05"
"\x79\x61\x68\x6F\x6F\x06\x61\x6B\x61\x64\x6E\x73\x03\x6E\x65\x74"
"\x00\xC0\x2B\x00\x01\x00\x01\x00\x00\x00\x1E\x00\x04\xD8\x6D\x75"
"\xCD\xC0\x2B\x00\x01\x00\x01\x00\x00\x00\x1E\x00\x04\xD8\x6D\x75"
"\xCE\xC0\x2B\x00\x01\x00\x01\x00\x00\x00\x1E\x00\x04\xD8\x6D\x76"
"\x4F\xC0\x2B\x00\x01\x00\x01\x00\x00\x00\x1E\x00\x04\xD8\x6D\x75"
"\x6A\xC0\x2B\x00\x01\x00\x01\x00\x00\x00\x1E\x00\x04\xD8\x6D\x75"
"\x6B\xC0\x2B\x00\x01\x00\x01\x00\x00\x00\x1E\x00\x04\xD8\x6D\x75"
"\x6C\xC0\x2B\x00\x01\x00\x01\x00\x00\x00\x1E\x00\x04\xD8\x6D\x75"
"\x6D\xC0\x2B\x00\x01\x00\x01\x00\x00\x00\x1E\x00\x04\xD8\x6D\x75"
"\x6E\xC0\x35\x00\x02\x00\x01\x00\x02\xA3\x00\x00\x05\x02\x7A\x66"
"\xC0\x35\xC0\x35\x00\x02\x00\x01\x00\x02\xA3\x00\x00\x05\x02\x7A"
"\x68\xC0\x35\xC0\x35\x00\x02\x00\x01\x00\x02\xA3\x00\x00\x07\x04"
"\x61\x2D\x39\x33\xC0\x35\xC0\x35\x00\x02\x00\x01\x00\x02\xA3\x00"
"\x00\x0C\x04\x75\x73\x65\x32\x04\x61\x6B\x61\x6D\xC0\x3C\xC0\x35"
"\x00\x02\x00\x01\x00\x02\xA3\x00\x00\x07\x04\x75\x73\x65\x34\xC1"
"\x07\xC0\x35\x00\x02\x00\x01\x00\x02\xA3\x00\x00\x07\x04\x75\x73"
"\x77\x35\xC1\x07\xC0\x35\x00\x02\x00\x01\x00\x02\xA3\x00\x00\x08"
"\x05\x61\x73\x69\x61\x33\xC1\x07\xC0\x35\x00\x02\x00\x01\x00\x02"
"\xA3\x00\x00\x0A\x07\x6E\x73\x31\x2D\x31\x35\x39\xC1\x07\xC0\x35"
"\x00\x02\x00\x01\x00\x02\xA3\x00\x00\x05\x02\x7A\x63\xC0\x35"
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
        exit(0);
}






int main(int argc, char *argv[]) {
	struct sockaddr_in addr, cliaddr;
	int s, port = 0, first = 1, len, counter, totalcounter, mu=0, last, seeder, childpid, connfd;
	unsigned int seed;
	struct timeval tv;


        if (argc < 2) {
                fprintf(stderr, "Use: %s [port] <seed>\n", argv[0]);
                exit(1);
        }
	

	port = atoi(argv[1]);
        if (argc == 3) seeder = atoi(argv[2]);
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


        counter = 0;
        while(1) {
	    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		fprintf(stderr, "Socket error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	    }
            //setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
	    addr.sin_family = AF_INET;
	    addr.sin_port = htons(port);
	    addr.sin_addr.s_addr = htonl(INADDR_ANY);
	    bind(s, (struct sockaddr *) &addr, sizeof(addr));
	    //listen(s, 1024);
            fprintf(stderr, "Listening for incoming connections on %d\n", port); 
            while (mu <= 0) {
		    mu=recv(s,buf2,sizeof(buf2),0);
		    if (mu > 1) {
			    fprintf(stderr,"recvd %d bytes on s\n", mu); 
			    len = send_crap();
			    corruptor(buf, len);
			    send(s, buf, len, 0); 
		    } else { 
			    usleep(1000);
	            }
	    }
	    mu = 0;
        }
	close(s);
	exit(EXIT_SUCCESS);
}

