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

char init[] =
"\x80\x2B\x01\x00\x02\x00\x12\x00\x00\x00\x10\x01\x00\x80\x07\x00"
"\xC0\x03\x00\x80\x06\x00\x40\x02\x00\x80\x04\x00\x80\x93\x63\xF8"
"\x1E\x90\x3C\x04\xAB\x68\x2B\x96\xED\x78\x12\xEF\xB5";

char second[] = 
"\x80\x8A\x02\x01\x00\x80\x00\x00\x00\x80\x00\x00\x98\xC0\x9A\xA0"
"\xE9\xC3\x20\x9C\xDD\xBE\x17\xF8\xF6\x9D\x6A\xAE\xC5\xE9\xA0\xD2"
"\x71\x61\x97\xCE\x71\xA1\x68\x7C\xE0\xFB\x8D\xA2\xAC\x84\x51\x68"
"\xB1\x51\xB7\x08\x5A\x29\x97\x04\x76\xD0\x96\x15\xD4\x1A\x07\x0B"
"\x60\xCF\x5C\x75\xEF\x57\x76\x0D\xE8\xE4\x80\x91\x37\xF5\xE7\x2F"
"\x78\x72\xA7\x9B\xBC\x4A\x27\x3C\xA1\x5D\x14\x99\x4E\x71\x96\x52"
"\x0D\xA8\xAE\x49\xF9\xF5\x22\xD4\x46\x78\x68\x9B\x21\x46\x90\x36"
"\xFD\xA7\xEC\x49\xFD\xF6\x01\xA5\x0D\xD5\x8E\x6A\xAD\x67\xB3\x7C"
"\x75\x09\xFA\xEC\xEB\x5C\x32\x39\xF0\x1A\x22\x33";

char third[] = 
"\x80\x21\x0A\x63\xD9\x02\x21\x65\x8C\x10\x37\xC8\x53\xFE\xB6\x84"
"\x76\xC9\x3D\xE4\x8C\x84\xB7\x4F\xED\xA5\x84\xF1\x4B\x26\x2B\x73"
"\x31\xCE\xC9";

char fourth[] = 
"\x80\x98\xC9\x30\x16\x06\x01\xA3\x87\x5F\x1F\xB7\x39\xF6\xE4\x9E"
"\x6D\xD4\xDA\x86\x6E\xA7\x4D\x67\x13\xE3\x05\x62\xF5\x61\x44\x55"
"\xAA\x69\xF9\xCB\xBE\x68\x71\x97\x02\x68\x0D\x4A\x75\xF5\xBA\xD9"
"\xC4\x85\x54\x1F\xB5\x8A\xA7\x57\x25\xC6\xF2\x78\x0A\x54\x16\x2F"
"\x08\xDD\xC6\x44\x90\x39\x84\x58\x0B\x76\x58\x67\x43\xAA\xA4\xCB"
"\x23\xD1\x2A\xC5\xEF\xDA\xC4\xE8\x15\xDA\xE4\x18\xB9\xE7\xE7\x6A"
"\x75\x16\x6F\x17\xC1\xD2\xAA\x73\x24\x13\xE5\xCF\xC7\x1E\x5C\xED"
"\x7A\xCF\x15\x31\xC3\x53\x5E\x6E\x13\xE5\xBA\x29\x23\x4D\x19\x56"
"\x0D\x0F\x2C\x54\x2D\xA5\x85\xD3\x69\x4D\xD7\x03\x17\x9D\xAC\xC8"
"\xDB\xF2\x24\xDA\xDC\xBE\x2F\xD4\x6B\x97";





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
        for (i=0; i < sizeof(buf); i++) {
                        printf(" 0x%x ", buf[i] & 0x000000FF);
			if ( (i % 16) == 15) printf("\n");
        }
        printf("*****\n");
}






int main(int argc, char *argv[]) {
	struct sockaddr_in addr;
	int s, port = 0, first = 1, len, counter, mu ;
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
            setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));

	    addr.sin_family = AF_INET;
	    addr.sin_port = htons(port);
	    addr.sin_addr.s_addr = inet_addr(host);
	    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stdout, "Unable to connect: %s\n", strerror(errno));
		if (!first) {
			diffit();
                }
	    }
	    first = 0;
            
	    memcpy(buf, init, sizeof(init)-1);
	    write(s, buf, sizeof(buf)-1);
            memset (&buf2, 0, sizeof(buf2));
            mu=recv(s,buf2,sizeof(buf2),0);

            memcpy(buf, second, sizeof(second)-1);
	    write(s, buf, sizeof(buf)-1);
	    memset (&buf2, 0, sizeof(buf2));
	    mu=recv(s,buf2,sizeof(buf2),0);

	    memcpy(buf,third,sizeof(third)-1);
	    write(s, buf, sizeof(buf)-1);
	    memset (&buf2, 0, sizeof(buf2));
	    mu=recv(s,buf2,sizeof(buf2),0);

            memcpy(buf,fourth,sizeof(fourth)-1);
	    corruptor(buf, sizeof(buf)-1);
	    write(s,buf,sizeof(buf)-1);
	    memset (&buf2, 0, sizeof(buf2));
	    mu=recv(s,buf2,sizeof(buf2),0);

	    close(s);
        }
	
	exit(EXIT_SUCCESS);
}

