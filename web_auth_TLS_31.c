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
"\x16\x03\x01\x00\x41\x01\x00\x00\x3D\x03\x01\x40\x81\xE8\x01\xCA"
"\x9D\xCB\xBF\xF0\x17\x6B\xEC\x77\xCA\x29\x08\x1B\xCF\x89\x5D\x55"
"\xFE\x21\x56\x7D\x6F\x2F\x6B\x18\xD4\xDB\x27\x00\x00\x16\x00\x04"
"\x00\x05\x00\x0A\x00\x09\x00\x64\x00\x62\x00\x03\x00\x06\x00\x13"
"\x00\x12\x00\x63\x01\x00";

char second[] = 
"\x16\x03\x01\x00\x86\x10\x00\x00\x82\x00\x80\x6B\xDC\x09\xEC\xA6"
"\x35\xD6\x25\x2C\x26\x45\x3F\x37\x49\xBF\xF9\x53\xB2\x50\x98\xA5"
"\xA5\x21\x66\xB0\x73\x95\xA7\x72\x90\x43\xA9\xCA\x8B\x6B\x98\x55"
"\x88\x5F\x73\x39\xD8\x1F\x57\xE6\xE4\x55\xC3\x74\x83\x15\x18\x1F"
"\xCB\x21\x5F\x5B\x2A\xD6\x3B\x2F\x98\xB9\xCF\x08\xF2\xC8\xEF\x61"
"\x8C\x8B\x00\x96\x6B\xD5\x87\xA0\x01\xC0\xD8\x80\x25\xF4\x74\x33"
"\xDA\x98\xBB\xFE\x65\x15\xB6\x68\x4A\x90\x01\x39\xCD\xFF\x26\x24"
"\x74\xF5\x12\x78\xD6\x5B\x80\x52\xDB\xB9\x29\xBE\x56\xF6\x8B\x4C"
"\xC5\x69\xED\xF5\x4C\x6D\x3E\xE5\x5C\x83\x8A\x14\x03\x01\x00\x01"
"\x01\x16\x03\x01\x00\x20\xE3\x12\x70\x08\x45\xF5\x3A\x71\x96\xB7"
"\x30\xCE\xF9\xD8\xAC\x80\x65\xC6\x17\xF6\x74\x09\x8D\x73\xC5\x7B"
"\x2F\x22\x12\x06\x01\x8A";

char third[] = 
"\x17\x03\x01\x00\x98\x34\x60\xAC\x5A\xD5\xC4\x20\x79\x9B\x12\x95"
"\x27\x55\x7E\x75\xCF\x47\x35\xFF\x2E\x35\x63\xA7\x72\x0C\x19\x82"
"\x1A\x12\x3B\x50\xBF\x85\xE3\x25\x2D\x99\x92\x83\x61\x48\xF1\x4A"
"\x1E\x22\x21\x76\x0F\x10\x30\x3C\x59\xD8\x46\xAC\x7B\x88\xFB\xFE"
"\x93\xF0\x4E\x78\x15\x39\xB1\xA0\xC1\x66\x86\x46\x33\x9A\xF4\xD7"
"\x18\x44\x52\x82\x3E\xCE\x13\x4D\x9C\xED\xCD\x42\x7B\x3D\x8B\x9A"
"\x6C\x0A\xBA\x5D\xA8\xD1\x6C\x64\xFA\xA0\xBC\xD4\x5E\x82\xA7\xFB"
"\xB7\xA9\x40\x34\x20\x27\x5F\x70\xB4\x13\x0A\xB4\xE6\xA0\xC5\xEB"
"\xDC\xC0\xE8\x39\x8F\x3F\x65\xFE\xCA\x8E\x5E\x56\xEC\x3D\xB4\xAF"
"\x7B\xB7\x5C\xDC\xF4\x34\x8F\x65\x83\xE8\x45\x7F\xA3";





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
	    corruptor(buf, sizeof(buf)-1);
	    write(s, buf, sizeof(buf)-1);
	    memset (&buf2, 0, sizeof(buf2));
	    mu=recv(s,buf2,sizeof(buf2),0);

	    close(s);
        }
	
	exit(EXIT_SUCCESS);
}

