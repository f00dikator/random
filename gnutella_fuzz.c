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

const char dacrap[] =
"\x47\x4E\x55\x54\x45\x4C\x4C\x41\x20\x43\x4F\x4E\x4E\x45\x43\x54"
"\x2F\x30\x2E\x36\x0D\x0A\x55\x73\x65\x72\x2D\x41\x67\x65\x6E\x74"
"\x3A\x20\x42\x65\x61\x72\x53\x68\x61\x72\x65\x20\x34\x2E\x33\x2E"
"\x35\x2E\x34\x0D\x0A\x41\x63\x63\x65\x70\x74\x2D\x45\x6E\x63\x6F"
"\x64\x69\x6E\x67\x3A\x20\x64\x65\x66\x6C\x61\x74\x65\x0D\x0A\x58"
"\x2D\x55\x6C\x74\x72\x61\x70\x65\x65\x72\x3A\x20\x46\x61\x6C\x73"
"\x65\x0D\x0A\x58\x2D\x51\x75\x65\x72\x79\x2D\x52\x6F\x75\x74\x69"
"\x6E\x67\x3A\x20\x30\x2E\x31\x0D\x0A\x4D\x61\x63\x68\x69\x6E\x65"
"\x3A\x20\x31\x2C\x38\x2C\x31\x39\x31\x2C\x31\x2C\x36\x34\x36\x0D"
"\x0A\x50\x6F\x6E\x67\x2D\x43\x61\x63\x68\x69\x6E\x67\x3A\x20\x30"
"\x2E\x31\x0D\x0A\x48\x6F\x70\x73\x2D\x46\x6C\x6F\x77\x3A\x20\x31"
"\x2E\x30\x0D\x0A\x4C\x69\x73\x74\x65\x6E\x2D\x49\x50\x3A\x20\x36"
"\x36\x2E\x35\x36\x2E\x31\x35\x2E\x31\x39\x39\x3A\x36\x33\x34\x36"
"\x0D\x0A\x52\x65\x6D\x6F\x74\x65\x2D\x49\x50\x3A\x20\x32\x32\x30"
"\x2E\x31\x36\x38\x2E\x31\x36\x35\x2E\x32\x31\x32\x0D\x0A\x47\x47"
"\x45\x50\x3A\x20\x30\x2E\x35\x0D\x0A\x58\x2D\x44\x65\x67\x72\x65"
"\x65\x3A\x20\x33\x32\x0D\x0A\x58\x2D\x55\x6C\x74\x72\x61\x70\x65"
"\x65\x72\x2D\x51\x75\x65\x72\x79\x2D\x52\x6F\x75\x74\x69\x6E\x67"
"\x3A\x20\x30\x2E\x31\x0D\x0A\x58\x2D\x4D\x61\x78\x2D\x54\x54\x4C"
"\x3A\x20\x34\x0D\x0A\x58\x2D\x44\x79\x6E\x61\x6D\x69\x63\x2D\x51"
"\x75\x65\x72\x79\x69\x6E\x67\x3A\x20\x30\x2E\x31\x0D\x0A\x58\x2D"
"\x50\x72\x6F\x62\x65\x2D\x51\x75\x65\x72\x69\x65\x73\x3A\x20\x30"
"\x2E\x31\x0D\x0A\x46\x50\x2D\x31\x61\x3A\x20\x31\x32\x38\x2C\xF0"
"\xC0\x56\xCB\x88\x66\x65\xA8\x7B\x95\x5C\x30\x72\x6C\xA7\x51\x88"
"\x8C\x49\x98\x32\xF4\x97\xFB\x6D\xC3\x5B\x68\xE6\x32\xAA\x44\x21"
"\x9E\x0D\x0A\x46\x50\x2D\x41\x75\x74\x68\x2D\x43\x68\x61\x6C\x6C"
"\x65\x6E\x67\x65\x3A\x20\x42\x41\x45\x4B\x42\x42\x55\x4A\x58\x4F"
"\x57\x50\x48\x4F\x44\x49\x53\x47\x58\x51\x4E\x44\x58\x4E\x4A\x50"
"\x33\x55\x4E\x4F\x45\x44\x0D\x0A\x0D\x0A";

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
	int s, port = 0, len, counter, totalcounter, mu, last, seeder;
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
                sleep(1);
                if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		    fprintf(stdout, "Unable to connect: %s\n", strerror(errno));
		    fprintf(stdout, "Counter : %d\n", counter);
	            diffit();
                    exit(0);
                }
	    }

	    len = send_crap();
	    corruptor(buf, len);         /* puts 1-17 random bytes into buf */
	    write(s, buf, len);
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

