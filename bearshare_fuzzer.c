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
"\x47\x45\x54\x20\x2F\x75\x72\x69\x2D\x72\x65\x73\x2F\x4E\x32\x52"
"\x3F\x75\x72\x6E\x3A\x73\x68\x61\x31\x3A\x50\x51\x41\x51\x48\x34"
"\x35\x4B\x35\x54\x57\x4D\x4B\x33\x53\x4E\x32\x57\x51\x42\x43\x51"
"\x47\x53\x4C\x59\x54\x4B\x45\x49\x57\x46\x20\x48\x54\x54\x50\x2F"
"\x31\x2E\x31\x0D\x0A\x43\x6F\x6E\x6E\x65\x63\x74\x69\x6F\x6E\x3A"
"\x20\x4B\x65\x65\x70\x2D\x41\x6C\x69\x76\x65\x0D\x0A\x48\x6F\x73"
"\x74\x3A\x20\x38\x30\x2E\x32\x32\x39\x2E\x31\x33\x37\x2E\x31\x38"
"\x38\x3A\x36\x33\x34\x36\x0D\x0A\x55\x73\x65\x72\x2D\x41\x67\x65"
"\x6E\x74\x3A\x20\x42\x65\x61\x72\x53\x68\x61\x72\x65\x20\x34\x2E"
"\x32\x2E\x39\x0D\x0A\x52\x61\x6E\x67\x65\x3A\x20\x62\x79\x74\x65"
"\x73\x3D\x30\x2D\x36\x32\x33\x35\x0D\x0A\x43\x6F\x6E\x74\x65\x6E"
"\x74\x2D\x44\x69\x73\x70\x6F\x73\x69\x74\x69\x6F\x6E\x3A\x20\x69"
"\x6E\x6C\x69\x6E\x65\x3B\x20\x66\x69\x6C\x65\x6E\x61\x6D\x65\x3D"
"\x4C\x41\x4D\x50\x45\x5F\x46\x2E\x57\x41\x56\x0D\x0A\x58\x2D\x51"
"\x75\x65\x75\x65\x3A\x20\x30\x2E\x31\x0D\x0A\x58\x2D\x47\x6E\x75"
"\x74\x65\x6C\x6C\x61\x2D\x43\x6F\x6E\x74\x65\x6E\x74\x2D\x55\x52"
"\x4E\x3A\x20\x75\x72\x6E\x3A\x73\x68\x61\x31\x3A\x50\x51\x41\x51"
"\x48\x34\x35\x4B\x35\x54\x57\x4D\x4B\x33\x53\x4E\x32\x57\x51\x42"
"\x43\x51\x47\x53\x4C\x59\x54\x4B\x45\x49\x57\x46\x0D\x0A\x46\x50"
"\x2D\x41\x75\x74\x68\x2D\x43\x68\x61\x6C\x6C\x65\x6E\x67\x65\x3A"
"\x20\x52\x58\x42\x34\x55\x57\x55\x48\x34\x50\x47\x35\x4C\x53\x37"
"\x4E\x4D\x33\x44\x36\x49\x41\x44\x53\x47\x51\x56\x4F\x55\x48\x43"
"\x32\x0D\x0A\x0D\x0A"
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
	            diffit();
                    exit(0);
                }
	    }

	    len = send_crap();
	    //corruptor(buf, len);         /* puts 1-17 random bytes into buf */
	    //Offset 68: 0xa -> 0xb4
	    //Offset 74: 0x63 -> 0x18
	    //Offset 75: 0x74 -> 0x57
	    //Offset 102: 0x32 -> 0xcb
	    //Offset 152: 0x67 -> 0x5b
	    //Offset 157: 0x79 -> 0xbc
	    //Offset 195: 0x6e -> 0x7
	    //Offset 199: 0x66 -> 0x7c
	    //Offset 263: 0x73 -> 0x46
	    //buf[68] = "\xB4";
	    //buf[74] = "\x18";
	    //buf[75] = "\x57";
	    //buf[102] = "\xCB";
	    //buf[152] = "\x5B";
	    //buf[157] = "\xBC";
	    //buf[195] = "\x07";
	    //buf[199] = "\x7C";
	    //buf[263] = "\x46";

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

