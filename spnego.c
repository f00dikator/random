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

const char init[] =
"\x00\x00\x00\x85\xFF\x53\x4D\x42\x72\x00\x00\x00\x00\x18\x53\xC8"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFE"
"\x00\x00\x00\x00\x00\x62\x00\x02\x50\x43\x01\x4E\x45\x54\x57\x4F"
"\x52\x4B\x0B\x50\x52\x4F\x47\x52\x41\x4D\xF0\x31\x2E\x30\x00\x02"
"\x4C\x41\x4E\x4D\x41\x4E\x31\x2E\x30\x00\x02\x57\x69\x6E\x64\x6F"
"\x77\x73\x77\x66\x6F\x72\x34\x57\x6F\x72\x6B\x67\x72\x6F\x75\x70"
"\x73\x96\x33\x2E\x31\x61\x00\x02\x4C\x4D\x31\x2E\x32\x58\x30\x30"
"\x32\x00\x02\x4C\x41\x4E\x4D\x41\x4E\x32\x2E\x31\x00\x02\x4E\x54"
"\x20\x4C\x4D\x20\x30\x2E\x31\x32\x00";

const char dacrap[] = 
"\x00\x00\x00\x9E\xFF\x53\x4D\x42\x73\x00\x00\x00\x00\x09\x01\xE8"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x27\x33"
"\x00\x00\x00\x00\x0C\xFF\x00\x00\x00\x05\xFF\x04\x00\x02\x00\x00"
"\x00\x00\x00\x44\x00\x00\x00\x00\x00\xFF\x00\x00\xFF\x63\x00\x60"
"\x58\x06\xFF\x06\xFF\x06\x0F\x05\x0F\x02\xFF\x06\xFF\xFF\xFF\xFF"
"\x06\x00\x06\x00\x2A\x00\x00\x00\x0A\x00\x0A\x00\x20\x00\x00\x00"
"\x42\x4C\x49\x4E\x47\x42\x4C\x49\x4E\x47\x4D\x53\x48\x4F\x4D\x45"
"\x2A\xFF\x7F\x74\x6F\xFF\x0A\x0B\x9E\xFF\xE6\x56\x73\x37\x57\x37"
"\x0A\x0B\x0C\x00\x0A\xCB\x00\x00\x31\x33\x70\x0A\xDD\xFF\xC4\xAB"
"\x0A\x0A\x00\x01\x00\x00\x0A\x0A\x00\x01\x0A\x0A\x00\x0A\x0A\x01"
"\x0A\x01\xFF"
;

#define CRAPLEN (sizeof(dacrap)-1)



int send_crap() {
	memcpy(buf, dacrap, CRAPLEN);
	return CRAPLEN;
}



void corruptor(char *buf, int len) {
        int cb, i, l;

	cb = rand()%15+1; 

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
	int s, port = 0, first = 1, len, counter, totalcounter, mu, last, seeder;
	char *host = NULL;
	unsigned int seed;
	struct timeval tv;

	printf("Generic Protocol fuzzer [propz to syzop]\n\n");

        if (argc < 3) {
                fprintf(stderr, "Use: %s [ip] [port]\n", argv[0]);
                exit(1);
        }
 
        srand(11637);	

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
        while(1) 
	{
            counter++;
	    if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
	    {
		fprintf(stderr, "Socket error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	    }
            setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));

	    addr.sin_family = AF_INET;
	    addr.sin_port = htons(port);
	    addr.sin_addr.s_addr = inet_addr(host);
	    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) 
	    {
		sleep (1);
		if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) 
		{
		    fprintf(stdout, "Unable to connect: %s\n", strerror(errno));
	            diffit();
		    exit(0);
		}
	    }


	    len = send_crap();
	    corruptor(buf, len);         
	    write (s, init, sizeof(init)-1);
	    mu=recv(s,buf2,sizeof(buf2),0);
	    if (mu <= 0)
	    {
		    fprintf(stderr,"recv error with init\n");
	    }
	    write(s, buf, len);
            memset (&buf2, 0, sizeof(buf2));
            mu=recv(s,buf2,sizeof(buf2),0);
            if ( (mu != last) && (counter > 1) ) 
	    {
                    fprintf(stdout, "return buffer from scanned host just changed Counter=%d\n", counter);
                    fprintf(stdout, "expected %d return bytes...received %d bytes\n", last, mu);
                    diffit();
            }
            last = mu;
	    close(s);
        }
	
	exit(EXIT_SUCCESS);
}

