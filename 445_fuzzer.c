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
"\x00\x00\x00\xA4\xFF\x53\x4D\x42\x72\x00\x00\x00\x00\x08\x01\xC8"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x4D\x0B"
"\x00\x00\xBB\x9A\x00\x81\x00\x02\x50\x43\x20\x4E\x45\x54\x57\x4F"
"\x52\x4B\x20\x50\x52\x4F\x47\x52\x41\x4D\x20\x31\x2E\x30\x00\x02"
"\x4D\x49\x43\x52\x4F\x53\x4F\x46\x54\x20\x4E\x45\x54\x57\x4F\x52"
"\x4B\x53\x20\x31\x2E\x30\x33\x00\x02\x4D\x49\x43\x52\x4F\x53\x4F"
"\x46\x54\x20\x4E\x45\x54\x57\x4F\x52\x4B\x53\x20\x33\x2E\x30\x00"
"\x02\x4C\x41\x4E\x4D\x41\x4E\x31\x2E\x30\x00\x02\x4C\x4D\x31\x2E"
"\x32\x58\x30\x30\x32\x00\x02\x53\x61\x6D\x62\x61\x00\x02\x4E\x54"
"\x20\x4C\x41\x4E\x4D\x41\x4E\x20\x31\x2E\x30\x00\x02\x4E\x54\x20"
"\x4C\x4D\x20\x30\x2E\x31\x32\x00";

const char dacrap[] =
"\x00\x00\x00\xD5\xFF\x53\x4D\x42\x73\x00\x00\x00\x00\x08\x01\xC8"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\xBB\x9A\x0C\xFF\x00\x00\x00\x01\x40\x02\x00\x01\x00\x00"
"\x00\x00\x00\x68\x00\x00\x00\x00\x00\x5C\x00\x00\x80\x9A\x00\x60"
"\x84\x00\x00\x00\x62\x06\x83\x00\x00\x06\x2B\x06\x01\x05\x05\x02"
"\xA0\x82\x00\x53\x30\x81\x50\xA0\x0E\x30\x0C\x06\x0A\x2B\x06\x01"
"\x04\x01\x82\x37\x02\x02\x0A\xA3\x3E\x30\x3C\xA0\x30\x3B\x2E\x04"
"\x81\x01\x25\x24\x81\x27\x04\x01\x00\x24\x22\x24\x20\x24\x18\x24"
"\x16\x24\x14\x24\x12\x24\x10\x24\x0E\x24\x0C\x24\x0A\x24\x08\x24"
"\x06\x24\x04\x24\x02\x04\x00\x04\x82\x00\x02\x39\x25\xA1\x08\x04"
"\x06\x4E\x65\x73\x73\x75\x73\x57\x00\x69\x00\x6E\x00\x64\x00\x6F"
"\x00\x77\x00\x73\x00\x00\x00\x00\x00\x00\x00\x19\x00\x02\x00\x4E"
"\x00\x65\x00\x73\x00\x73\x00\x75\x00\x73\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x19\x00\x02\x00\x00\x00";

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
		    fprintf(stderr,"recv error with init mu=%d\n",mu);
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

