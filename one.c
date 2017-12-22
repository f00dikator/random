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
char recvbuf[8192];

#define TIMEOUT 3

const char req[] =
"\x00\x9C\x00\x01\x1A\x2B\x3C\x4D\x00\x01\x00\x00\x01\x00\x00\x00"
"\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x0A\x28\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x4D\x69\x63\x72"
"\x6F\x73\x6F\x66\x74\x20\x57\x69\x6E\x64\x6F\x77\x73\x20\x4E\x54"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

const char dacrap[] = 
"\x00\xA8\x00\x01\x1A\x2B\x3C\x4D\x00\x07\x00\x00\x40\x00\xF2\xBC"
"\x00\x00\x01\x2C\x05\xF5\xE1\x00\x00\x00\x00\x03\x00\x00\x00\x03"
"\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00";


char xbuf[1024];

#define CRAPLEN (sizeof(dacrap)-1)

#define TCP_NODELAY 0

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
		if ((l < 4) || (l > 7))                             //bytes 4,5,6,7 == cookie
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
	int i, s, port = 0, len, counter, mu, last, seeder;
	char *host = NULL;
	unsigned int seed;
	struct timeval tv;

	printf("Generic Protocol fuzzer\n\n");

        if (argc < 3) {
                fprintf(stderr, "Use: %s [ip] [port] <seed>\n", argv[0]);
                exit(1);
        }
	

	host = argv[1];
	port = atoi(argv[2]);
        if (argc == 4) seeder = atoi(argv[3]);
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
	//seed = (2058280217);                  //remove this beey-otch
	srand(seed);

	for (i=0; i < sizeof(xbuf) - 1 ; i++) {
		xbuf[i] = rand() % 256;
	}
	xbuf[i] = '\0';

        memset(&tv, 0, sizeof(tv));
        tv.tv_sec = TIMEOUT;
        tv.tv_usec = 0;
        setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv)); 

	memset(&addr, 0, sizeof(addr));


        counter = 0;
        fprintf(stderr, "Fuzzing...\n");
        while(1) {
            counter++;
	    if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "Socket error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	    }
	    signal(SIGPIPE, SIG_IGN);
            setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));     // timeout on recv()
	    int x;
	    //setsockopt(s,IPPROTO_TCP,TCP_NODELAY,&x,sizeof(x));      //disable nagle's alg.
	    
	    addr.sin_family = AF_INET;
	    addr.sin_port = htons(port);
	    addr.sin_addr.s_addr = inet_addr(host);
	    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		sleep (1);
		if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
			fprintf(stdout, "Unable to connect: %s\n", strerror(errno));
			diffit();
			exit(0);
                }
	    }
	    

	    write (s, req, sizeof(req) - 1);
	    memset (&buf,0,sizeof(buf));
	    len = send_crap();
	    corruptor(buf, len);         /* puts 1-17 random bytes into buf */
	    usleep (1000);
	    write(s, buf, len);
            mu=recv(s,recvbuf,sizeof(recvbuf),0);
            if ( (mu != last) && (counter > 1) ) {
                    diffit();
            }
	    if ( (counter % 4) == 0 ) {
		    corruptor(xbuf, sizeof(xbuf) -1);
		    write(s,xbuf, sizeof(xbuf)-1);
            }
            last = mu;
	    close(s);
        }
	
	exit(EXIT_SUCCESS);
}

