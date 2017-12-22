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

int counter, diffcounter;

const char fuzzpacket[] =
"\x10\xf4\xa9\x6f\x69\x36\x0d\x23\x5b\xf4\xf8\xc2\xcf\xd0\x8b\xf7"
"\x50\xf9\x71\x2f\x85\x25\xea\xe1\x4b\x9d\x78\xef\x6f\x72\x20\x24"
"\x05\xcd\x5d\xdd\x67\x64\xa7\xc5\xcd\x09\x9a\xb9\x86\x5c\xc7\xca"
"\x59\xaa\x9d\x14\xbd\xd9\xc6\xb0\x59\x06\x99\xf7\xc2\x45\xfa\x87"
"\x79\xe0\xdb\xae\xe2\xcf\xce\x28\xdc\x45\x2b\x05\x01\x67\xda\xa9"
"\x7b\x17\xbe\xed\x81\xef\xbf\x64\x6d\x4a\x71\xb8\x7c\x7c\x66\x32"
"\x21\x21\x0d\x58\x06\x93\x45\xb0\xa0\x75\x82\xa3\x6d\x6c\x9a\x7d"
"\x82\x8e\x26\x5e\x8a\x66\xed\x4d\x52\x61\x7d\x16\xbe\x22\x19\x6e"
"\x2f\x29\xda\x64\x41\x8d\xba\xe2\x06\x8c\x50\x81\x47\x4c\xca\xe1"
"\x4d\xe5\xc2\xc6\x5e\x51\x47\x5d\xd3\x7f\x87\x9c\xd7\x86\x16\xc7"
"\x79\xaf\xfc\xd4\x06\x54\x2e\x7a\x7f\xce\x92\x79\xd8\x34\x98\xe4"
"\x61\xcd\x79\x06\x77\x76\x41\xd9\x97\x28\x33\x68\x5c\x3d\x6c\x70"
"\x77\xb9\xca\x4d\xaf\xb8\x79\xbc\x79\x07\x1d\xbb\x2f\xcf\x99\x8d"
"\x51\x7a\x12\xef\xd3\x7b\x4f\x88\x62\x2d\x35\x20\xbe\xbb\x14\x63"
"\xba\x90\xb5\xf3";


#define FUZZLEN (sizeof(fuzzpacket)-1)

int offsetz[FUZZLEN] = {};


void mangle(char *buf, int len) {
	int phi, omega, moffset, divisor;
	divisor = ((FUZZLEN / 8) % 15) + 1;
	phi = rand() % divisor + 1; 

	for (omega=0; omega < phi; omega++)
	{
		moffset = rand() % len;
		buf[moffset] = rand() % 256;
	}
}




void diffit() {
	int i;
	diffcounter++;	
	time_t mytime;
	mytime = time(NULL);

        printf("DIFF %s\n",asctime(localtime(&mytime)) );
        for (i=0; i < FUZZLEN; i++)
        {
                if (buf[i] != fuzzpacket[i])
		{
                        printf("Offset %d: 0x%x -> 0x%x\n", i, fuzzpacket[i] & 0x000000FF, buf[i] & 0x000000FF);
			offsetz[i]++;
		}
        }
        printf("*****\n");
}


void handle_offsetz()
{
	int zeta;
	double bling;
	if (diffcounter == 0)
		return ;
	bling = diffcounter;
	for (zeta=0; zeta<=FUZZLEN; zeta++)
	{
		printf("OFFSET: %d\t%d\t(%f)\n", zeta, offsetz[zeta], offsetz[zeta] / bling);
	}
	return;
}


void handle_offset()
{
	handle_offsetz();
	exit(0);
}


int main(int argc, char *argv[]) 
{
	struct sockaddr_in addr;
	int s, port = 0, len, totalcounter, mu, last, seeder, x;
	char *host = NULL;
	unsigned int seed;
	struct timeval tv;
  	signal(SIGTERM, handle_offset);
  	signal(SIGINT, handle_offset);
  	signal(SIGQUIT, handle_offset);
  	signal(SIGHUP, handle_offset);
  	signal(SIGALRM, handle_offset);



	printf("Generic Protocol fuzzer [jwl]\n\n");

        if (argc < 3) 
	{
                fprintf(stderr, "Use: %s [ip] [port]\n", argv[0]);
                exit(1);
        }
	

	host = argv[1];
	port = atoi(argv[2]);
	if ((port < 1) || (port > 65535)) 
	{
		fprintf(stderr, "Port out of range (%d)\n", port);
		exit(1);
	}

	for (s=0; s<=FUZZLEN; s++)
	{
		offsetz[s] = 0;
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
            setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));        //recv timeout
	    setsockopt(s,IPPROTO_TCP,TCP_NODELAY,&x,sizeof(x));         //disable nagles alg.

	    addr.sin_family = AF_INET;
	    addr.sin_port = htons(port);
	    addr.sin_addr.s_addr = inet_addr(host);
	    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) 
	    {
                sleep(1);
                if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) 
		{
		    fprintf(stdout, "Unable to connect: %s\n", strerror(errno));
	            diffit();
		    handle_offsetz();
                    exit(0);
                }
	    }

            memcpy(buf, fuzzpacket, FUZZLEN);

	    mangle(buf, FUZZLEN);         /* puts 1-17 random bytes into buf */
	    write(s, buf, FUZZLEN);
	    //write(s,buf, rand() % FUZZLEN);   //new stuff
            memset (&buf2, 0, sizeof(buf2));
            mu=recv(s,buf2,sizeof(buf2),0);
            if ( (mu != last) && (counter > 1) ) 
	    {
                    fprintf(stdout, "return buffer from scanned host just changed Counter=%d\n", counter);
                    fprintf(stdout, "expected %d return bytes...received %d bytes\n", last, mu);
                    diffit();
            }
            last = mu;
            totalcounter = 0;
	    close(s);
	    sleep(1);				//yo, remove this if you want to silly DoS
        }
	
	exit(EXIT_SUCCESS);
}

