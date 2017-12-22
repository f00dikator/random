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

const char motherfuzzer[] =
"\x11\x02\xE5\x42\x0A\x0A\x0A\x07\x00\x8A\x00\xBB\x00\x00\x20\x45"
"\x49\x45\x42\x45\x4D\x45\x4A\x45\x46\x43\x41\x43\x41\x43\x41\x43"
"\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x00"
"\x20\x46\x48\x45\x50\x46\x43\x45\x4C\x45\x48\x46\x43\x45\x50\x46"
"\x46\x46\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x42"
"\x4F\x00\xFF\x53\x4D\x42\x25\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x11\x00\x00\x21\x00\x00\x00\x00\x00\x00\x00\x00\x00\xE8"
"\x03\x00\x00\x00\x00\x00\x00\x00\x00\x21\x00\x56\x00\x03\x00\x01"
"\x00\x00\x00\x02\x00\x32\x00\x5C\x4D\x41\x49\x4C\x53\x4C\x4F\x54"
"\x5C\x42\x52\x4F\x57\x53\x45\x00\x0F\x00\x80\xFC\x0A\x00\x48\x41"
"\x4C\x49\x45\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00"
"\x03\x10\x05\x00\x0F\x01\x55\xAA\x00"
;

#define FUZZLEN (sizeof(motherfuzzer)-1)

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
                if (buf[i] != motherfuzzer[i])
		{
                        printf("Offset %d: 0x%x -> 0x%x\n", i, motherfuzzer[i] & 0x000000FF, buf[i] & 0x000000FF);
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
	    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) 
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

            memcpy(buf, motherfuzzer, FUZZLEN);

	    mangle(buf, FUZZLEN);         /* puts 1-17 random bytes into buf */
	    write(s, buf, FUZZLEN);
	    if ((counter % 7) == 1)
	    	write(s,buf, rand() % FUZZLEN);   //new stuff
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

