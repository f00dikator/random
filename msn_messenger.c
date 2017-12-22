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
"\x4D\x53\x47\x20\x48\x6F\x74\x6D\x61\x69\x6C\x20\x48\x6F\x74\x6D"
"\x61\x69\x6C\x20\x35\x31\x36\x0D\x0A\x4D\x49\x4D\x45\x2D\x56\x65"
"\x72\x73\x69\x6F\x6E\x3A\x20\x31\x2E\x30\x0D\x0A\x43\x6F\x6E\x74"
"\x65\x6E\x74\x2D\x54\x79\x70\x65\x3A\x20\x74\x65\x78\x74\x2F\x78"
"\x2D\x6D\x73\x6D\x73\x67\x73\x70\x72\x6F\x66\x69\x6C\x65\x3B\x20"
"\x63\x68\x61\x72\x73\x65\x74\x3D\x55\x54\x46\x2D\x38\x0D\x0A\x4C"
"\x6F\x67\x69\x6E\x54\x69\x6D\x65\x3A\x20\x31\x31\x33\x38\x32\x35"
"\x35\x33\x37\x31\x0D\x0A\x45\x6D\x61\x69\x6C\x45\x6E\x61\x62\x6C"
"\x65\x64\x3A\x20\x30\x0D\x0A\x4D\x65\x6D\x62\x65\x72\x49\x64\x48"
"\x69\x67\x68\x3A\x20\x31\x39\x36\x36\x30\x38\x0D\x0A\x4D\x65\x6D"
"\x62\x65\x72\x49\x64\x4C\x6F\x77\x3A\x20\x2D\x32\x31\x30\x34\x38"
"\x31\x31\x39\x36\x34\x0D\x0A\x6C\x61\x6E\x67\x5F\x70\x72\x65\x66"
"\x65\x72\x65\x6E\x63\x65\x3A\x20\x31\x30\x33\x33\x0D\x0A\x70\x72"
"\x65\x66\x65\x72\x72\x65\x64\x45\x6D\x61\x69\x6C\x3A\x20\x0D\x0A"
"\x63\x6F\x75\x6E\x74\x72\x79\x3A\x20\x0D\x0A\x50\x6F\x73\x74\x61"
"\x6C\x43\x6F\x64\x65\x3A\x20\x0D\x0A\x47\x65\x6E\x64\x65\x72\x3A"
"\x20\x0D\x0A\x4B\x69\x64\x3A\x20\x30\x0D\x0A\x41\x67\x65\x3A\x20"
"\x0D\x0A\x42\x44\x61\x79\x50\x72\x65\x3A\x20\x0D\x0A\x42\x69\x72"
"\x74\x68\x64\x61\x79\x3A\x20\x0D\x0A\x57\x61\x6C\x6C\x65\x74\x3A"
"\x20\x0D\x0A\x46\x6C\x61\x67\x73\x3A\x20\x31\x37\x39\x38\x35\x0D"
"\x0A\x73\x69\x64\x3A\x20\x35\x30\x37\x0D\x0A\x6B\x76\x3A\x20\x37"
"\x0D\x0A\x4D\x53\x50\x41\x75\x74\x68\x3A\x20\x37\x33\x79\x74\x51"
"\x4D\x41\x6F\x66\x41\x50\x53\x42\x4C\x4D\x32\x42\x72\x42\x2A\x37"
"\x59\x54\x43\x6B\x52\x4E\x74\x30\x37\x4B\x6A\x59\x6E\x4D\x33\x78"
"\x36\x46\x2A\x57\x6D\x68\x4E\x4A\x68\x72\x79\x6F\x41\x45\x35\x63"
"\x6C\x4E\x38\x7A\x41\x78\x7A\x4B\x6E\x52\x7A\x33\x79\x7A\x49\x46"
"\x39\x7A\x39\x70\x42\x4E\x34\x48\x67\x5A\x7A\x78\x52\x62\x6E\x67"
"\x66\x72\x6A\x6A\x68\x72\x48\x34\x5A\x21\x53\x38\x69\x4F\x7A\x49"
"\x44\x58\x66\x6E\x4E\x42\x4B\x4B\x47\x69\x43\x74\x57\x59\x4C\x21"
"\x59\x6B\x34\x54\x47\x42\x30\x45\x58\x38\x5A\x41\x53\x0D\x0A\x43"
"\x6C\x69\x65\x6E\x74\x49\x50\x3A\x20\x36\x37\x2E\x31\x34\x30\x2E"
"\x32\x30\x30\x2E\x38\x36\x0D\x0A\x43\x6C\x69\x65\x6E\x74\x50\x6F"
"\x72\x74\x3A\x20\x36\x38\x39\x36\x0D\x0A\x41\x42\x43\x48\x4D\x69"
"\x67\x72\x61\x74\x65\x64\x3A\x20"
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

