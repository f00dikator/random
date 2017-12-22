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

const char init[] =
"\x80\x67\x01\x03\x01\x00\x4E\x00\x00\x00\x10\x01\x00\x80\x03\x00"
"\x80\x07\x00\xC0\x06\x00\x40\x02\x00\x80\x04\x00\x80\x00\x00\x39"
"\x00\x00\x38\x00\x00\x35\x00\x00\x33\x00\x00\x32\x00\x00\x04\x00"
"\x00\x05\x00\x00\x2F\x00\x00\x16\x00\x00\x13\x00\xFE\xFF\x00\x00"
"\x0A\x00\x00\x15\x00\x00\x12\x00\xFE\xFE\x00\x00\x09\x00\x00\x64"
"\x00\x00\x62\x00\x00\x03\x00\x00\x06\x06\x4D\x2F\xB2\x5C\x7A\x3E"
"\x43\xDE\x66\xA5\x35\x71\x91\x27\x90";

const char motherfuzzer[] =
"\x16\x03\x01\x00\x86\x10\x00\x00\x82\x00\x80\x59\x80\xD4\x78\xA3"
"\xAD\x4F\xC7\x2E\x40\xB5\x7F\x2B\x67\x66\xBC\x95\x07\x71\x3F\xEC"
"\xCB\x5C\xDE\x68\xF0\xB4\x31\xBC\x8C\xE3\x32\xFA\xF4\x9C\x01\x40"
"\x2A\x19\x22\xF9\x2D\x66\xE7\xDF\x27\x93\x17\xC7\x7F\xF4\x44\x26"
"\xEB\xDD\x56\x7D\xDD\xDE\x8F\xD5\xE8\x4F\x96\xD2\xBB\x58\xBC\x95"
"\x9F\xD2\xBE\x06\x77\x39\xF2\x91\xFA\xAA\x21\x25\x71\xAA\x29\x02"
"\x95\xBA\x07\xF5\xB1\xF8\xFD\xF1\x4C\x31\x3E\x2C\xFB\x25\xB6\x25"
"\x11\xD4\xCB\x06\xF3\x9D\x10\x78\xF5\x40\x1A\xD7\x91\x68\xF9\x3C"
"\x01\x6B\x6C\xE7\x61\xC2\x06\x99\x9C\xE4\xE0\x14\x03\x01\x00\x01"
"\x01\x16\x03\x01\x00\x30\xC8\x5D\x15\xE7\xDA\x5B\x43\x1D\xAB\x8C"
"\xA2\x40\x88\x02\x53\x17\x7B\xB8\xB9\xA9\x10\x66\x73\xFD\x37\xA9"
"\x76\x31\x19\x4C\x8E\x8E\x06\xFF\x50\x79\xBE\x4D\xDE\xDE\x45\xE1"
"\xC3\x60\x5F\x33\x6D\x4D"
;

#define FUZZLEN (sizeof(motherfuzzer))

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
	int s, port = 0, len, totalcounter, mu, last, seeder, x, giantrunt, done;
	char *host = NULL;
	unsigned int seed;
	struct timeval tv;
  	signal(SIGTERM, handle_offset);
  	signal(SIGINT, handle_offset);
  	signal(SIGQUIT, handle_offset);
  	signal(SIGHUP, handle_offset);
  	signal(SIGALRM, handle_offset);



	printf("Generic Protocol fuzzer [jwl in the hizzzzzouse]\n\n");

        if (argc < 3) 
	{
                fprintf(stderr, "Use: %s [ip] [port (443/SSL)]\n", argv[0]);
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
	    giantrunt = done = 0;
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

	    // init crap
	    memcpy(buf, init, sizeof(init));
	    mangle(buf, sizeof(init));
	    write (s, buf, sizeof(init));
	    memset (&buf2, 0, sizeof(buf2));
	    mu=recv(s,buf2,sizeof(buf2),0);
	    if (mu < 1000)
	    {
		    done = 1;
		    fprintf(stdout, "Sorry....only able to fuzz first packet this sequence\n");
	    }
	    else
	    {
		    fprintf(stdout, "FUZZING 2nd packet\n");
	    }
	    // end init
	   
	    if (done == 0)
	    { 
            	memcpy(buf, motherfuzzer, FUZZLEN);

	    	mangle(buf, FUZZLEN);         /* puts 1-17 random bytes into buf */
            	if ((counter % 9) == 8)
	    	{
                    write(s,buf, rand() % FUZZLEN);		// every 9th packet, send a RUNT
		    giantrunt = 1;
	    	}
            	else
	    	{
                	write(s, buf, FUZZLEN);
	    	}
	    	if ((counter % 7) == 1)
 	    	{
	    		write(s,buf, rand() % FUZZLEN);   		// every 7th packet, send a GIANT
			giantrunt = 1;
	    	}
            	memset (&buf2, 0, sizeof(buf2));
            	mu=recv(s,buf2,sizeof(buf2),0);

	    	if (giantrunt == 0)
	    	{
            		if ( (mu != last) && (counter > 1) ) 
	    		{
                    		fprintf(stdout, "return buffer from scanned host just changed Counter=%d\n", counter);
                    	fprintf(stdout, "expected %d return bytes...received %d bytes\n", last, mu);
                    	diffit();
            		}
            		last = mu;
	    	}
	    }

            totalcounter = 0;
	    close(s);
	    if ((counter % 10) == 9)
	    	sleep(1);				//yo, remove this if you want to silly DoS
        }
	
	exit(EXIT_SUCCESS);
}

