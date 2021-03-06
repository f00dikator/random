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

#define TIMEOUT 4

#define TCP_NODELAY 0

char buf[8192];
char buf2[8192];

int counter, diffcounter;

const char init[] = 
{ 0x03, 0x00, 0x00, 0x0b, 0x06, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00};
//  03    00    00    0B    06    E0    00    00    00    00    00                 ...........


const char fuzzpacket[] =
{ 0x03, 0x00, 0x01, 0x1c, 0x02, 0xf0, 0x80, 0x7f, 
0x65, 0x82, 0x01, 0x10, 0x04, 0x01, 0x01, 0x04, 
0x01, 0x01, 0x01, 0x01, 0xff, 0x30, 0x19, 0x02, 
0x01, 0x22, 0x02, 0x01, 0x02, 0x02, 0x01, 0x00, 
0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 
0x01, 0x02, 0x02, 0xff, 0xff, 0x02, 0x01, 0x02, 
0x30, 0x19, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 
0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x02, 0x01, 
0x00, 0x02, 0x01, 0x01, 0x02, 0x02, 0x04, 0x20, 
0x02, 0x01, 0x02, 0x30, 0x1c, 0x02, 0x02, 0xff, 
0xff, 0x02, 0x02, 0xfc, 0x17, 0x02, 0x02, 0xff, 
0xff, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 
0x01, 0x01, 0x02, 0x02, 0xff, 0xff, 0x02, 0x01, 
0x02, 0x04, 0x82, 0x00, 0xaf, 0x00, 0x05, 0x00, 
0x14, 0x7c, 0x00, 0x01, 0x80, 0xa6, 0x00, 0x08, 
0x00, 0x10, 0x00, 0x01, 0xc0, 0x00, 0x44, 0x75, 
0x63, 0x61, 0x80, 0x98, 0x01, 0xc0, 0x8c, 0x00, 
0x04, 0x00, 0x08, 0x00, 0x00, 0x04, 0x00, 0x03, 
0x01, 0xca, 0x03, 0xaa, 0x09, 0x04, 0x00, 0x00, 
0x93, 0x08, 0x00, 0x00, 0x41, 0x00, 0x43, 0x00, 
0x45, 0x00, 0x52, 0x00, 0x59, 0x00, 0x44, 0x00, 
0x45, 0x00, 0x52, 0x00, 0x2d, 0x00, 0x47, 0x00, 
0x58, 0x00, 0x30, 0x00, 0x45, 0x00, 0x4f, 0x00, 
0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x01, 0xca, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x02, 0xc0, 0x0c, 0x00, 0x09, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00 };


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
                sleep(2);
                if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) 
		{
		    fprintf(stdout, "Unable to connect: %s\n", strerror(errno));
	            diffit();
		    handle_offsetz();
                    exit(0);
                }
	    }

            memcpy(buf, fuzzpacket, FUZZLEN);

	    write(s, init, sizeof(init) );
	    mu=recv(s,buf2,sizeof(buf2),0);
	    /*write(s, init2, sizeof(init2) - 1);
	    mu=recv(s,buf2,sizeof(buf2),0); */

	    mangle(buf, FUZZLEN);         /* puts 1-17 random bytes into buf */
	    write(s, buf, FUZZLEN);

	    /*while (mu >= 0)
	    {
		    memcpy(buf, init2, sizeof(init2) - 1);
		    mangle(buf, sizeof(init2) - 1);
		    write(s, buf, rand() % (sizeof(init2) - 1) );
		    fprintf(stderr,".");
		    memset (&buf2, 0, sizeof(buf2));
		    mu=recv(s,buf2,sizeof(buf2),0);
	    }*/

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
	    usleep(5000);				//yo, remove this if you want to silly DoS
        }
	
	exit(EXIT_SUCCESS);
}

