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

/*       |                                                      |     
 * 0xFA,0x16,0x00,0x47,0x66,0x3A,0x87,0x7B,0x09,0x46,0x0E,0x80,0xD7,0x0A,0x0A,0xFE,
 *                                                                   |    
 * 0x0A,0x0A,0x0A,0x08,0x53,0x52,0x00,0x04,0x01,0x00,0x31,0x30,0x2E,0xB3,0x30,0x2E,
 *       |                                                           
 * 0x31,0x52,0x2E,0x32,0x35,0x34,0x00,0x43,0x41,0x49,0x35,0x34,0x34,0x45,0x35,0x33,
 *            |    |                        |         |              
 * 0x2D,0x30,0x8A,0xF0,0x30,0x30,0x00,0x31,0xE4,0x2E,0xC6,0x30,0x2E,0x31,0x30,0x2E,
 *                                         
 * 0x38,0x00,0x63,0x61,0x6D,0x00,0xAF);
 *
 */

const char fuzzpacket[] =
"\xFA\x0D\x00\x47\x66\x3A\x87\x7B\x09\x46\x0E\x80\x0A\x0A\x0A\xFE"
"\x0A\x0A\x0A\x08\x53\x52\x00\x04\x01\x00\x31\x30\x2E\x31\x30\x2E"
"\x31\x30\x2E\x32\x35\x34\x00\x43\x41\x49\x35\x34\x34\x45\x35\x33"
"\x2D\x30\x30\x30\x30\x30\x00\x31\x30\x2E\x31\x30\x2E\x31\x30\x2E"
"\x38\x00\x63\x61\x6D\x00\xAF"
;

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
	    fprintf(stderr, ".");
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

	    // recv that stupid ACK0x00
	    memset (&buf2, 0, sizeof(buf2));
	    mu=recv(s,buf2,sizeof(buf2),0);

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
	    if (mu > 1)
		    fprintf(stderr," %d ", mu);
            last = mu;
            totalcounter = 0;
	    close(s);
	    sleep(2);				//yo, remove this if you want to silly DoS
        }
	
	exit(EXIT_SUCCESS);
}

