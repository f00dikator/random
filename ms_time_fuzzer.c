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

#define TIMEOUT 3

const char req1[] =
"\x00\x00\x00\x64\xFF\x53\x4D\x42\xA2\x00\x00\x00\x00\x18\x07\xC8"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\xEC\x31"
"\x00\x08\x02\x9B\x18\xFF\x00\xDE\xDE\x00\x0E\x00\x16\x00\x00\x00"
"\x00\x00\x00\x00\x9F\x01\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x03\x00\x00\x00\x01\x00\x00\x00\x40\x00\x40\x00"
"\x02\x00\x00\x00\x01\x11\x00\x00\x5C\x00\x73\x00\x72\x00\x76\x00"
"\x73\x00\x76\x00\x63\x00\x00\x00";


const char dacrap[] =
"\x00\x00\x00\x88\xFF\x53\x4D\x42\x2F\x00\x00\x00\x00\x18\x07\xC8"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\xFF\xFE"
"\x00\x08\x12\x9B\x0E\xFF\x00\xDE\xDE\x0A\x40\x00\x00\x00\x00\xFF"
"\xFF\xFF\xFF\x08\x00\x48\x00\x00\x00\x48\x00\x40\x00\x00\x00\x00"
"\x00\x49\x00\xEE\x05\x00\x0B\x03\x10\x00\x00\x00\x48\x00\x00\x00"
"\x01\x00\x00\x00\xB8\x10\xB8\x10\x00\x00\x00\x00\x01\x00\x00\x00"
"\x00\x00\x01\x00\xC8\x4F\x32\x4B\x70\x16\xD3\x01\x12\x78\x5A\x47"
"\xBF\x6E\xE1\x88\x03\x00\x00\x00\x04\x5D\x88\x8A\xEB\x1C\xC9\x11"
"\x9F\xE8\x08\x00\x2B\x10\x48\x60\x02\x00\x00\x00";


const char req3[] =
"\x00\x00\x00\x3B\xFF\x53\x4D\x42\x2E\x00\x00\x00\x00\x18\x07\xC8"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\xFF\xFE"
"\x00\x08\x22\x9B\x0C\xFF\x00\xDE\xDE\x0A\x40\x00\x00\x00\x00\x00"
"\x04\x00\x04\xFF\xFF\xFF\xFF\x00\x04\x00\x00\x00\x00\x00\x00";


/*const char dacrap[] = 
"\x00\x00\x00\x98\xFF\x53\x4D\x42\x25\x00\x00\x00\x00\x18\x07\xC8"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\xEC\x31"
"\x00\x08\x32\x9B\x10\x00\x00\x44\x00\x00\x00\x00\x04\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x54\x00\x44\x00\x54\x00\x02"
"\x00\x26\x00\x0A\x40\x55\x00\x01\x5C\x00\x50\x00\x49\x00\x50\x00"
"\x45\x00\x5C\x00\x00\x00\x6B\x00\x05\x00\x00\x03\x10\x00\x00\x00"
"\x44\x00\x00\x00\x01\x00\x00\x00\x2C\x00\x00\x00\x00\x00\x1C\x00"
"\x18\x43\x08\x00\x0E\x00\x00\x00\x00\x00\x00\x00\x0E\x00\x00\x00"
"\x5C\x00\x5C\x00\x31\x00\x30\x00\x2E\x00\x31\x00\x30\x00\x2E\x00"
"\x31\x00\x30\x00\x2E\x00\x34\x00\x35\x00\x00\x00";
*/

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
                        printf("Offset %d: 0x%x -> 0x%x\n", i, dacrap[i], buf[i]);
        }
        printf("*****\n");
}






int main(int argc, char *argv[]) {
	struct sockaddr_in addr;
	int r, s, port = 0, first = 1, len, counter, totalcounter, mu, last, seeder;
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
	srand(seed);

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
            setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
	    addr.sin_family = AF_INET;
	    addr.sin_port = htons(port);
	    addr.sin_addr.s_addr = inet_addr(host);
	    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "Unable to connect: %s\n", strerror(errno));
		if (!first) {
			diffit();
                        totalcounter++;
                }
		if (totalcounter > 3) exit(EXIT_FAILURE);
	    }
	    first = 0;
	    if ( (counter % 100) == 0) {fprintf(stdout,"counter=%d\n", counter); fflush(stdout); }


	    write (s, req1, sizeof(req1) - 1);
	    r = recv(s, buf, sizeof(buf),0);
	    /*write (s, req2, sizeof(req2) - 1);
	    r = recv(s, buf, sizeof(buf),0);
	    write (s, req3, sizeof(req3) - 1);
	    r = recv(s, buf, sizeof(buf),0);*/
            memset(&buf, 0, sizeof(buf));

	    len = send_crap();
	    corruptor(buf, len);         /* puts 1-17 random bytes into buf */
	    write(s, buf, len);
            mu=recv(s,buf,sizeof(buf),0);
            if ( (mu != last) && (counter > 1) ) {
                    fprintf(stderr, "return buffer from scanned host just changed Counter=%d\n", counter);
                    fprintf(stderr, "expected %d return bytes...received %d bytes\n", last, mu);
                    diffit();
            }
            last = mu;
	    close(s);
        }
	
	exit(EXIT_SUCCESS);
}

