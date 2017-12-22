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

const char dacrap[8192] = "\x00\xA8\x00\x01\x1A";

int counter;

#define CRAPLEN (sizeof(dacrap)-1)



int send_crap() {
	int qq;
	for (qq=0; qq<counter; qq++) {
		buf[qq] = rand() % 256;
	}
	return (sizeof(buf) - 1);
}



void corruptor(char *buf, int len) {
int cb, i, l;

	cb = (rand() % 2) + 1; /* bytes to corrupt */

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
	int var1, var2, var3, s, port = 0, first = 1, len, totalcounter, mu, last, seeder;
	int mu2, mu3, mu4, mu5, zz;
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


        fprintf(stderr, "Fuzzing...\n");
        while(counter < 8193) {
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
	    //len = send_crap();
	    len = 1500;
	    for (zz=0; zz<1500; zz++) {buf[zz] = rand() % 256;}
	    var1 = write(s,buf,len);
	    mu2 = recv(s,buf,sizeof(buf),0);
	    var2 = write(s,buf,len);
	    mu3 = recv(s,buf,sizeof(buf),0);
	    var3 = write(s,buf,len);
	    mu4 = recv(s,buf,sizeof(buf),0);
	    usleep (1000);
	    var1 = write(s,buf,len);
	    mu5 = recv(s,buf,sizeof(buf),0);
	    if ( (mu5 != mu4) || (mu5 != mu3) || (mu5 != mu2) ) {
		    fprintf(stderr, "mu5 = %d / mu4 = %d / mu3 = %d / mu2 = %d\n", mu5, mu4, mu3, mu2);
            }
	    //corruptor(buf, len);         /* puts 1-17 random bytes into buf */
	    
	    write(s, buf, len);
            mu=recv(s,buf,sizeof(buf),0);
            if ( (mu != last) && (counter > 1) ) {
                    fprintf(stderr, "return buffer from scanned host just changed Counter=%d\n", counter);
                    fprintf(stderr, "expected %d return bytes...received %d bytes\n", last, mu);
                    diffit();
		    exit(0);
            }
            last = mu;
            totalcounter = 0;
	    close(s);
        }
	
	exit(EXIT_SUCCESS);
}

