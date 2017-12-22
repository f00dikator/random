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




int main(int argc, char *argv[]) {
	struct sockaddr_in addr;
	int s, port = 0, first = 1, len, counter, totalcounter, mu, last, seeder, byte_size, i, fu=0;
	char *host = NULL;
	struct timeval tv;
	char crap[] = "1\",.<$&";
	char crap2[] = "nsdpq";


	printf("Generic Protocol fuzzer\n\n");

        if (argc < 4) {
                fprintf(stderr, "Use: %s [ip] [port] [byte size] \n", argv[0]);
                exit(1);
        }
	
	host = argv[1];
	port = atoi(argv[2]);
	if (argv[3] == "var") {
		byte_size = rand() % 8192;
        } else {
	    byte_size = atoi(argv[3]);
	}
	
	if (byte_size >= 8192) {
	         fprintf(stderr, "sorry...only up to 8192 bytes are supported\n");
	         exit(0);
	}

	if ((port < 1) || (port > 65535)) {
		fprintf(stderr, "Port out of range (%d)\n", port);
		exit(0);
	}

        memset(&tv, 0, sizeof(tv));
        tv.tv_sec = TIMEOUT;
        tv.tv_usec = 0;

	memset(&addr, 0, sizeof(addr));


	signal(SIGPIPE, SIG_IGN); 
        counter = 0;
        fprintf(stdout, "Fuzzing...\n");
        while(1) {
            counter++;
	    if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(stdout, "Socket error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	    }
            setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
	    addr.sin_family = AF_INET;
	    addr.sin_port = htons(port);
	    addr.sin_addr.s_addr = inet_addr(host);
	    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stdout, "Unable to connect: %s\n", strerror(errno));
		if (!first) {
		    sleep(1);
		    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
			fprintf(stdout, "2 consecutive connect failures\nvalue of last packet was:\n");
			for (i=0; i<byte_size; i++) {
				fprintf(stdout, "\\x%x", buf[i] & 0x000000FF);
				if ( (i%16) == 15) fprintf(stdout,"\n");
			}
			fprintf(stdout, "\n");
			exit(0);
		    }
                }
	    }
	   
	    // setup our bogus packet 
            if (byte_size > 2048) { 
	        for (i=0; i < (byte_size - 40)  ; i++) {
		    buf[i] = rand() % 256;
	        }
	    
	        for (i=(byte_size - 40) ; i<byte_size; i++ , fu++) {
		    if ( (i % 3) == 0)
		        buf[i] = crap[i % 7];
		    if ( (i % 3) == 1)
			buf[i] = 0x37;
		    if ( (i % 3) == 2)
			buf[i] = crap2[fu % 5];
                }
	    } else {
		for (i=0; i<byte_size; i++) {
			buf[i] = rand() % 256;
	        }
	    }

	    buf[i] = '\0';	    

	    first = 0;
	    //if ( (counter % 100) == 0) {fprintf(stdout,"counter=%d\n",counter); fflush(stdout); }
	    mu = 0;
	    
            while (mu >= 0)
	    {
	    	write(s, buf, byte_size);
		printf(".");
            	mu=recv(s,buf,sizeof(buf),0);
	    }
	    printf("\n");
	    //if (mu > 0) fprintf(stderr, "Recvd %d bytes from host\n", mu);
            if ( (mu != last) && (counter > 1) ) {
		    fprintf(stdout, "return buffer from scanned host just changed Counter=%d\n", counter);
		    fprintf(stdout, "expected %d return bytes...received %d bytes\n", last, mu);
		    fprintf(stdout, "value of last packet was:\n");
		    for (i=0; i < byte_size; i++) {
			    fprintf(stdout, "\\x%x", buf[i] & 0x000000FF);
			    if ( (i%16) == 15) fprintf(stdout,"\n");
		    }
		    fprintf(stdout, "\n\n****************\n\n");
		    fflush(stdout);
            }
            last = mu;
	    close(s);
	    byte_size = rand() % 8192;
        }
	
	exit(EXIT_SUCCESS);
}

