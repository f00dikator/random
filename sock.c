#ifdef WIN32

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <windows.h>
#include <winsock.h>

#pragma comment(lib, "wsock32.lib")

#else

#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <sys/signal.h>
#include <arpa/nameser.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>

#endif


#define DEBUG 1 

#define TIMEOUT 5 

char mybanner[8192 * 2];

char bantmp [8192 * 2];









int open_sock_tcp (char * myhost, int myport)
{
		struct sockaddr_in addr;
		int s, con;

#ifdef WIN32
                WSADATA wsa;

                if ( (WSAStartup( MAKEWORD(2,0), &wsa)) != 0)
                {
                        fprintf(stderr, "WSAStartup failed\n");
                        handle_error();
                }
#endif

		
		memset (&addr, 0, sizeof(addr));

   	        s = socket(AF_INET, SOCK_STREAM, 0);

	        if (s >= 0)
		{
			 addr.sin_family = AF_INET;
	 		 addr.sin_port = htons(myport);
	 		 addr.sin_addr.s_addr = inet_addr(myhost);
	 		 con = connect(s, (struct sockaddr *)&addr, sizeof(addr));
	                 if (con != 0)
			 {
				 return(-1); 
			 }

	  		 return(s);
	 	}
		return (-1);
}






int open_sock_udp (char * myhost, int myport)
{
	struct sockaddr_in addr;
	int s, con;

#ifdef WIN32
        WSADATA wsa;

        if ( (WSAStartup( MAKEWORD(2,0), &wsa)) != 0)
        {
	        fprintf(stderr, "WSAStartup failed\n");
                handle_error();
        }
#endif


	memset (&addr, 0, sizeof(addr));

	s = socket(AF_INET, SOCK_DGRAM, 0);

	if (s >= 0)
	{
		addr.sin_family = AF_INET;
		addr.sin_port = htons(myport);
		addr.sin_addr.s_addr = inet_addr(myhost);
		con = connect(s, (struct sockaddr *)&addr, sizeof(addr));
		if (con != 0)
		{
			return(-1);
		}

		return(s);
	}
	return(-1);
}





char * recv_sock(int mysoc, int mytimeout, int mylength)
{
	struct timeval tv;
	int mu = 0;
	int mu2, nullreads=0;
	char *myerror = "ERROR";

	if (mytimeout < 2)
	{
		mytimeout = TIMEOUT;
	}

	tv.tv_sec = mytimeout;
	tv.tv_usec = 0;
	setsockopt(mysoc,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));

	memset(&mybanner,0,sizeof(mybanner));

	while (mu < mylength)
	{
		mu2 = recv(mysoc,bantmp,sizeof(mybanner) - mu, 0);

		mu += mu2;

		if (mu2 <= 0)
		{
			if (mu == 0)
			{
				close(mysoc);
				return(myerror);
			}

			nullreads++;

			if (nullreads > 2)
			{
				if (DEBUG)
				{
					printf("3 nullreads, returning banner\n");
				}

				if (mu > 0)
				{
					return(mybanner);
				}
				else
				{
					return(myerror);
				}
			}

		}
		else
		{
			strncat(mybanner, bantmp, mu2 );
		}


		if (mu >= (sizeof(mybanner) - 5) )
		{
			return (mybanner);
		}

		if (DEBUG)
		{
			printf("Recvd %d bytes from server\n", mu2);
		}

	}

	if (mu > 0)
	{
		return(mybanner);
	}
}




/* ------------------------------------------------------ */
/* ----------------------  main()  ---------------------- */
/* ------------------------------------------------------ */



int main (int argc, char **argv)
{
	        int dsoc, philemon,muck;
	        char *banban = NULL;
		char *dhost = NULL;
		int dport;
	        char drequest[1024];
		dhost = argv[1];
		dport = 80;
		int mypid;
		int forkerr = 0;

		mypid = fork();
		if ( mypid == 0)
		{
			//child
			exit(0);
		}

		if ( mypid < 0)
		{
			fprintf(stderr, "fork error\n");
			forkerr = 1;
		}
		
		if ( mypid > 0)
		{
			//parent
		}

	        //dsoc = open_sock_tcp(dhost, dport);
	        //if (dsoc >= 0)
	        //{
	        //        sprintf(drequest, "GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic =\r\n\r\n");
	        //        write(dsoc,drequest, strlen(drequest));
		//	banban = recv_sock(dsoc, 5, 4096);
		//	printf("%s\n", banban);
	        //}
       	 	//close(dsoc);
	        return(1);
}


