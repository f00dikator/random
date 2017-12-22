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

#define WVERSION 1.0.11

// 15 days until expire . add 1296000 (15 days) to the current time(NULL)
#define WTIMEOUT 1096425757

#define DEBUG 0 

#define TIMEOUT 5 

#define MAXSIGS 1024

//#define DEMOV 1

// number of elements denoted in tcp_ports array
#define TCPNUM 3 

char mybanner[8192 * 2];

char bantmp [8192 * 2];

const int tcp_ports[] = {21,23,80};


struct pwords 
{
	char hash[64];
	char description[512];
	char plaintext[512];
};

const struct pwords dcounts[MAXSIGS] = {
	{"c3VwZXI6NTc3NzM2NA==", "NetGear AccessPoint", "super|5777364"},
	{"OmFkbWlu", "3COM, Apple Airport, or Linksys Access Point", "NULL|admin"},
	{"YWRtaW46Y29tY29tY29t","3COM wireless AP","admin|comcomcom"},
	{"YWRtaW46QWRtaW4=","3COM wireless AP","admin|Admin"},
	{"OjA=","Accton Access Point","NULL|0"},
	{"cm9vdDpkZWZhdWx0","Micronet Access Point","root|default"},
	{"YWRtaW46YWRtaW4=","Dell TrueMobile or Gateway Access Point","admin|admin"},
	{"aW50ZWw6aW50ZWw=","Intel Wireless Gateway","intel|intel"},
	{"OkludGVs","Intel 2011 Wireless Access Point","NULL|Intel"},
	{"YWRtaW46","DLINK Access Point","admin|NULL"},                                  //10
	{"YWRtaW46cGFzc3dvcmQ=","NetGear Access Point","admin|password"},
	{"YWRtaW46MTIzNA==","NetGear Access Point","admin|1234"},
	{"OnBhc3N3b3Jk","Airport Access Point","NULL|password"},
	{"YWRtaW46c3lzdGVt","Cisco Access Point","admin|system"},
	{"cm9vdDo=","Buffalo Access Point","root|NULL"},                                  //15
	{"QWRtaW46NXVw","SMC Access Point","Admin|5up"},
	{"OnB1YmxpYw==","Avaya Access Point","NULL|public"},
	{"OnBhc3N3b3Jk","Enterasys RoamAbout Access Point","NULL|password"},
	{"OkNpc2Nv","Cisco Wireless Access Point","NULL|Cisco"},
	{"Q2lzY286Q2lzY28=","Cisco Wireless Access Point","Cisco|Cisco"},               //20
	{"ZGVmYXVsdDo=","IBM Wireless Gateway","default|NULL"},
	{"YWRtaW46bW90b3JvbGE=","Motorola Wireless Gateway","admin|motorola"},
	{"d2lyZWxlc3M6d2lyZWxlc3M=","Generic wireless AP","wireless|wireless"}
};

#ifdef DEMOV 

#define DTOT 1

#else

#define DTOT 23 

#endif

struct AP 
{
	char needle[512];
	char description[512];
};



const struct AP sigs[MAXSIGS] = {
{"BCM430","BCM430 Wireless Access Point"},
{"BUFFALO WBR-G54","BUFFALO WBR-G54 Wireless Access Point"},
{"CG814M","CG814M Wireless Access Point"},
{"Cisco AP340","Cisco AP340 Wireless Access Point"},
{"Cisco AP350","Cisco AP350 Wireless Access Point"},
{"Cisco BR500","Cisco BR500 Wireless Access Point"},
{"DG824M","DG824M Wireless Access Point"},
{"DG834G","DG834G Wireless Access Point"},
{"D-Link DI-1750","D-Link DI-1750 Wireless Access Point"},
{"D-Link DI-514","D-Link DI-514 Wireless Access Point"},                 // 10
{"D-Link DI-524","D-Link DI-524 Wireless Access Point"},
{"D-Link DI-614","D-Link DI-614 Wireless Access Point"},
{"D-Link DI-624","D-Link DI-624 Wireless Access Point"},
{"D-Link DI-713","D-Link DI-713 Wireless Access Point"},
{"D-Link DI-714","D-Link DI-714 Wireless Access Point"},
{"D-Link DI-754","D-Link DI-754 Wireless Access Point"},
{"D-Link DI-764","D-Link DI-764 Wireless Access Point"},
{"D-Link DI-774","D-Link DI-774 Wireless Access Point"},
{"D-Link DI-784","D-Link DI-784 Wireless Access Point"},
{"D-Link DI-824","D-Link DI-824 Wireless Access Point"},                //20
{"D-Link DSA-3100","D-Link DSA-3100 Wireless Access Point"},
{"FM114P","FM114P Wireless Access Point"},
{"FVM318","FVM318 Wireless Access Point"},
{"FWAG114","FWAG114 Wireless Access Point"},
{"HE102","HE102 Wireless Access Point"},
{"HR314","HR314 Wireless Access Point"},
{"Cisco 12000","Cisco 12000 Wireless Access Point"},
{"Linksys BEFW","Linksys BEFW Wireless Access Point"},
{"Linksys WAP","Linksys WAP Wireless Access Point"},
{"Linksys WPG","Linksys WPG Wireless Access Point"},                      //30
{"Linksys WRV","Linksys WRV Wireless Access Point"},
{"MA101","MA101 Wireless Access Point"},
{"ME102","ME102 Wireless Access Point"},
{"ME103","ME103 Wireless Access Point"},
{"MR314","MR314 Wireless Access Point"},
{"MR814","MR814 Wireless Access Point"},
{"PS111W","PS111W Wireless Access Point"},
{"R2 Wireless Access Platform","R2 Wireless Access Platform Wireless Access Point"},
{"SetExpress.shm","SetExpress.shm Wireless Access Point"},
{"SOHO Version","SOHO Version Wireless Access Point"},                     //40
{"WG101","WG101 Wireless Access Point"},
{"WG302","WG302 Wireless Access Point"},
{"WG602","WG602 Wireless Access Point"},
{"WGR614","WGR614 Wireless Access Point"},
{"WLAN","WLAN Wireless Access Point"},
{"WLAN AP","WLAN AP Wireless Access Point"},
{"220-****Welcome to WLAN AP****", "SMC EZ Connect Wireless Access Point"},
{"ce03b8ee9dc06c1", "SMC EZ Connect Wireless Access Point"},
{"AP-","Compaq Access Point"},
{"Base Station","Base Station Access Point"},                              //50
{"WaveLan","WaveLan Access Point"},
{"WavePOINT-II","Orinoco WavePOINT II Wireless AP"},
{"AP-1000","Orinoco AP-1000 Wireless AP"},
{"Cisco BR500","Cisco Aironet Wireless Bridge"},
{"Internet Gateway Device" , "D-Link Wireless Internet Gateway Device"},         //55
{"Symbol Access Point","Symbol Wireless Access Point"},
{"Linksys WAP51AB","Linksys WAP51AB Wireless Access Point"},
{"Spectrum24 Access Point","Spectrum24 Wireless Access Point"},
{"SMC2671W","SMC 2671W Wireless Access Point"},
{"SMC2870W","SMC 2870W Wireless Access Point"},                                //60
{"SMC2655W","SMC 2655W Wireless Access Point"},
{"OfficePortal 1800HW","2WireOfficePortal 1800HW Home wireless gateway"},
{"HomePortal 180HW","2Wire HomePortal 180HW"},
{"Portal 1000HG","2Wire Wireless Portal"},
{"Portal 1000HW","2Wire Wireless Portal"},                                    //65
{"Portal 1000SW","2Wire Wireless Portal"},
{"Portal 1700HG","2Wire Wireless Portal"},
{"Portal 1700HW","2Wire Wireless Portal"},
{"Portal 1700SG","2Wire Wireless Portal"},
{"HomePortal 180HG","2Wire HomePortal 180HG"},                                //70
{"HomePortal 2000","2Wire HomePortal 2000"},
{"Wireless 11a/b/g Access Point","3COM OfficeConnect Wireless Access Point"},
{"AT-WA1004G","Allied-Telesyn Wireless Access Point"},
{"AT-WA7500","Allied-Telesyn Wireless Access Point"},
{"AT-WL2411","Allied-Telesyn Wireless Access Point"},                      //75
{"RTW020","ASKEY Access Point"},
{"RTW026","ASKEY Access Point"},
{"RTA040W","ASKEY Access Point"},
{"RTA300W","ASKEY Access Point"},
{"RTW010","ASKEY Access Point"},                                            //80
{"RTW030","ASKEY Access Point"},
{"The setup wizard will help you to configure the Wireless","AT&T Wireless Router"},
{"realm=Access-Product","Avaya Access Point"},
{"USR8054","US Robotics Wireless Access Point"},
{"MR814","NetGear MR814"},                                               // 85
{"WGR614","NetGear WGR614"},
{"WGT624","NetGear WGT624"},
{"AirPlus","D-Link AirPlus Wireless Access Point"},
{"Linksys WET11","Linksys WET11 Access Point"},
{"wireless/wireless_tab1.jpg","Belkin Wireless Internet Gateway"},     //90
{"wireless/use_as_access_point_only_off","Linksys Access Point"},
{"Gateway 11G Router","Gateway 802.11G Access Point"},
{"Gateway 11B Router","Gateway 802.11B Access Point"},
{"IBM High Rate Wireless LAN","IBM High Rate Wireless LAN Gateway"},
{"MN-500","Microsoft Broadband Access Point"},                         // 95
{"MN-700","Microsoft Broadband Access Point"},
{"MN-510","Microsoft Broadband Access Point"},
{"SBG900","Motorola Wireless Cable Modem Gateway"},
{"SBG1000","Motorola Wireless Cable Modem Gateway"},
{"WA840G","Motorola Wireless Cable Modem Gateway"},                 //100
{"WR850G","Motorola Wireless Cable Modem Gateway"},
{"WL1200-AB", "NEC Access Point"},
{"WL5400AP","NEC Access Point"},
{"BR2000E V5.0E", "ARLAN BR2000E V5.0E"},
{"Server: Cochise","beeeeeeeeeeyatch"}
};

#ifdef DEMOV

#define NUMSIGZ 52 

#else

#define NUMSIGZ 105

#endif


const struct AP gensigs[256] = {
	{"Wireless","GEN"},
	{"wireless","GEN"},
	{"AP","GEN"},
	{"Access Point","GEN"},
	{"access point","GEN"},
	{"802.11","GEN"},
	{"WEP","GEN"},
	{"wep","GEN"},
	{"SSID","GEN"},
	{"Service Set ID","GEN"},
	{"ssid","GEN"},
	{"service set ID","GEN"},
	{"Beacon","GEN"},
	{"BEACON","GEN"},
	{"beacon","GEN"},
	{"RTS","GEN"},
	{"CTS","GEN"},
	{"TKIP","GEN"},
	{"DHCP","GEN"},
	{"54G","GEN"},                   //20
	{"2.4GHz","GEN"},
	{"54 Mbps","GEN"},
	{"108 Mbps","GEN"},
	{"11 Mbps","GEN"},
	{"Ad Hoc","GEN"},                //25
	{"Ad-Hoc","GEN"},
	{"Wired Equivalent Privacy","GEN"},
	{"ssid","GEN"},
	{"Infrastructure Mode","GEN"},
	{"Infrastructure mode","GEN"},      //30
	{"infrastructure mode","GEN"},
	{"802.11A","GEN"},
	{"802.11G","GEN"},
	{"PROGv00d00", "f00dikator06222004"}
};

#ifdef DEMOV

#define GENSIGZ 2 

#else

#define GENSIGZ 34 

#endif

//clean this up later
void handle_error (void)
{
	fprintf(stderr, "Socket Error\n");
	exit(0);
}



int banner_match (char * haystack, char * bhost)
{
        int tu, bret;

        for (tu=0; tu < NUMSIGZ; tu++)
        {
	        if (strstr(haystack, sigs[tu].needle))
	        {
			return(tu);
		}
	}

	bret = match_generic(haystack,bhost);

        return(-1);
}






int match_generic (char * haystack, char * ghost)
{
	int phi, totalcounter=0;

	for (phi=0; phi < GENSIGZ ; phi++)
	{
		if (strstr(haystack, gensigs[phi].needle))
		{
			totalcounter++;
		}
	}
	if (totalcounter >= 2)
	{
		printf("%s : Access Point : Matched %d out of %d generic signatures : %d\n", 
				ghost, totalcounter, GENSIGZ, ghost);		
		exit(0);
	}
}	





void check_snmp (char * myhost)
{
	char snmpreq[] = 
	"\x30\x26"
	"\x02\x01\x00\x04\x06"
	"public"
	"\xA0\x19\x02\x01\xDE\x02\x01\x00"
	"\x02\x01\x00\x30\x0E\x30\x0C\x06"
	"\x08\x2b\x06\x01\x02\x01\x01\x01"
	"\x00\x05\x00";

	struct sockaddr_in addr;
	int s, con, mu, iswireless;
	struct timeval tv;
	char *myerr = "ERROR";


#ifdef WIN32
	WSADATA wsa;

	if ( (WSAStartup( MAKEWORD(2,0), &wsa)) != 0)
	{
		fprintf(stderr, "WSAStartup failed\n");
		handle_error();
	}
#endif

	 memset(&addr, 0, sizeof(addr));
	 s = socket(AF_INET, SOCK_DGRAM,0);
	 if (s >= 0)
	 {
		 memset(&tv, 0, sizeof(tv));
		 tv.tv_sec = TIMEOUT;
		 tv.tv_usec = 0;
		 setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));

		 addr.sin_family = AF_INET;
		 addr.sin_port = htons(161);
		 addr.sin_addr.s_addr = inet_addr(myhost);
		 con = connect(s, (struct sockaddr *)&addr, sizeof(addr));
		 write(s,snmpreq, sizeof(snmpreq) - 1);
		 if (DEBUG)
		 {
			 printf("Sent snmpreq to UDP 161\n");
		 }

		 memset (&mybanner, 0, sizeof(mybanner));
		 mu=recv(s,mybanner,sizeof(mybanner),0);

		 if (mu > 0)
		 {
		     iswireless = banner_match(mybanner,myhost);
		     if (DEBUG)
		     {
			     printf("SNMP iswireless is %d\n", iswireless);
		     }

		     if (iswireless >= 0)
		     {
		             printf("Access Point : %s [SNMP]\n", sigs[iswireless].description);
		             exit(0);
		     }
		 }
		 close(s);
	 }
}





int default_accounts(char * dhost, int dport)
{
	int dsoc, philemon,muck;
	char *banban = NULL;
	char drequest[1024];

	for (philemon=0; philemon < DTOT ; philemon++)
	{
		dsoc = open_sock_tcp(dhost, dport);
		if (dsoc >= 0)
		{
			sprintf(drequest, "GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic %s\r\n\r\n",
					dcounts[philemon].hash);
			write(dsoc,drequest, strlen(drequest));
			muck = recv(dsoc, mybanner, 64, 0);        
			if (strstr(mybanner,"200 OK"))
			{
				muck = match_generic(mybanner,dhost);	
				return(philemon);
			}
		}
		close(dsoc);
	}
	return(-1);
}






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









char * get_banner (int bport, char * myhost )
{
	        struct sockaddr_in addr;
		int s, con, mu, mu2, tmplen;
		int maxreads = 0;
		struct timeval tv;
		char wrequest[64];
		char frequest[64];
		char trequest[64];
		char *myerr = "ERROR";

#ifdef WIN32
	WSADATA wsa;

	if ( (WSAStartup( MAKEWORD(2,0), &wsa)) != 0)
	{
		fprintf(stderr, "WSAStartup failed\n");
		handle_error();
	}
#endif

	 	sprintf(frequest, "USER Anonymous\r\n");	
		sprintf(wrequest, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
		sprintf(trequest, "cisco\n");

		memset(&addr, 0, sizeof(addr));
		s = socket(AF_INET, SOCK_STREAM, 0);
		if (s >= 0)
		{
			alarm(TIMEOUT);
			memset(&tv, 0, sizeof(tv));
			tv.tv_sec = TIMEOUT;
			tv.tv_usec = 0;
			setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));

			addr.sin_family = AF_INET;
			addr.sin_port = htons(bport);
			addr.sin_addr.s_addr = inet_addr(myhost);
			con = connect(s, (struct sockaddr *)&addr, sizeof(addr));

			if (con < 0)
			{
				return(myerr);
			}
			else
			{
				alarm(0);

				if (bport == 21)
				{
					write(s,frequest, strlen(frequest));
					memset (&mybanner, 0, sizeof(mybanner));
					mu=recv(s,mybanner,sizeof(mybanner),0);
					if (mu > 0)
					{
						return(mybanner);
					}	
			 	}

				if (bport == 23)
				{
					mu=recv(s,mybanner,sizeof(mybanner),0);
					if (mu > 0)
					{
						if (strstr(mybanner,"assword"))
						{
							write(s,trequest,strlen(trequest));
							mu=recv(s,bantmp,sizeof(bantmp),0);
							if (mu > 0)
							{
								return(bantmp);
							}
						}
						return(mybanner);
					}
				}

				if (bport == 80)
				{
					write(s,wrequest, strlen(wrequest) );
					memset (&mybanner, 0, sizeof(mybanner));
					mu=recv(s,mybanner,sizeof(mybanner),0);
					if (DEBUG)
					{
						printf("Recvd %d bytes from server\n", mu);
					}

					while ( (mu > 0) && (mu < sizeof(mybanner)) )
					{
						maxreads++;
						if (maxreads > 5)
						{
							if (DEBUG)
							{
								printf("Maxreads exceeded\n");
							}
							break;
						}

						tmplen = sizeof(mybanner) - (mu + 1);
						memset(&bantmp, 0, sizeof(bantmp));
						mu2 = recv(s,bantmp,tmplen ,0);
						if (mu2 < 0)
						{
							if (DEBUG)
							{
								printf("recv returned -1\n");
							}
							break;
						}

						mu = mu + mu2;

						if (DEBUG)
						{
							printf("Recvd %d bytes from server\n", mu2);
						}

						if (mu2 > 0)
						{
							strncat(mybanner, bantmp, tmplen);
						} 
					}

					if ( (! strstr(mybanner, "Server: Microsoft IIS")) &&
				             (! strstr(mybanner, "Server: Apache"))        &&
					     (! strstr(mybanner, "Server: Netscape"))      &&
					     (! strstr(mybanner, "Server: NaviServer"))    &&
					     (! strstr(mybanner, "Server: Tomcat"))        &&
					     (! strstr(mybanner, "Server: Zeus"))          &&
					     (! strstr(mybanner, "Server: Domino-Go-Webserver")) &&
					     (! strstr(mybanner, "Server: Red Hat Secure")) ) 
					{
						return(mybanner);
					}

				}
			}
		}
		return(myerr);
}











/******************************************************/
/* ****************      MAIN()      **************** */
/******************************************************/




int main(int argc, char *argv[]) 
{
	int port, i, mypid, status, forkerr;
	char *host = NULL;
	char *banner = NULL;
	int iswireless;
	int pidrray[3];
	pid_t demopid;
	time_t mytimeout;

	mytimeout = time(NULL);
	if (mytimeout > WTIMEOUT)
	{
		fprintf(stderr, "***          Wdetect Demo has expired                  ***\n");
		fprintf(stderr, "*** Contact a sales representative for a valid license ***\n");
		exit(0);
	}

	if (argc != 2)
	{
		printf("Usage: wdetect <IP Addr>\n");
		exit(0);
	}
#ifdef DEMOV

	demopid = getpid();
	if ( (demopid % 256) == 0)
	{
		fprintf(stderr, "*** TRIAL VERSION OF WDETECT ***\n");
		fprintf(stderr, "*** Using less than half of signatures ***\n");
		fprintf(stderr, "*** Contact sales person for a full version ***\n");
	}

#endif

	host = argv[1];

	for (i=0; i < strlen(host) ; i++)
	{
		if ( (host[i] == '0') ||	
		     (host[i] == '1') ||
		     (host[i] == '2') ||
		     (host[i] == '3') ||
		     (host[i] == '4') ||
		     (host[i] == '5') ||
		     (host[i] == '6') ||
		     (host[i] == '7') ||
		     (host[i] == '8') ||
		     (host[i] == '9') ||
		     (host[i] == '\n') ||
		     (host[i] == '.') )
		{
			//cool
	 	}
		else
		{
			printf("Invalid IP\n");
			exit(0);
		}
	}


	
        for (i=0; i < (TCPNUM + 1); i++)
	{	
		if (forkerr == 1)
		{
			i--;
			forkerr = 0;
			if (DEBUG)
			{
				printf("Decrementing i due to a fork error\n");
			}
		}

		mypid = fork();	
		if ( mypid == 0 )
		{
			if (DEBUG)
			{
				printf("In child with i = %d\n", i);
			}

			if (i == TCPNUM)
			{
				check_snmp(host);
			}
			else
			{
				if (DEBUG)
				{
					printf("Testing port %d\n", tcp_ports[i]);
				}

				banner = get_banner(tcp_ports[i], host);

				if (DEBUG)
				{
					printf("Return banner : %s\n", banner);
				}

				if (banner != "ERROR")
				{
					iswireless = banner_match(banner,host);
					if (DEBUG)
					{
						printf("iswireless is %d\n", iswireless);
					}

					if ((iswireless >= 0) && (sigs[iswireless].description))
					{
				            printf("%s : Access Point : %s : %d\n",host,sigs[iswireless].description,
					           tcp_ports[i]);
					    fflush(stdout);
					    exit(0);
					}
					
					/* if it's a web port and it required authentication
					 * then we will run the webserver through a default 
					 * password checker */
					if ( (tcp_ports[i] == 80) && 
					      (strstr(banner, "401 Authorization")) )
					{
						iswireless = default_accounts(host,tcp_ports[i]);	
						if ((iswireless >= 0) && (dcounts[iswireless].description))
						{
							printf("%s : Access Point : %s : %d : %s\n",
								       host, dcounts[iswireless].description,
							       	       tcp_ports[i], dcounts[iswireless].plaintext);
					 		fflush(stdout);
							exit(0);		
						}
					}

				}
			}
			exit(0);
		}

		if (mypid < 0)
		{
			if (DEBUG)
			{
				printf("fork error with %s ... sleeping\n", host);
			}
			sleep(rand() % 5);
			forkerr = 1;	
		} 

		if (mypid > 0)
		{
			pidrray[i] = mypid;
			if (DEBUG)
			{
				printf("In parent.  Child PID is %d\n", mypid);
			}	
		}
	}
	
	if (DEBUG)
	{
		printf("main program is complete.  Waiting on PIDs:\n");
		for (i=0; i < (TCPNUM + 1); i++)
		{
			printf("%d ", pidrray[i]);
		}
		printf("\ncalling waitpid()\n");
	}                                                           

	for (i=0; i<= TCPNUM; i++)
	{
		waitpid(pidrray[i],&status,0);
	}
	exit(0);
}

