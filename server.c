#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <unistd.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <errno.h>
#include <netdb.h>
#include <openssl/aes.h>
#include "pbproxy.h"

//pbproxy in server mode
void server(char *port, char * dhost,char *dport, unsigned char *key)
{
	int b,a,p,w,serverclose=1,s,sock_listen,sock_client,sock_server,nfds,r,on=1,rc;
	char buf[4096];
	char plainbuf[4096];
	unsigned char cipherbuf[4096];
	FILE *fd;
	unsigned char clientiv[AES_BLOCK_SIZE],serveriv[AES_BLOCK_SIZE];
	struct hostent *hp,*gethostbyname();
	struct sockaddr_in listener,server;
	struct pollfd pfds[3];
	struct ctr_state clientstate, serverstate;
	AES_KEY aeskey;

	//create listener socket
	sock_listen=socket(AF_INET,SOCK_STREAM,0);
	if(sock_listen==-1)
	{
		fprintf(stderr,"Error opening socket");
		exit(1);
	}
	memset(&listener,0,sizeof(listener));
	listener.sin_family = AF_INET;
	listener.sin_addr.s_addr = INADDR_ANY;
	listener.sin_port=htons(atoi(port));
	
	//bind the listener socket to port
	if(bind(sock_listen,(struct sockaddr *) &listener, sizeof(listener))==-1)
	{
		perror("Error binding socket");
		exit(1);
	}
	listen(sock_listen,5);

	//set listener socket as reusable
	rc=setsockopt(sock_listen,SOL_SOCKET,SO_REUSEADDR,(char *)&on,sizeof(on));
	if(rc<0)
	{
		perror("setcockopt failed");
		close(sock_listen);
		exit(1);
	}
	
	//set hostname for server
	hp=gethostbyname(dhost);
	if(hp==(struct hostent *)0)
	{
		fprintf(stderr, "Host %s not known",dhost);
		exit(1); 
	}

	//set AES key
	if(AES_set_encrypt_key(key,128,&aeskey)<0)
	{
		fprintf(stderr,"Could not set encryption key");
		exit(1);
	}

	/*listener socket keeps listening for connections after a client connection is terminated
	*/
	while(1)
	{
		//create server socket		
		memset(&server,0,sizeof(server));
		server.sin_family = AF_INET;
		memcpy((char *) &server.sin_addr,(char *)hp->h_addr,hp->h_length);
		server.sin_port=htons(atoi(dport));
		sock_server = socket(AF_INET,SOCK_STREAM,0);

		//connect to server socket
		if(connect(sock_server,(struct sockaddr *) &server, sizeof(server))==-1)
		{
			fprintf(stderr,"Error connecting to socket");
			exit(1);
		}
		
		//accept a client connection
		sock_client= accept(sock_listen,NULL,NULL);

		//get client iv and set counter
		memset(&clientiv,0,sizeof(clientiv));
		r=0;
		while(r!=AES_BLOCK_SIZE)
		{
			a=read(sock_client,clientiv+r,AES_BLOCK_SIZE);
			if(a==-1)
			{
				fprintf(stderr,"Error reading IV from client socket");
				exit(1);
			}
			r=r+a;
		}
		memset(&clientstate,0,sizeof(clientstate));
		init_ctr(&clientstate,clientiv);

		//generate random server iv and set counter
		fd=fopen("/dev/urandom","rb");
		if(fd==NULL)
		{
			perror("Cannot read file /dev/urandom");
			exit(1);
		}
		memset(&serveriv,0,sizeof(serveriv));
		fread(&serveriv,1,AES_BLOCK_SIZE,fd);
		memset(&serverstate,0,sizeof(serverstate));
		init_ctr(&serverstate,serveriv);

		//send the server iv
		w=0;
		while(w!=AES_BLOCK_SIZE)
		{
			a=write(sock_client,serveriv+w,AES_BLOCK_SIZE);
			if(a==-1)
			{
				fprintf(stderr,"Error writing IV to client socket");
				exit(1);
			}
			w=w+a;
		}

		//set the pollfd structure
		pfds[0].fd=sock_client;
		pfds[0].events=POLLIN;
		pfds[0].revents=0;
		pfds[1].fd=sock_server;
		pfds[1].events=POLLIN;
		pfds[1].revents=0;

		while(1)
		{
			p=poll(pfds,2,-1);
			if(p<0)
			{
				fprintf(stderr,"Poll failed");
				exit(1);
			}
			if(p>0)
			{
				//client socket has data ready to be received
				if(pfds[0].revents & POLLIN)
				{
					memset(&buf,0,sizeof(buf));
					b=recv(sock_client,buf,sizeof(buf)-1,MSG_PEEK);
					if(b>0)
					{
						r=0;
						memset(&buf,0,sizeof(buf));
						while(r!=b)
						{
							a=recv(sock_client,buf+r,b,0);
							r=r+a;
						} 

						memset(&plainbuf,0,sizeof(plainbuf));
						decryptdata(buf,r,&aeskey,&clientstate,plainbuf);
						w=0;
						while(w!=r)
						{
							a=write(sock_server,plainbuf+w,r);
							if(a==-1)
							{
								fprintf(stderr,"Error writing to server socket");
								exit(1);
							}
							w=w+a;

						}
						usleep(20000);

					}
					if(b<=0)
					{
						shutdown(sock_client,SHUT_RDWR);
						close(sock_client);
						shutdown(sock_server,SHUT_RDWR);
						close(sock_server);
						break;
					}
				}
				
				//server socket has data ready to be received
				if(pfds[1].revents & POLLIN)
				{
					memset(&buf,0,sizeof(buf));
					b = recv(sock_server,buf,sizeof(buf)-1,MSG_PEEK);
					if(b>0)
					{
						r=0;
						memset(&buf,0,sizeof(buf));
						while(r!=b)
						{
							a=recv(sock_server,buf+r,b,0);
							r=r+a;
						} 	
						memset(&cipherbuf,0,sizeof(cipherbuf));		
						encryptdata(buf,r,&aeskey,&serverstate,cipherbuf);
						w=0;
						while(w!=r)
						{
							a=write(sock_client,cipherbuf+w,r);
							if(a==-1)
							{
								fprintf(stderr,"Error writing to socket client\n");
								exit(1);
							}
							w=w+a;	
						}
						usleep(20000);

					}
				}
			}
		}
	}
}
