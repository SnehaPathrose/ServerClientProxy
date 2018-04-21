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

//pbproxy in client mode
void client(char *dhost, char *dport, unsigned char *key)
{
	int b,sock,ret,r,w,a;
	char buf[4096];
	unsigned char cipherbuf[4096];
	char plainbuf[4096];
	unsigned char clientiv[AES_BLOCK_SIZE];
	unsigned char serveriv[AES_BLOCK_SIZE];
	FILE *fd;
	struct sockaddr_in server;
	struct hostent *hp,*gethostbyname();
	struct pollfd pfds[2];
	AES_KEY aeskey;
	struct ctr_state clientstate, serverstate;

	//create socket for destination
	sock = socket(AF_INET,SOCK_STREAM,0);
	if(sock==-1)
	{
		fprintf(stderr,"Error opening socket");
		exit(1);
	}
	
	//set destination host and port	
	memset(&server,0,sizeof(server));
	server.sin_family=AF_INET;
	hp=gethostbyname(dhost);
	if(hp==(struct hostent *)0)
	{
		fprintf(stderr, "Host %s not known",dhost);
		exit(1); 
	}
	memcpy((char *) &server.sin_addr,(char *)hp->h_addr,hp->h_length);
	server.sin_port=htons(atoi(dport));

	//connect to destination socket
	if(connect(sock,(struct sockaddr *) &server, sizeof(server))==-1)
	{
		fprintf(stderr,"Error connecting to socket");
		exit(1);
	}

	//generate the IV for destination and set the counter
	fd=fopen("/dev/urandom","rb");
	if(fd==NULL)
	{
		fprintf(stderr,"Cannot read file /dev/urandom");
		exit(1);
	}
	memset(&clientiv,0,sizeof(clientiv));
	fread(&clientiv,1,AES_BLOCK_SIZE,fd);
	memset(&clientstate,0,sizeof(clientstate));
	init_ctr(&clientstate,clientiv);

	//send IV as first message
	w=0;
	while(w!=AES_BLOCK_SIZE)
	{
		a=write(sock,clientiv+w,AES_BLOCK_SIZE);
		if(a==-1)
		{
			fprintf(stderr,"Error writing IV to socket");
			exit(1);
		}
		w=w+a;
	}

	//set the AES key
	if(AES_set_encrypt_key(key,128,&aeskey)<0)
	{
		fprintf(stderr,"Could not set encryption key");
		exit(1);
	}

	
	//receive the IV from destination and set counter
	memset(&serveriv,0,sizeof(serveriv));
	r=0;
	while(r!=AES_BLOCK_SIZE)
	{
		a=read(sock,serveriv+r,AES_BLOCK_SIZE);
		if(a==-1)
		{
			fprintf(stderr,"Error reading IV from socket");
			exit(1);
		}
		r=r+a;
	}
	memset(&serverstate,0,sizeof(serverstate));
	init_ctr(&serverstate,serveriv);

	//set the pollfd structure for polling
	pfds[0].fd=0;
	pfds[0].events=POLLIN;
	pfds[1].fd=sock;
	pfds[1].events=POLLIN;

	//do polling and read/write data
	while(1)
	{	
		ret = poll(pfds,2,-1);
		if(ret<0)
		{
			fprintf(stderr,"error in polling");
			exit(1);
		}
		if(ret>0)
		{
			//stdin has data that can be received
			if(pfds[0].revents & POLLIN)
			{	
				memset(&buf,0,sizeof(buf));
				if((r = read(0,buf,sizeof(buf)-1))>0)
				{
					memset(&cipherbuf,0,sizeof(cipherbuf));		
					encryptdata(buf,r,&aeskey,&clientstate,cipherbuf);
					w=0;
					while(w!=r)
					{
						a=write(sock,cipherbuf+w,r);
						if(a==-1)
						{
							fprintf(stderr,"Error writing to socket");
							exit(1);
						}
						w=w+a;
					}
					usleep(20000);
				}
			}
			
			//destination socket has data that can be received
			if(pfds[1].revents & POLLIN)
			{
				memset(&buf,0,sizeof(buf));
				b=recv(sock,buf,sizeof(buf)-1,MSG_PEEK);	
				if(b>0)
				{
					r=0;
					memset(&buf,0,sizeof(buf));
					while(r!=b)
					{
						a=recv(sock,buf+r,b,0);
						r=r+a;
					} 					
					memset(&plainbuf,0,sizeof(plainbuf));
					decryptdata(buf,r,&aeskey,&serverstate,plainbuf);
					w=0;
					while(w!=r)
					{
						a=write(1,plainbuf+w,r);
						w= w+a;
					}
						
				}
				usleep(20000);
				if(b<=0)
				{
					shutdown(sock,SHUT_RDWR);
					close(sock);
					break;
				}
			}
		}
	}
}
