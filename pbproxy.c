#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "pbproxy.h"

//prints the usage of pbproxy
void print_usage()
{
printf("\nUsage: ./pbproxy [-l <portnumber>] -k <filename> <destinationhost destinationport>\n");
}

int main(int argc , char **argv)
{
	int i,f,index[10],found,servermode=0,clientmode=0,j=0;
	char *keyfile, *dhost, *dport, *port;
	unsigned char key[16];
	
	//process the arguments
	for(i=1;i<argc;i++)
	{
		found=0;	
		if(strcmp(argv[i],"-l")==0)
		{		
			servermode=1;
			port=argv[i+1];
			found = 1;
			i++;
		}
		if(strcmp(argv[i],"-k")==0)
		{
			keyfile=argv[i+1];
			found = 1;
			i++;
		}
		if(found==0)
			index[j++]=i;
	}

	if(j!=2)
	{
		fprintf(stderr,"Invalid number of arguments1");
		print_usage();
		exit(1);
	}
	else if(j==2)
	{
		dhost=argv[index[0]];
		dport=argv[index[1]];
	}
	if (servermode==0)
	{
		clientmode=1;
	}
	if (servermode ==1)
	{
		if(port==NULL)
		{
			fprintf(stderr,"Invalid number of arguments2");
			print_usage();
			exit(1);	
		}
	}
	if ((keyfile==NULL) || (dhost==NULL) || (dport==NULL))
	{
		fprintf(stderr,"Invalid number of arguments3");
		print_usage();
		exit(1);
	}
	
	//read key from file if permissions allow
	if((access(keyfile,R_OK))<0)
	{
		fprintf(stderr,"Keyfile does not have read permissions\n");
		exit(1);
	}
	FILE *fd = fopen(keyfile,"r");
	if(fd==NULL)
	{
		fprintf(stderr,"Error in opening keyfile");
		exit(1);
	}
	f=fread(&key,1,16,fd);
	if(f<0)
	{
		fprintf(stderr,"Error in reading keyfile");
		exit(1);
	}
	
	//call the pbproxy function according to mode
	if(clientmode==1)
		client(dhost, dport, key);	
	else if(servermode==1)
		server(port,dhost,dport, key);
}

