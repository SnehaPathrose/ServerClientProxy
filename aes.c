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

//encrypts data using AES in CTR mode
void encryptdata(char *buf,int length,const AES_KEY *key,struct ctr_state *state,unsigned char *cipherbuf)
{
	int offset=0,size;
	unsigned char outtemp[AES_BLOCK_SIZE],temp[AES_BLOCK_SIZE];

	while(offset<length)
	{
		//obtain maximum of 16 bytes as size
		if(length-offset<AES_BLOCK_SIZE)
			size=length-offset;
		else
			size=AES_BLOCK_SIZE;
		memset(temp,0,AES_BLOCK_SIZE);
		memcpy(temp,buf+offset,size);
		temp[size]='\0';
		
		//encrypt size bytes of temp to outtemp and finally to cipherbuf
		memset(outtemp,0,AES_BLOCK_SIZE);
		AES_ctr128_encrypt(temp,outtemp,AES_BLOCK_SIZE,key,state->ivec,state->ecount,&state->num);
		memcpy(cipherbuf+offset,outtemp,size);
		
		//increment offset by 16 bytes
		offset =offset+AES_BLOCK_SIZE;
	}

}

//initialize the counter for AES encryption in CTR mode
int init_ctr(struct ctr_state *state,const unsigned char iv[16])
{
	state->num=0;
	memset(state->ecount,0,AES_BLOCK_SIZE);
	memset(state->ivec+8,0,8);
	memcpy(state->ivec,iv,8);
}

//decrypt data using AES in CTR mode
void decryptdata(unsigned char *cipherbuf,int length,const AES_KEY *key,struct ctr_state *state,char *buf)
{
	int offset=0,size;
	unsigned char outtemp[AES_BLOCK_SIZE],temp[AES_BLOCK_SIZE];

	while(offset<length)
	{
		//obtain maximum of 16 bytes as size		
		if(length-offset<AES_BLOCK_SIZE)
			size=length-offset;
		else
			size=AES_BLOCK_SIZE;
		memset(temp,0,AES_BLOCK_SIZE);
		memcpy(temp,cipherbuf+offset,size);

		//encrypt size bytes of temp to outtemp and finally to cipherbuf
		memset(outtemp,0,AES_BLOCK_SIZE);
		AES_ctr128_encrypt(temp,outtemp,AES_BLOCK_SIZE,key,state->ivec,state->ecount,&state->num);
		memcpy(buf+offset,outtemp,size);
		
		//increment offset by 16 bytes
		offset =offset+AES_BLOCK_SIZE;
	}
	buf[length]='\0';
}

