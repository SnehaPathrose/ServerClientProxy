#ifndef PBPROXY_H_
#define PBPROXY_H_

#include <openssl/aes.h>
struct ctr_state
{
unsigned char ivec[AES_BLOCK_SIZE];
unsigned int num;
unsigned char ecount[AES_BLOCK_SIZE];
};
void encryptdata(char *buf,int length,const AES_KEY *key,struct ctr_state *state,unsigned char *cipherbuf);
void decryptdata(unsigned char *cipherbuf,int length,const AES_KEY *key,struct ctr_state *state,char *buf);
void client(char *dhost, char *dport, unsigned char *key);
void server(char *port, char * dhost,char *dport, unsigned char *key);
int init_ctr(struct ctr_state *state,const unsigned char iv[16]);


#endif
