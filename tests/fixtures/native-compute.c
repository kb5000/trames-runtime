// SPDX-License-Identifier: GPL-3.0-or-later
/* Real public ABI calls: run against original and automatically adapted libs. */
#include <stddef.h>
#include <stdint.h>
extern unsigned long crc32(unsigned long,const unsigned char*,unsigned);
extern unsigned long adler32(unsigned long,const unsigned char*,unsigned);
extern int compress2(unsigned char*,unsigned long*,const unsigned char*,unsigned long,int);
extern int uncompress(unsigned char*,unsigned long*,const unsigned char*,unsigned long);
extern size_t ZSTD_compress(void*,size_t,const void*,size_t,int);
extern size_t ZSTD_decompress(void*,size_t,const void*,size_t);
extern unsigned ZSTD_isError(size_t);
extern unsigned lzma_easy_buffer_encode(uint32_t,unsigned,const void*,const uint8_t*,size_t,uint8_t*,size_t*,size_t);
extern unsigned lzma_stream_buffer_decode(uint64_t*,uint32_t,const void*,const uint8_t*,size_t*,size_t,uint8_t*,size_t*,size_t);
extern unsigned char *SHA256(const unsigned char*,size_t,unsigned char*);
typedef struct {uint32_t words[60];int rounds;} AES_KEY;
extern int AES_set_encrypt_key(const unsigned char*,int,AES_KEY*);
extern int AES_set_decrypt_key(const unsigned char*,int,AES_KEY*);
extern void AES_encrypt(const unsigned char*,unsigned char*,const AES_KEY*);
extern void AES_decrypt(const unsigned char*,unsigned char*,const AES_KEY*);
extern void AES_cbc_encrypt(const unsigned char*,unsigned char*,size_t,const AES_KEY*,unsigned char*,int);
typedef struct {uint32_t h[8],Nl,Nh,data[16],num,md_len;} SHA256_CTX;
extern int SHA256_Init(SHA256_CTX*);
extern int SHA256_Update(SHA256_CTX*,const void*,size_t);
extern int SHA256_Final(unsigned char*,SHA256_CTX*);
extern int *__errno_location(void);
static int equal(const unsigned char*a,const unsigned char*b,size_t n){for(size_t i=0;i<n;i++)if(a[i]!=b[i])return 0;return 1;}
int main(void) {
    unsigned char source[1024],compressed[4096],result[4096],digest[32];
    const unsigned char sha[32]={0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
    for(size_t i=0;i<sizeof source;i++)source[i]=(unsigned char)i;
    *__errno_location()=73;
    for(int repeat=0;repeat<4;repeat++) {
        if(crc32(0,(const unsigned char*)"123456789",9)!=0xcbf43926UL)return 1;
        if(adler32(1,(const unsigned char*)"123456789",9)!=0x091e01deUL)return 2;
        if(*__errno_location()!=73)return 12;
        unsigned long size=sizeof compressed,out=sizeof result;
        if(compress2(compressed,&size,source,sizeof source,6)||uncompress(result,&out,compressed,size)||out!=sizeof source||!equal(source,result,out))return 3;
        size=ZSTD_compress(compressed,sizeof compressed,source,sizeof source,3);
        if(ZSTD_isError(size)||ZSTD_decompress(result,sizeof result,compressed,size)!=sizeof source||!equal(source,result,sizeof source))return 4;
        size_t op=0,ip=0;uint64_t limit=~(uint64_t)0;
        if(lzma_easy_buffer_encode(6,4,0,source,sizeof source,compressed,&op,sizeof compressed))return 5;
        size_t compressed_size=op;op=0;
        if(lzma_stream_buffer_decode(&limit,0,0,compressed,&ip,compressed_size,result,&op,sizeof result)||op!=sizeof source||ip!=compressed_size||!equal(source,result,op))return 6;
        if(SHA256((const unsigned char*)"abc",3,digest)!=digest||!equal(digest,sha,32))return 7;
        SHA256_CTX hash;
        if(!SHA256_Init(&hash)||!SHA256_Update(&hash,0,0)||!SHA256_Update(&hash,"a",1)||!SHA256_Update(&hash,"bc",2)||!SHA256_Final(digest,&hash)||!equal(digest,sha,32))return 13;
        unsigned char key[16],plain[16],cipher[16],restored[16];AES_KEY schedule;
        const unsigned char expected[16]={0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};
        for(int i=0;i<16;i++){key[i]=(unsigned char)i;plain[i]=(unsigned char)(i*17);}
        if(AES_set_encrypt_key(key,128,&schedule))return 8;
        AES_encrypt(plain,cipher,&schedule);if(!equal(cipher,expected,16))return 9;
        if(AES_set_decrypt_key(key,128,&schedule))return 10;
        AES_decrypt(cipher,restored,&schedule);if(!equal(restored,plain,16))return 11;
        unsigned char iv[16]={0},cbc[32],decoded[32];
        AES_set_encrypt_key(key,128,&schedule);AES_cbc_encrypt(source,cbc,32,&schedule,iv,1);
        for(int i=0;i<16;i++)iv[i]=0;
        AES_set_decrypt_key(key,128,&schedule);AES_cbc_encrypt(cbc,decoded,32,&schedule,iv,0);
        if(!equal(source,decoded,32))return 14;
        *__errno_location()=73;
    }
    return 0;
}
