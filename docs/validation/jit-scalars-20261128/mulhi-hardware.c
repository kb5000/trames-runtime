#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>
int main(void) {
 unsigned long cases=0;
 size_t page=(size_t)sysconf(_SC_PAGESIZE);
 uint32_t *code=mmap(0,page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
 if(code==MAP_FAILED)return 2;
 uint64_t values[]={0,1,0x7fffffffffffffffULL,0x8000000000000000ULL,0xffffffffffffffffULL,0xfedcba9876543210ULL};
 for(int sign=0;sign<2;sign++) for(unsigned ra=0;ra<32;ra++) {
  if(mprotect(code,page,PROT_READ|PROT_WRITE))return 3;
  code[0]=(sign?0x9b400020:0x9bc00020)|(ra<<10);code[1]=0xd65f03c0;
  __builtin___clear_cache((char*)code,(char*)(code+2));
  if(mprotect(code,page,PROT_READ|PROT_EXEC))return 4;
  uint64_t (*f)(uint64_t,uint64_t)=(void*)code;
  for(unsigned a=0;a<6;a++)for(unsigned b=0;b<6;b++) {
   uint64_t expected=sign?(uint64_t)(((__int128)(int64_t)values[a]*(int64_t)values[b])>>64):(uint64_t)(((unsigned __int128)values[a]*values[b])>>64);
   uint64_t actual=f(values[b],values[a]);
   if(actual!=expected){printf("mismatch sign=%d Ra=%u a=%u b=%u\n",sign,ra,a,b);return 5;}
   cases++;
  }
 }
 munmap(code,page);printf("hardware mul-high: %lu signed/unsigned programs, all 32 ignored Ra values passed\n",cases);
 return 0;
}
