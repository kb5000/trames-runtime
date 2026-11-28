#include <sys/auxv.h>
#include <unistd.h>
#include <stdio.h>
int main(void) { printf("{\"hwcap\":\"0x%lx\",\"hwcap2\":\"0x%lx\",\"page_size\":%ld}\n", getauxval(AT_HWCAP),getauxval(AT_HWCAP2),sysconf(_SC_PAGESIZE)); }
