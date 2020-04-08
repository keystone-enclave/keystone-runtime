#include "string.h"

/* TODO This is a temporary place to put libc functionality until we
 * decide on a lib to provide such functionality to the runtime */

#include <stdint.h>
#include <ctype.h>

void* memcpy(void* dest, const void* src, size_t len)
{
  const char* s = src;
  char *d = dest;

  if ((((uintptr_t)dest | (uintptr_t)src) & (sizeof(uintptr_t)-1)) == 0) {
    while ((void*)d < (dest + len - (sizeof(uintptr_t)-1))) {
      *(uintptr_t*)d = *(const uintptr_t*)s;
      d += sizeof(uintptr_t);
      s += sizeof(uintptr_t);
    }
  }

  while (d < (char*)(dest + len))
    *d++ = *s++;

  return dest;
}


void* memset(void* dest, int byte, size_t len)
{
  if ((((uintptr_t)dest | len) & (sizeof(uintptr_t)-1)) == 0) {
    uintptr_t word = byte & 0xFF;
    word |= word << 8;
    word |= word << 16;
    word |= word << 16 << 16;

    uintptr_t *d = dest;
    while (d < (uintptr_t*)(dest + len))
      *d++ = word;
  } else {
    char *d = dest;
    while (d < (char*)(dest + len))
      *d++ = byte;
  }
  return dest;
}

int memcmp(const void* s1, const void* s2, size_t n)
{
  unsigned char u1, u2;

  for ( ; n-- ; s1++, s2++) {
    u1 = * (unsigned char *) s1;
    u2 = * (unsigned char *) s2;
    if ( u1 != u2) {
      return (u1-u2);
    }
  }
  return 0;
}




int strlen(char *s)
{
  int count=0;

  while(*s!=0)
  {
    count++;
    s++;
  }
  return count;
}


int strcmp(char *s1, char *s2)
{
  int len= strlen(s1);
  if(len!=strlen(s2))
    return 1;

  for(int i=0;i<len;i++)
  {
    if(s1[i]!=s2[i])
      return 1;
  }
  return 0;
}



void strcat(char *s1, char *s2)
{
  int len= strlen(s1);
  int len2= strlen(s2);





  for(int i=0;i<len2;i++)
  {
    s1[len+i]=s2[i];
  }

}


void strcpy(char *s1, char *s2)
{
  //int len= strlen(s1);
  int len2= strlen(s2);





  for(int i=0;i<len2;i++)
  {
    s1[i]=s2[i];
  }

}
