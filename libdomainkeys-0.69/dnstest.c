#include <stdio.h>
#include <stdlib.h>
char *dns_text(char *);

int main(int argc, char *argv[]) {
  char *txtrec, *cp;

  if (argc < 2) exit(1);
  txtrec = dns_text(argv[1]);
  cp = txtrec;
  printf("%d\n", strlen(cp));
  while (*cp) {
    printf("%02x ", *cp++);
    if ((cp-txtrec) % 16 == 0)  printf("\n");
  }
  printf("\n");
  if (!strcmp(txtrec,"e=perm;"))
    exit(0);
  
  if (!strcmp(txtrec,"e=temp;"))
    exit(0);

  free(txtrec);
}
