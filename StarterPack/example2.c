#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void win(void) {
  puts("you have correctly got the variable to the right value");
}

int main(int argc, char **argv) {
  volatile int modified = 0;
  char buffer[64];

  if (argc < 2) {
    fprintf(stderr, "Usage: %s <payload>\n", argv[0]);
    return 1;
  }

  /* Vulnerable: no bounds check */
  strcpy(buffer, argv[1]);

  if (modified == 0x43434343) {
    win();
  } else {
    printf("Try again, you got 0x%08x\n", modified);
  }

  return 0;
}
