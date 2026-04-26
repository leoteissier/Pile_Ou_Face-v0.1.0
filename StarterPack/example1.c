/*
 * Deliberately vulnerable example used for stack overflow demos.
 *
 * Reads more than 64 bytes into buffer to overwrite adjacent data.
 * Uses a raw syscall so Unicorn can inject input via --stdin.
 */
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void win()
{
  printf("you have correctly got the variable to the right value\n");
}


int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];

  ////(void)argc;
  //(void)argv;

  modified = 0;

  if (modified == 0x43434343) {
    win();
  } else {
    printf("Try again, you got 0x%08x\n", modified);
  }
}
