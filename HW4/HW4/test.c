#include <stdio.h>
#include <unistd.h>
#define claimedMem syscall(354)
#define freeMem syscall(353)

int main() {
  float frag;
  printf("Run 6 Tests:\n");
  int i = 0;
  for (i = 0; i < 6; i++) {
    fragmentation = (float)freeMem / (float)claimedMem;
    printf("Claimed Memory: %lu\n", claimedMem);
    printf("Free Memory: %lu\n", freeMem);
    printf("Memory Fragmentation: %f\n", frag);
    printf("---------\n");
    sleep(1);
  }
}
