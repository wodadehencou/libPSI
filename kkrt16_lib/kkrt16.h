
#ifndef _KKRT16_LIB_
#define _KKRT16_LIB_

#include <bits/stdint-uintn.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef struct Block {
  uint64_t high;
  uint64_t low;
} Block;

void run_sender(Block seeds, Block *sendSet, uint64_t sendSize,
                uint64_t recvSize, const char *server, int port,
                int malicious, int statSec);

void run_receiver(uint64_t *intersection,
                  uint64_t *intersectionSize, Block seeds,
                  Block *recvSet, uint64_t sendSize,
                  uint64_t recvSize, const char *server, int port,
                  int malicious, int statSec);
#ifdef __cplusplus
}
#endif

#endif