#ifndef __IDEMIX_VERIFIER_H__
#define __IDEMIX_VERIFIER_H__

#include <pbc/pbc.h>

struct verify_s {
  element_t T_bar[8];
};
typedef struct verify_s *verify_ptr;
typedef struct verify_s verify_t[1];

#endif // __IDEMIX_VERIFIER_H__
