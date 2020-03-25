#ifndef __IDEMIX_PAIRING_H__
#define __IDEMIX_PAIRING_H__

#include <pbc/pbc.h>

// returns  0 on success
// returns -1 on failure 
static inline int pbc_pairing_init_from_path
(pairing_t pairing,
 char *path)
{
  char s[16384];
  FILE *fp = fopen(path, "r");
  if (!fp) {
    return -1;
  }
  size_t count = fread(s, 1, 16384, fp);
  fclose(fp);
  
  if (pairing_init_set_buf(pairing, s, count)) {
    return -1;
  }
  
  return 0;
}
#endif // __IDEMIX_PAIRING_H__

static inline void pbc_element_to_mpz(mpz_t z, element_t e)
{
  int count = element_length_in_bytes(e);
  unsigned char *s = (unsigned char *)malloc(sizeof(unsigned char) * count);
  element_to_bytes(s, e);
  mpz_import(z, count, 1, 1, 1, 0, s);
  free(s);
}
