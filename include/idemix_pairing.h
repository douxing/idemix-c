#ifndef __IDEMIX_PAIRING_H__
#define __IDEMIX_PAIRING_H__

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
