#ifndef __IDEMIX_SCHEMA_H__
#define __IDEMIX_SCHEMA_H__

struct attribute_s {
  mpz_t m; // 256-bit, if not used, set this to 0
  unsigned char is_hidden; // 0 = false, 1 = true
};
typedef struct attribute_s *attribute_ptr;
typedef struct attribute_s attribute_t[1];

// schema template
struct schema_s {
  unsigned long attr_c; // = l
  attribute_ptr attr_v;
};
typedef struct schema_s *schema_ptr;
typedef struct schema_s schema_t[1];

#endif
