#ifndef __IDEMIX_SCHEMA_H__
#define __IDEMIX_SCHEMA_H__

struct attribute_s {
  char name[32];
  unsigned long is_hidden;
};
typedef struct attribute attribute_t[1];
typedef struct attribute *attribute_ptr;

struct schema {
  char name[32];
  unsigned long attr_c;
  attribute_ptr attr_v;
};
typedef struct schema schema_t[1];
typedef struct schema *schema_ptr;

#endif
