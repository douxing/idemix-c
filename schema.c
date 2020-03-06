#include <stdlib.h>
#include "idemix_schema.h"

void schema_init(schema_t schema, const unsigned long l)
{
  schema->l = l;
  schema->vec = (attribute_ptr)malloc(sizeof(attribute_t) * l);

  for (unsigned long i = 0; i < l; ++i) {
    attribute_ptr a = schema->vec + i;
    mpz_init(a->m);
    a->is_hidden = 0; // default to known
    a->eq_class = 0;  // default to revealed
  }
}

// used in Chapter 5
unsigned long schema_attr_is_hidden(schema_t s, const unsigned long i)
{
  return (s->vec + i)->is_hidden;
}

// used in Chapter 7
unsigned long schema_attr_is_revealed(schema_t s, const unsigned long i)
{
  return !(s->vec + i)->eq_class;
}

unsigned long schema_attr_eq_class(schema_t s, const unsigned long i)
{
  return (s->vec + i)->eq_class;
}
