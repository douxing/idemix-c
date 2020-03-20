#include "idemix_schema.h"
#include <assert.h>

void schema_init(schema_t s, const unsigned long l)
{
  assert(l > 3);
  s->l = l;
  mpz_init(s->map);
}

void schema_clear(schema_t s)
{
  mpz_clear(s->map);
}

int schema_attr_is_hidden(schema_t s, unsigned long i)
{
  assert(i < s->l);
  return bitmap_tstbit(s->map, i);
}

void schema_attr_set_hidden(schema_t s, unsigned long i)
{
  assert(i < s->l);
  bitmap_setbit(s->map, i);
}

unsigned long schema_attr_cnt_hidden(schema_t s)
{
  return bitmap_cnt1(s->map, s->l);
}


void schema_attr_set_known(schema_t s, unsigned long i)
{
  bitmap_clrbit(s->map, i);
}

void schema_attr_set_revealed(schema_t s, unsigned long i)
{
  bitmap_clrbit(s->map, i);
}

unsigned long schema_attr_cnt_known(schema_t s)
{
  return bitmap_cnt0(s->map, s->l);
}

unsigned long schema_attr_cnt_revealed(schema_t s)
{
  return bitmap_cnt0(s->map, s->l);
}
