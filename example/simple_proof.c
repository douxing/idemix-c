#include "idemix.h"

void usage(char *name) {
  gmp_printf("usage:\n  %s param_file\n", name);
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    usage(argv[0]);
    return -1;
  }

  pairing_t pairing;
  if (pbc_pairing_init_from_path(pairing, argv[1])) {
    gmp_printf("pairing load error.\n");
    return -1;
  }

  gmp_printf("length in bytes: (GT, G1, G2, Zr): (%d, %d, %d, %d).\n",
	     pairing_length_in_bytes_GT(pairing),
	     pairing_length_in_bytes_G1(pairing),
	     pairing_length_in_bytes_G2(pairing),
    	     pairing_length_in_bytes_Zr(pairing));

  gmp_printf("4.1: defines the primary credential schema S\n");
  schema_t schema;
  schema_init(schema, 5); // 3 internal + 2 user defined
  schema_attr_set_hidden(schema, 0);
  schema_attr_set_known(schema, 1);
  schema_attr_set_hidden(schema, 2);
  schema_attr_set_known(schema, 3);  // nationality
  schema_attr_set_known(schema, 4);  // age

  gmp_printf("4.2: primary credential crypto setup\n");
  issuer_sk_t iss_sk;
  issuer_pk_t iss_pk;
  issuer_keys_init_assign(iss_sk, iss_pk, 1000);

  gmp_printf("4.4 non-revocation credential crypto setup\n");
  element_t g1_gen;
  element_t g2_gen;
  element_init_G1(g1_gen, pairing);
  element_init_G2(g2_gen, pairing);
  element_random(g1_gen);
  element_random(g2_gen);

  nonrev_sk_t nr_sk;
  nonrev_pk_t nr_pk;
  nonrev_keys_init_assign(nr_sk, nr_pk, pairing, g1_gen, g2_gen);
  
  


  gmp_printf("clean up variables...\n");
  
  nonrev_pk_clear(nr_pk);
  nonrev_sk_clear(nr_sk);
  element_clear(g2_gen);
  element_clear(g1_gen);
  issuer_pk_clear(iss_pk);
  issuer_sk_clear(iss_sk);
  schema_clear(schema);
  pairing_clear(pairing);

  gmp_printf("goodbye!\n");
  return 0;
}
