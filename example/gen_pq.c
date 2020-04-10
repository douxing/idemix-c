#include <assert.h>
#include "idemix.h"

int main(int argc, char *argv[]) {
  mpz_t p, pp;
  mpz_inits(p, pp, NULL);

  do {
    random_prime_exact_bits(p, 1024);
    mpz_mul_ui(pp, p, 2);
    mpz_add_ui(pp, pp, 1);
  } while(!mpz_probab_prime_p(pp, REPS_VAL));
  gmp_printf("p' %Zd\n", p);

  do {
    random_prime_exact_bits(p, 1024);
    mpz_mul_ui(pp, p, 2);
    mpz_add_ui(pp, pp, 1);
  } while(!mpz_probab_prime_p(pp, REPS_VAL));
  gmp_printf("q' %Zd\n", p);

  mpz_clears(p, pp, NULL);
  return 0;
}
