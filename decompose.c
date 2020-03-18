#include "decompose.h"
#include <assert.h>

void four_squares_init(mpz_t fours[FOUR])
{
  mpz_inits(fours[0], fours[1], fours[2], fours[3], NULL);
}

void four_squares_clear(mpz_t fours[FOUR])
{
  mpz_clears(fours[0], fours[1], fours[2], fours[3], NULL);
}


// returns 1 if input is one of the special cases
//           and fours' last 3 slots set
// returns 0 otherwise and fours' no changed
int special_case_p(mpz_t fours[FOUR], mpz_t input)
{
  if (!mpz_cmp_ui(input, 2)) {
    mpz_set_ui(fours[1], 0);
    mpz_set_ui(fours[2], 1);
    mpz_set_ui(fours[3], 1);
    return 1;
  }
  if (!mpz_cmp_ui(input, 3)) {
    mpz_set_ui(fours[1], 1);
    mpz_set_ui(fours[2], 1);
    mpz_set_ui(fours[3], 1);
    return 1;
  }
  if (!mpz_cmp_ui(input, 10)) {
    mpz_set_ui(fours[1], 0);
    mpz_set_ui(fours[2], 1);
    mpz_set_ui(fours[3], 3);
    return 1;
  }
  if (!mpz_cmp_ui(input, 34)) {
    mpz_set_ui(fours[1], 3);
    mpz_set_ui(fours[2], 3);
    mpz_set_ui(fours[3], 4);
    return 1;
  }

  if (!mpz_cmp_ui(input, 58)) {
    mpz_set_ui(fours[1], 0);
    mpz_set_ui(fours[2], 3);
    mpz_set_ui(fours[3], 7);
    return 1;
  }
  if (!mpz_cmp_ui(input, 85)) {
    mpz_set_ui(fours[1], 0);
    mpz_set_ui(fours[2], 6);
    mpz_set_ui(fours[3], 7);
    return 1;
  }
  if (!mpz_cmp_ui(input, 130)) {
    mpz_set_ui(fours[1], 0);
    mpz_set_ui(fours[2], 3);
    mpz_set_ui(fours[3], 11);
    return 1;
  }
  if (!mpz_cmp_ui(input, 214)) {
    mpz_set_ui(fours[1], 3);
    mpz_set_ui(fours[2], 6);
    mpz_set_ui(fours[3], 13);
    return 1;
  }
  if (!mpz_cmp_ui(input, 226)) {
    mpz_set_ui(fours[1], 8);
    mpz_set_ui(fours[2], 9);
    mpz_set_ui(fours[3], 9);
    return 1;
  }
  if (!mpz_cmp_ui(input, 370)) {
    mpz_set_ui(fours[1], 8);
    mpz_set_ui(fours[2], 9);
    mpz_set_ui(fours[3], 15);
    return 1;
  }
  if (!mpz_cmp_ui(input, 526)) {
    mpz_set_ui(fours[1], 6);
    mpz_set_ui(fours[2], 7);
    mpz_set_ui(fours[3], 21);
    return 1;
  }
  if (!mpz_cmp_ui(input, 706)) {
    mpz_set_ui(fours[1], 15);
    mpz_set_ui(fours[2], 15);
    mpz_set_ui(fours[3], 16);
    return 1;
  }
  if (!mpz_cmp_ui(input, 730)) {
    mpz_set_ui(fours[1], 0);
    mpz_set_ui(fours[2], 1);
    mpz_set_ui(fours[3], 27);
    return 1;
  }
  if (!mpz_cmp_ui(input, 1414)) {
    mpz_set_ui(fours[1], 6);
    mpz_set_ui(fours[2], 17);
    mpz_set_ui(fours[3], 33);
    return 1;
  }
  if (!mpz_cmp_ui(input, 1906)) {
    mpz_set_ui(fours[1], 13);
    mpz_set_ui(fours[2], 21);
    mpz_set_ui(fours[3], 36);
    return 1;
  }
  if (!mpz_cmp_ui(input, 2986)) {
    mpz_set_ui(fours[1], 21);
    mpz_set_ui(fours[2], 32);
    mpz_set_ui(fours[3], 39);
    return 1;
  }
  if (!mpz_cmp_ui(input, 9634)) {
    mpz_set_ui(fours[1], 56);
    mpz_set_ui(fours[2], 57);
    mpz_set_ui(fours[3], 57);
    return 1;
  }

  return 0;
}

void isqrt(mpz_t square, mpz_t rem, const mpz_t n)
{
  assert(mpz_sgn(n) >= 0);
  mpz_sqrtrem(square, rem, n);
}

// returns 1 means p is a square number and equals ui^2
// returns 0 means p is a (probab) prime and ui is the imaginary unit
int iunit(mpz_t iu, const mpz_t p)
{
  // pre-condition: p % 4 == 1 (q == ...01 base2)
  assert( mpz_tstbit(p, 0));
  assert(!mpz_tstbit(p, 1));

  // 0: continue while loop
  // 1: calculte ui using b := b^((p - 1) / 4) mod p
  // 2: p == ui^2, do nothing after the while loop
  int flag = 0;

  mpz_t q, t;
  mpz_inits(q, t, NULL);

  if (mpz_tstbit(p, 2)) {
    // with pre-conditions, this implies q & 7 == 5 (q == ...101 base2)
    flag = 1;
    mpz_set_ui(q, 2);
  } else {
    flag = 0;
    mpz_set_ui(q, 3); // set q to be the first odd prime
    do {
      // according to the article:
      // (q % 2 = 1) and (p % 4 = 1) implies jacobi(q, p) = jacobi(p % q, q)
      mpz_mod(t, p, q); // t = p mod q
      if (mpz_jacobi(t, q) == 1) {
	// jacobi(q, p) == 1
	mpz_nextprime(q, q);
	if (!mpz_cmp_ui(q, 229)) {
	  // too many iterates, test if p is a square
	  isqrt(iu, t, p);
	  if (!mpz_sgn(t)) {
	    flag = 2;
	  }
	}
      } else {
	flag = 1;
      }
    } while(!flag);
  }

  if (flag == 1) {
    mpz_tdiv_q_2exp(t, p, 2); // no need to minus 2 before shift
    mpz_powm(iu, q, t, p);
  }

  mpz_clears(q, t, NULL);
  return flag - 1;
}

// returns 1 on success: p = a^2 + b^2
// returns 0 on failure: decomposition is unsuccessful
int decompose_prime(mpz_t a, mpz_t b, const mpz_t n)
{
  // pre-condition: n is a prime, n % 4 == 1 (p == ...01 base2)
  assert( mpz_tstbit(n, 0));
  assert(!mpz_tstbit(n, 1));

  if (iunit(b, n)) {
    // return 0, b, TRUE
    mpz_set_ui(a, 0);
    return 1;
  }

  // gmp_printf("iunit(%Zd, %Zd)\n", b, n);
  mpz_mul(a, b, b);
  mpz_add_ui(a, a, 1);
  mpz_mod(a, a, n);
  if (mpz_sgn(a)) {
    mpz_set_ui(a, 0);
    mpz_set_ui(b, 0);
    return 0;
  }

  mpz_t t;
  mpz_init(t);
  mpz_set(a, n);
  mpz_mul(t, b, b); // t = b * b
  while (mpz_cmp(t, n) > 0) {
    mpz_mod(t, a, b);
    mpz_swap(a, b);
    mpz_swap(b, t);
    mpz_mul(t, b, b);
  }

  // dx: different from the document
  mpz_mod(a, a, b);
  assert(mpz_cmp(a, b) <= 0);
  mpz_clear(t);
  return 1;
}

void sort_scaled(mpz_t fours[FOUR], const mpz_t v)
{
  if (mpz_cmp(fours[0], fours[1]) > 0) {
    mpz_swap(fours[0], fours[1]);
  } // post-condition: fours[0] < fours[1]



  if (mpz_cmp(fours[2], fours[3]) > 0) {
    mpz_swap(fours[2], fours[3]);
  } // post-condition: fours[2] < fours[3]


  if (mpz_cmp(fours[0], fours[2]) > 0) {
    mpz_swap(fours[0], fours[2]);
  } // post-condition: fours[1] is the minimum

  if (mpz_cmp(fours[1], fours[3]) > 0) {
    mpz_swap(fours[1], fours[3]);
  } // post-condition: fours[3] is the maximum


  if (mpz_cmp(fours[1], fours[2]) > 0) {
    mpz_swap(fours[1], fours[2]);
  } // order the number in between

  mpz_mul(fours[0], fours[0], v);
  mpz_mul(fours[1], fours[1], v);
  mpz_mul(fours[2], fours[2], v);
  mpz_mul(fours[3], fours[3], v);
}

// this function is guaranteed to return okay
// pre-condition: n >= 0
// returns 1 on success, 0 otherwise
// sorted 4 square roots in incresing order
int decompose(mpz_t fours[FOUR], mpz_t n)
{
  assert(mpz_sgn(n) >= 0);  // pre-condition: n >= 0

  if (!mpz_cmp_ui(n, 0)) {
    mpz_set_ui(fours[0], 0);
    mpz_set_ui(fours[1], 0);
    mpz_set_ui(fours[2], 0);
    mpz_set_ui(fours[3], 0);
    return 1;
  }

  if (!mpz_cmp_ui(n, 1)) {
    mpz_set_ui(fours[0], 0);
    mpz_set_ui(fours[1], 0);
    mpz_set_ui(fours[2], 0);
    mpz_set_ui(fours[3], 1);
    return 1;
  }

  mpz_t r0, r1, v, sqr, p, delta;
  mpz_inits(r0, r1, v, sqr, p, delta, NULL);

  mpz_set_ui(v, 1);
  while(!mpz_tstbit(n, 0) && !mpz_tstbit(n, 1)) { // n & 3 == 0
    mpz_tdiv_q_2exp(n, n, 2);
    mpz_add(v, v, v);
  }

  // post-condition:
  // 1. original n = v^2 * n
  // 2. n % 4 != 0
  // 3. v = 2^k for some k >= 0

  isqrt(sqr, p, n);

  // gmp_printf("isqrt(%Zd, %Zd, %Zd)\n", sqr, p, n);

  if (!mpz_sgn(p)) {
    mpz_set_ui(fours[0], 0);
    mpz_set_ui(fours[1], 0);
    mpz_set_ui(fours[2], 0);
    mpz_mul(fours[3], v, sqr);
    mpz_clears(r0, r1, v, sqr, p, delta, NULL);
    return 1;
  }

  if (mpz_tstbit(n, 0) && !mpz_tstbit(n, 1)) { // n & 3 == 1
    if (mpz_probab_prime_p(n, REPS_VAL)) { // n is prime
      if (decompose_prime(sqr, p, n)) { // if done
	mpz_set_ui(fours[0], 0);
	mpz_set_ui(fours[1], 0);
	mpz_set(fours[2], sqr);
	mpz_set(fours[3], p);
	sort_scaled(fours, v);
	mpz_clears(r0, r1, v, sqr, p, delta, NULL);
	return 1;
      }
    }
  }

  if (mpz_tstbit(n, 0) &&  mpz_tstbit(n, 1) && mpz_tstbit(n, 2)) {
    // gmp_printf("n == 7 mod 8\n");
    // in this case: n & 7 = 7, which means n = 8m + 7 (n = ...111 base2)
    // subtract largest square delta^2
    // s.t. (n > delta^2) and (delta^2 % 8 != 0)
    mpz_set(delta, sqr);
    mpz_set(n, p);
    if (!mpz_tstbit(sqr, 0) && !mpz_tstbit(sqr, 1)) { // sqr & 3 == 0
      mpz_sub_ui(delta, delta, 1); // new_delta = old_delta - 1
      mpz_add(n, n, delta); // new_n = old_n + new_delta + new_delta + 1
      mpz_add(n, n, delta);
      mpz_add_ui(n, n, 1);
    }

    // dx: try to understand:
    // sqr^2 + p = delta^2 + n = 8m + 7 (*)
    // if sqr % 4 == 0 then if statement is entered:
    // delta % 8 in [3, 7] => delta^2 % 8 == 1
    // (*) holds => n % 8 == 6 (1)
    // if sqr % 4 != 0 then if statement is NOT entered:
    // then delta % 8 in [1,2,3,5,6,7] => delta^2 % 8 in [1, 4]
    // (*) holds => n % 8 in [3, 6] (2)
    // (1) (2) implies n % 4 != 1, then n != a^2 + b^2

    isqrt(sqr, p, n);
  } else {
    // gmp_printf("n != 7 mod 8\n");
    mpz_set_ui(delta, 0); // only 3 square roots is enough
  }

  // delta is the first square root
  // post-condition: sqr = isqrt(n), n % 8 == 7, n % 4 != 0
  // and old_n = v^2 * (new_n + delta^2)
  // this implies n = a^2 + b^2 + c^2
  
  // check for special cases:
  if (special_case_p(fours, n)) {
    // gmp_printf("is special case: %Zd\n", n);
    // fours[1], fours[2], fours[3] set
    mpz_set(fours[0], delta);
    sort_scaled(fours, v);
    mpz_clears(r0, r1, v, sqr, p, delta, NULL);
    return 1;
  }

  // gmp_printf("NOT special case: %Zd\n", n);

  // Case 1: n % 4 == 3, n = x^2 + 2*p, p % 4 == 1
  //         p is a prime, p = x^2 + y^2 => n = x^2 + (y+z)^2 + (y-z)^2
  if (mpz_tstbit(n, 0) && mpz_tstbit(n, 1)) {
    // gmp_printf("CASE 1\n");

    if (!mpz_tstbit(sqr, 0)) {
      mpz_sub_ui(sqr, sqr, 1);
      mpz_add(p, p, sqr);
      mpz_add(p, p, sqr);
      mpz_add_ui(p, p, 1);
    }
    mpz_tdiv_q_2exp(p, p, 1);
    while (1) {
      if (mpz_probab_prime_p(p, REPS_VAL)) {
	if (decompose_prime(r0, r1, p)) {
	  mpz_set(fours[0], delta);
	  mpz_set(fours[1], sqr);
	  mpz_add(fours[2], r0, r1);
	  mpz_sub(fours[3], r0, r1);
	  mpz_abs(fours[3], fours[3]);
	  sort_scaled(fours, v);
	  mpz_clears(r0, r1, v, sqr, p, delta, NULL);
	  return 1;
	}
      }

      mpz_sub_ui(sqr, sqr, 2);

      assert(mpz_sgn(sqr) > 0);
      if (mpz_sgn(sqr) < 0) {
	  mpz_set_ui(fours[0], 0);
	  mpz_set_ui(fours[1], 0);
	  mpz_set_ui(fours[2], 0);
	  mpz_set_ui(fours[3], 0);
	  mpz_clears(r0, r1, v, sqr, p, delta, NULL);
	  return 0; // not going to happen
      }

      mpz_add(p, p, sqr);
      mpz_add(p, p, sqr);
      mpz_add_ui(p, p, 2);
    }
  }

  // Case 2: n % 4 = 1 or n % 4 = 2, n = x^2 + p,
  //         p % 4 = 1, p prime, p = y^2 + z^2 implies n = x^2 + y^2 + z^2
  assert((!mpz_tstbit(n, 0) && mpz_tstbit(n, 1))
	 || (mpz_tstbit(n, 0) && !mpz_tstbit(n, 1)));

  // gmp_printf("CASE 2\n");

  mpz_sub(r0, n, sqr);
  if (!mpz_tstbit(r0, 0)) {
    mpz_sub_ui(sqr, sqr, 1);
    mpz_add(p, p, sqr);
    mpz_add(p, p, sqr);
    mpz_add_ui(p, p, 1);
  }
  while (1) {
    if (mpz_probab_prime_p(p, REPS_VAL)) {
      if (decompose_prime(r0, r1, p)) {
	mpz_set(fours[0], delta);
	mpz_set(fours[1], sqr);
	mpz_set(fours[2], r0);
	mpz_set(fours[3], r1);
	sort_scaled(fours, v);
	mpz_clears(r0, r1, v, sqr, p, delta, NULL);
	return 1;
      }
    }
    
    mpz_sub_ui(sqr, sqr, 2);

    assert(mpz_sgn(sqr) > 0);
    if (mpz_sgn(sqr) < 0) {
      mpz_set_ui(fours[0], 0);
      mpz_set_ui(fours[1], 0);
      mpz_set_ui(fours[2], 0);
      mpz_set_ui(fours[3], 0);
      mpz_clears(r0, r1, v, sqr, p, delta, NULL);
      return 0; // not going to happen
    }

    mpz_add_ui(r0, sqr, 1); // r0 = sq + 1
    mpz_add(r0, r0, r0); // r0 = 2 * r0
    mpz_add(r0, r0, r0); // r0 = 2 * r0
    mpz_add(p, p, r0);
  }
}
