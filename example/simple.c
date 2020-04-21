#include <assert.h>
#include "idemix.h"

// dx: kindly remind don't get confused
// use this value both L in accumulator and l in primary credential crypto
#define L 16

// index i < L, picked by Issuer, first item in page 5
#define INDEX 10

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
  char *p_apos_str = "173628922298686045020428559970675111465203302151827445847908795228013832423228784296158592917582239150796838330441923803511600970530804742977150486806704676486180147030392605390859997909451933124666121832714651567164808132660770837339740693245220964374024614768999085431492435327781011462395999287424603706073";
  char *q_apos_str = "145046181312680974872097511099498940411577803531108057745262901008932754163706572141412464363559833363924244165374828845964557879722071900654599850885551493617541831654693100926057793145360422594018596283879918139922248607395251741757811601254413148635509570785585942719467320558644620657163707820723344405421";

  mpz_t p_apos, q_apos;
  mpz_inits(p_apos, q_apos, NULL);
  if (!gmp_sscanf(p_apos_str, "%Zd", p_apos)) {
    gmp_printf("error reading p'\n");
    return -1;
  }
  if (!gmp_sscanf(q_apos_str, "%Zd", q_apos)) {
    gmp_printf("error reading q'\n");
    return -1;
  }

  issuer_sk_t iss_sk;
  issuer_pk_t iss_pk;
  issuer_keys_init_assign(iss_sk, iss_pk, L, p_apos, q_apos);


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

  gmp_printf("4.4.1 new accumulator setup\n");

  accumulator_t acc;
  accumulator_sk_t acc_sk;
  accumulator_pk_t acc_pk;
  accumulator_init_assign(acc, acc_sk, acc_pk,
                          pairing, L,
                          g1_gen, g2_gen);

  // assistant values:
  mpz_t zero, hundred, t0, t1;
  mpz_inits(zero, hundred, t0, t1, NULL);

  mpz_set_ui(zero, 0);
  mpz_set_ui(hundred, 100);

  // values in the schema:
  mpz_t m1, m2, m3, m4, m5; // five value as said
  mpz_inits(m1, m2, m3, m4, m5, NULL);

  // dx: holder_id is the florished H in 5.1
  mpz_t n0, v_apos, holder_id;
  mpz_inits(n0, v_apos, holder_id, NULL);

  // Holder|Prover set m1 and m3 and Issuer set the rest values
  random_num_bits(m1, 64); // link secret
  mpz_set_ui(m3, 0); // dx: not using this value

  gmp_printf("5.1 Holder setup\n");
  gmp_printf("- Set hidden attributes {mi}, i in Ah\n");
  attr_vec_t Ah;
  attr_vec_init(Ah, 2); // m1 and m3
  attr_vec_head(Ah)[0].i = 0;
  mpz_set(attr_vec_head(Ah)[0].v, m1);
  attr_vec_head(Ah)[1].i = 2;
  mpz_set(attr_vec_head(Ah)[1].v, m3);

  gmp_printf("- Establishes a connection with Issuer and gets nonce n0 either from Issuer or as a precomputed value.\n");
  random_num_bits(n0, 80); // nonce from Issuer, make it 80 bits
  gmp_printf("- Holder is known to Issuer with identiﬁer H(holder_id).\n");
  random_num_bits(holder_id, 32); // generate holder_id

  // Holder prepares data for primary credential
  // generate 2128 bit v', holder should store this value for later use
  gmp_printf("1. Generate random 2128-bit v0.\n");
  random_num_exact_bits(v_apos, 2128);

  primary_credential_request_t pc_req;
  primary_credential_request_init(pc_req, schema);

  primary_credential_request_assign(pc_req,
                                    iss_pk,
                                    n0,
                                    v_apos,
                                    Ah);
  // gmp_printf("n0: %Zd\nv': %Zd\nm1: %Zd\nm3: %Zd\nc(hash): %Zd\n",
  // n0, v_apos, m1, m3, pc_req->c);

  gmp_printf("Holder prepares for non-revocation credential\n");
  element_t s_apos;
  element_init_Zr(s_apos, pairing);
  element_random(s_apos);
  nonrev_credential_request_t nrc_req;
  nonrev_credential_request_init(nrc_req, pairing);
  nonrev_credential_request_assign(nrc_req, s_apos, nr_pk);

  gmp_printf("5.2 Primary Credential Issuance\n");
  gmp_printf("Issuer veriﬁes the correctness of Holder’s input\n");
  if (!primary_credential_request_verify(pc_req, iss_pk, n0)) {
    gmp_printf("primary pre credential prepare verifyed: okay\n");
  } else {
    gmp_printf("primary pre credential prepare verifyed: error\n");
    return -1;
  }

  gmp_printf("Issuer prepare the credential\n");

  mpz_t index;
  mpz_init(index);
  mpz_set_ui(index, INDEX); // i < L
  compute_m2(m2, index, holder_id);
  mpz_set_ui(m4, 86); // country code of China?
  mpz_set_ui(m5, 18); // age

  gmp_printf("m2: %Zd\nm4: %Zd\nm5: %Zd\n", m2, m4, m5);

  attr_vec_t Ak;
  attr_vec_init(Ak, schema_attr_cnt_known(schema));
  attr_vec_head(Ak)[0].i = 1;
  mpz_set(attr_vec_head(Ak)[0].v, m2);
  attr_vec_head(Ak)[1].i = 3;
  mpz_set(attr_vec_head(Ak)[1].v, m4);
  attr_vec_head(Ak)[2].i = 4;
  mpz_set(attr_vec_head(Ak)[2].v, m5);

  primary_credential_response_t pc_res;
  primary_credential_response_init(pc_res, schema);
  primary_credential_response_assign(pc_res, iss_pk, iss_sk, Ak, pc_req);

  gmp_printf("primary pre credential:\nA : %Zd\ne : %Zd\n",
             pc_res->A, pc_res->e);


  gmp_printf("5.3 Non-revocation Credential Issuance\n");
  nonrev_credential_response_t nrc_res;
  nonrev_credential_response_init(nrc_res, pairing);
  nonrev_credential_response_assign(nrc_res,
                                    m2,
                                    INDEX,
                                    nr_pk,
                                    nr_sk,
                                    acc,
                                    acc_pk,
                                    acc_sk,
                                    nrc_req);
  // gmp_printf("i: %d\n", nrc_res->i);
  // element_printf("w: %B\n", nrc_res->wit_i->w);

  gmp_printf("5.4 Storing Credentials\n");

  // N.B. order is a little different from document,
  //      because we have to construct Cs(All attributes array)
  //      before we can verify, so we can use these valuses
  //      directly from primary credential
  primary_credential_t pc;
  primary_credential_init(pc, schema);
  primary_credential_assign(pc, v_apos, Ah, pc_res);

  // gmp_printf("primary credential:\nA : %Zd\ne : %Zd\n",
  // pc->A, pc->e);

  if (!primary_credential_response_verify(pc_res, iss_pk, pc_req->n1, pc)) {
    gmp_printf("primary pre credential okay\n");
  } else {
    gmp_printf("primary pre credential error\n");
    return -1;
  }

  nonrev_credential_t nrc;
  nonrev_credential_init(nrc, pairing);
  nonrev_credential_assign(nrc, s_apos, nrc_res);

  gmp_printf("7.2 Proof preparation\n");
  gmp_printf("Holder prepares all credential pairs to submit\n");
  // open m4, the country code
  // and predicate 18 <= m5 < 20

  /* gmp_printf("update CNR, oldV: %Zd, newV: %Zd\n", */
  /*	     nrc->wit_i->V, acc->V); */
  attr_vec_t Ar_bar; // m_tildes
  attr_vec_init_random(Ar_bar, 4, 592); // open m4
  attr_vec_head(Ar_bar)[0].i = 0;
  attr_vec_head(Ar_bar)[1].i = 1;
  attr_vec_head(Ar_bar)[2].i = 2;
  attr_vec_head(Ar_bar)[3].i = 4; // m5_tilde

  mpz_vec_t spT, spC; // T for subproof
  mpz_vec_init(spT);
  mpz_vec_init(spC);

  element_printf("before norev_credential_update, w: %B\n", nrc->wit_i->w);
  nonrev_credential_update(nrc, acc); // dx: nothing changed
  element_printf("after norev_credential_update, w: %B\n", nrc->wit_i->w);
  nonrev_credential_subproof_auxiliary_t nrcsp_aux;
  nonrev_credential_subproof_auxiliary_init(nrcsp_aux, pairing);
  nonrev_credential_subproof_auxiliary_assign(nrcsp_aux, nrc);

  nonrev_credential_subproof_tuple_c_t nrspC; // C for nonrev subproof
  nonrev_credential_subproof_tuple_c_init(nrspC, pairing);
  nonrev_credential_subproof_tuple_c_assign(nrspC, nr_pk, nrc, nrcsp_aux, acc);
  nonrev_credential_subproof_tuple_c_into_vec(spC, nrspC);
  nonrev_credential_subproof_dump_t(spT, pairing, nr_pk, acc, nrcsp_aux, nrspC);
 
  gmp_printf("Validity proof:\n");
  primary_credential_subproof_auxiliary_t pcsp_aux;
  primary_credential_subproof_auxiliary_init(pcsp_aux);
  primary_credential_subproof_auxiliary_assign(pcsp_aux, pc);
  primary_credential_subproof_tuple_c_t pcspC;
  primary_credential_subproof_tuple_c_init(pcspC);
  primary_credential_subproof_tuple_c_assign(pcspC, iss_pk, pc, pcsp_aux);
  primary_credential_subproof_tuple_c_into_vec(spC, pcspC);

  primary_credential_subproof_dump_t(spT, iss_pk, Ar_bar, pcsp_aux, pcspC);

  mpz_t z5;
  mpz_init_set_ui(z5, 20);
  predicate_t pred;
  predicate_init_assign(pred, LESS_THAN, m5, z5);
  predicate_subproof_auxiliary_t pred_aux;
  predicate_subproof_auxiliary_init(pred_aux);
  predicate_subproof_auxiliary_assign(pred_aux,
                                      pred,
                                      attr_vec_head(Ar_bar)[3].v);
  predicate_subproof_tuple_c_t predC;
  predicate_subproof_tuple_c_init(predC);
  predicate_subproof_tuple_c_assign(predC, iss_pk, pred_aux);
  predicate_subproof_tuple_c_into_vec(spC, predC);
  predicate_subproof_dump_t(spT, iss_pk, pred_aux, predC);

  gmp_printf("7.2.1 Hashing\n");
  mpz_t CH;
  mpz_init(CH);
  sm3_TCn(CH, spT, spC, pc_req->n1);

  gmp_printf("7.2.2 final preparation\n");
  tuple_x_t X; // subproof for non revocation
  tuple_x_init(X, pairing);
  tuple_x_assign(X, CH, m2, nrc, nrcsp_aux);
  primary_credential_subproof_t pcsp;
  primary_credential_subproof_init(pcsp, 4);
  primary_credential_subproof_assign(pcsp,
                                     CH,
                                     Ar_bar,
                                     pc,
                                     pcsp_aux,
                                     pcspC->A_apos);
  predicate_subproof_t predsp;
  predicate_subproof_init(predsp);
  predicate_subproof_assign(predsp, CH, pred, pred_aux);

  gmp_printf("7.2.3 Sending (CH, X, PrC, PrP, C) to the Verifier\n");
  attr_vec_t Ar;
  attr_vec_init(Ar, 1);
  attr_vec_head(Ar)[0].i = 3;
  mpz_set(attr_vec_head(Ar)[0].v, m4);

  gmp_printf("7.3 Verification\n");

  mpz_vec_t checkT;
  mpz_vec_init(checkT);
  nonrev_credential_subcheck_dump_t(checkT,
                                    pairing,
                                    CH,
                                    acc,
                                    acc_pk,
                                    nr_pk,
                                    X,
                                    nrspC);
  primary_credential_subcheck_dump_t(checkT, iss_pk, CH, Ar, pcsp);
  predicate_subcheck_dump_t(checkT, iss_pk, CH, pred, predC, predsp);


  // dx test zone
  printf("-------------------- test zone ------------------------\n");


  for (unsigned long i = 0; i < mpz_vec_size(spT); ++i)
    {
      if (mpz_cmp(mpz_vec_head(spT) + i, mpz_vec_head(checkT) + i)) {
        gmp_printf("different T:\nT%dbar: %Zd\nT%dcar: %Zd\n",
                   i + 1,
                   mpz_vec_head(spT) + i,
                   i + 1,
                   mpz_vec_head(checkT) + i);
        return -1;
      }
    }
  gmp_printf("All Ts are the same.\n");
  
  mpz_t CH1;
  mpz_init(CH1);
  sm3_TCn(CH1, checkT, spC, pc_req->n1);
  gmp_printf("CH : %Zd\nCH1: %Zd\n", CH, CH1);

  printf("-------------------- test zone end --------------------\n");

  gmp_printf("clean up variables...\n");
  mpz_clear(CH1);
  mpz_vec_clear(checkT);
  attr_vec_clear(Ar);

  predicate_subproof_clear(predsp);
  primary_credential_subproof_clear(pcsp);
  tuple_x_clear(X);
  mpz_clear(CH);

  predicate_subproof_tuple_c_clear(predC);
  predicate_subproof_auxiliary_clear(pred_aux);
  predicate_clear(pred);
  mpz_clear(z5);
  attr_vec_clear(Ar_bar);
  primary_credential_subproof_tuple_c_clear(pcspC);
  primary_credential_subproof_auxiliary_clear(pcsp_aux);
  nonrev_credential_subproof_tuple_c_clear(nrspC);
  nonrev_credential_subproof_auxiliary_clear(nrcsp_aux);
  mpz_vec_clear(spC);
  mpz_vec_clear(spT);

  nonrev_credential_clear(nrc);
  primary_credential_clear(pc);
  nonrev_credential_response_clear(nrc_res);
  primary_credential_response_clear(pc_res);
  attr_vec_clear(Ak);
  mpz_clear(index);
  nonrev_credential_request_clear(nrc_req);
  primary_credential_request_clear(pc_req);
  attr_vec_clear(Ah);
  element_clear(s_apos);
  mpz_clears(n0, v_apos, holder_id, NULL);
  mpz_clears(m1, m2, m3, m4, m5, NULL);
  mpz_clears(zero, hundred, t0, t1, NULL);

  accumulator_clear(acc);
  accumulator_pk_clear(acc_pk);
  accumulator_sk_clear(acc_sk);
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
