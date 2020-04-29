#include <assert.h>
#include <stdlib.h>
#include <sys/time.h>
#include "idemix.h"

static unsigned long L = 8;
static unsigned long INDEX = 5;

static pairing_t pairing;
static schema_t schema;
static unsigned long attr_num;
static predicate_ptr predicates;
static predicate_subproof_tuple_c_ptr predCs;
static predicate_subproof_ptr predsps;
static predicate_subproof_auxiliary_ptr pred_auxes;
static unsigned long pred_num;

// Issuer的公私钥
static mpz_t p_apos, q_apos;
static issuer_sk_t iss_sk; // 私钥
static issuer_pk_t iss_pk; // 公钥
int init_issuer_keys(char *file_path) {
  mpz_inits(p_apos, q_apos, NULL);
  FILE *fp = fopen(file_path, "r");
  if (gmp_fscanf(fp, "p' %Zd\nq' %Zd\n", p_apos, q_apos) != 2) {
    return -1;
  }
  issuer_keys_init_assign(iss_sk, iss_pk, attr_num, p_apos, q_apos);
  fclose(fp);
  return 0;
}

// Non-revocation的生成元和公私钥
static element_t g1_gen;
static element_t g2_gen;
static nonrev_sk_t nr_sk;
static nonrev_pk_t nr_pk;
void init_nonrev_keys() {
  element_init_G1(g1_gen, pairing);
  element_init_G2(g2_gen, pairing);
  element_random(g1_gen);
  element_random(g2_gen);
  nonrev_keys_init_assign(nr_sk, nr_pk, pairing, g1_gen, g2_gen);
}

// 累加器
static accumulator_t acc;
static accumulator_sk_t acc_sk;
static accumulator_pk_t acc_pk;

void print_with_time(char* s) {
  struct timeval now;
  gettimeofday(&now, NULL);
  printf("%d.%-6d: %s", now.tv_sec, now.tv_usec, s);
}

int main(int argc, char *argv[]) {
  if (argc != 5) {
    gmp_printf("usage:\n  %s param_file(a.param) pq_crypto_file(pq.crypto) attr_num pred_num\n", argv[0]);
    return -1;
  }

  attr_num = atoi(argv[3]);
  pred_num = atoi(argv[4]);

  if (attr_num < pred_num) {
    print_with_time("error: attr_num < pred_num!\n");
    return -1;
  }
  if (L < attr_num) {
    L = attr_num;
  }

  printf("L: %d, attribute number: %d, predicate num: %d\n",
	 L, attr_num, pred_num);

  print_with_time("初始化双线性对数据\n");
  if (pbc_pairing_init_from_path(pairing, argv[1])) {
    gmp_printf("pairing load error.\n");
    return -1;
  }

  print_with_time("Issuer准备密码学工具\n");
  {
    // 自行生成p q等参数很慢，直接读取之前生成的数据
    print_with_time("Issuer Key...\n");
    if (init_issuer_keys(argv[2])) {
      printf("p', q'读取错误.\n");
      return -1;
    }
    gmp_printf("从%s读取：\np': %Zd\nq': %Zd\n", argv[2], p_apos, q_apos);

    print_with_time("Non-revocation Key...\n");
    init_nonrev_keys();

    print_with_time("累加器...\n");
    accumulator_init_assign(acc, acc_sk, acc_pk,
                            pairing, L,
                            g1_gen, g2_gen);
  }
  print_with_time("密码学工具准备完毕\n");

  print_with_time("初始化schema等常量数据...\n");
  schema_init(schema, attr_num);
  for (unsigned long i = 0; i < attr_num; ++i) {
    schema_attr_set_known(schema, i);
  }
  print_with_time("初始化schema等常量数据完毕...\n");

  FILE *statfile = fopen("stat.py", "a");
  if (statfile == NULL) {
    printf("statfile open error\n");
    return -1;
  }

  struct timeval start, stop;
  unsigned long span = 0;

  attr_vec_t Ah; 
  attr_vec_init(Ah, 0);

  attr_vec_t Ak;
  attr_vec_init(Ak, attr_num);
  for (unsigned long i = 0; i < attr_num; ++i) {
    mpz_set_ui(attr_vec_head(Ak)[i].v, 10);
    attr_vec_head(Ak)[i].i = i;
  }

  print_with_time("发证开始\n");
  gettimeofday(&start, NULL);

  mpz_t nonce, v_apos;
  mpz_inits(nonce, v_apos, NULL);
  random_num_bits(nonce, 32); // nonce from Issuer, make it 80 bits
  random_num_exact_bits(v_apos, 2128);

  primary_credential_request_t pc_req;
  primary_credential_request_init(pc_req, schema);

  primary_credential_request_assign(pc_req,
                                    iss_pk,
                                    nonce,
                                    v_apos,
                                    Ah);
  /*
  element_t s_apos;
  element_init_Zr(s_apos, pairing);
  element_random(s_apos);
  nonrev_credential_request_t nrc_req;
  nonrev_credential_request_init(nrc_req, pairing);
  nonrev_credential_request_assign(nrc_req, s_apos, nr_pk);

  if (primary_credential_request_verify(pc_req, iss_pk, nonce)) {
    print_with_time("primary pre credential prepare verifyed: error\n");
    return -1;
  }
  */
  
  primary_credential_response_t pc_res;
  primary_credential_response_init(pc_res, schema);
  primary_credential_response_assign(pc_res, iss_pk, iss_sk, Ak, pc_req);

  /*
  nonrev_credential_response_t nrc_res;
  nonrev_credential_response_init(nrc_res, pairing);
  nonrev_credential_response_assign(nrc_res,
                                    attr_vec_head(Ak)[1].v, // m2
                                    INDEX,
                                    nr_pk,
                                    nr_sk,
                                    acc,
                                    acc_pk,
                                    acc_sk,
                                    nrc_req);
  */

  primary_credential_t pc;
  primary_credential_init(pc, schema);
  primary_credential_assign(pc, v_apos, Ah, pc_res);
  if (primary_credential_response_verify(pc_res, iss_pk, pc_req->n1, pc)) {
    print_with_time("primary pre credential error\n");
    return -1;    
  }

  gettimeofday(&stop, NULL);  
  print_with_time("发证结束\n");
  span = (stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec;
  printf("耗时(毫秒)span=%d.%d\n", span / 1000, span % 1000);
  fprintf(statfile, "issue_time += %d\n", span);

  /*
  nonrev_credential_t nrc;
  nonrev_credential_init(nrc, pairing);
  nonrev_credential_assign(nrc, s_apos, nrc_res);
  */

  attr_vec_t Ar_bar; // m_tildes
  attr_vec_init_random(Ar_bar, attr_num, 592);
  for (unsigned long i = 0; i < attr_num; ++i) {
    attr_vec_head(Ar_bar)[i].i = i;    
  }

  attr_vec_t Ar;
  attr_vec_init(Ar, 0);

  print_with_time("证明开始\n");
  gettimeofday(&start, NULL);  

  mpz_vec_t spT, spC; // T for subproof
  mpz_vec_init(spT);
  mpz_vec_init(spC);

  /*
  nonrev_credential_update(nrc, acc); // dx: nothing changed
  nonrev_credential_subproof_auxiliary_t nrcsp_aux;
  nonrev_credential_subproof_auxiliary_init(nrcsp_aux, pairing);
  nonrev_credential_subproof_auxiliary_assign(nrcsp_aux, nrc);

  nonrev_credential_subproof_tuple_c_t nrspC; // C for nonrev subproof
  nonrev_credential_subproof_tuple_c_init(nrspC, pairing);
  nonrev_credential_subproof_tuple_c_assign(nrspC, nr_pk, nrc, nrcsp_aux, acc);
  nonrev_credential_subproof_tuple_c_into_vec(spC, nrspC);
  nonrev_credential_subproof_dump_t(spT, pairing, nr_pk, acc, nrcsp_aux, nrspC);
  */
 
  primary_credential_subproof_auxiliary_t pcsp_aux;
  primary_credential_subproof_auxiliary_init(pcsp_aux);
  primary_credential_subproof_auxiliary_assign(pcsp_aux, pc);
  primary_credential_subproof_tuple_c_t pcspC;
  primary_credential_subproof_tuple_c_init(pcspC);
  primary_credential_subproof_tuple_c_assign(pcspC, iss_pk, pc, pcsp_aux);
  primary_credential_subproof_tuple_c_into_vec(spC, pcspC);

  primary_credential_subproof_dump_t(spT, iss_pk, Ar_bar, pcsp_aux, pcspC);

  mpz_t z;
  mpz_init(z);
  mpz_set_ui(z, 11);
  pred_auxes = (predicate_subproof_auxiliary_ptr)malloc(sizeof(predicate_subproof_auxiliary_t) * pred_num);
  predicates = (predicate_ptr)malloc(sizeof(predicate_t) * pred_num);
  predCs = (predicate_subproof_tuple_c_ptr)malloc(sizeof(predicate_subproof_tuple_c_t) * pred_num);
  for (unsigned long i = 0; i < pred_num; ++i) {
    predicate_subproof_auxiliary_init(pred_auxes+i);

    predicate_init_assign(predicates+i,
			  LESS_THAN,
			  attr_vec_head(Ak)[i].v,
			  z);

    predicate_subproof_auxiliary_assign(pred_auxes+i,
					predicates+i,
					attr_vec_head(Ar_bar)[i].v);
    
    predicate_subproof_tuple_c_init(predCs+i);
    predicate_subproof_tuple_c_assign(predCs+i, iss_pk, pred_auxes+i);
    predicate_subproof_tuple_c_into_vec(spC, predCs+i);
    predicate_subproof_dump_t(spT, iss_pk, pred_auxes+i, predCs+i);
  }

  mpz_t CH;
  mpz_init(CH);
  sm3_TCn(CH, spT, spC, nonce);

  /*
  tuple_x_t X; // subproof for non revocation
  tuple_x_init(X, pairing);
  tuple_x_assign(X, CH, attr_vec_head(Ak)[1].v, nrc, nrcsp_aux);
  */

  primary_credential_subproof_t pcsp;
  primary_credential_subproof_init(pcsp, attr_num);
  primary_credential_subproof_assign(pcsp,
                                     CH,
                                     Ar_bar,
                                     pc,
                                     pcsp_aux,
                                     pcspC->A_apos);

  predsps = (predicate_subproof_ptr)malloc(sizeof(predicate_subproof_t) * pred_num);
  for (unsigned long i = 0; i < pred_num; ++i) {
    predicate_subproof_init(predsps + i);
    predicate_subproof_assign(predsps + i, CH, predicates+i, pred_auxes+i);
  }

  gettimeofday(&stop, NULL);  
  print_with_time("证明结束\n");
  span = (stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec;
  printf("耗时(毫秒)span=%d.%d\n", span / 1000, span % 1000);
  fprintf(statfile, "prove_time += %d\n", span);

  print_with_time("验证开始\n");
  gettimeofday(&start, NULL);  

  mpz_vec_t checkT;
  mpz_vec_init(checkT);
  /*
  nonrev_credential_subcheck_dump_t(checkT,
                                    pairing,
                                    CH,
                                    acc,
                                    acc_pk,
                                    nr_pk,
                                    X,
                                    nrspC);
  */

  primary_credential_subcheck_dump_t(checkT, iss_pk, CH, Ar, pcsp);
  for (unsigned long i = 0; i < pred_num; ++i) {
    predicate_subcheck_dump_t(checkT, iss_pk, CH, predicates+i, predCs+i, predsps+i);
  }

  mpz_t CH1;
  mpz_init(CH1);
  sm3_TCn(CH1, checkT, spC, nonce);

  gettimeofday(&stop, NULL);
  print_with_time("验证结束\n");
  span = (stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec;
  printf("耗时(毫秒)span=%d.%d\n", span / 1000, span % 1000);
  fprintf(statfile, "verify_time += %d\n", span);

  printf("例子结束(%d, %d)，bye!\n",
	 mpz_vec_size(spT),
	 mpz_vec_size(checkT));
  fprintf(statfile, "counter += 1\n\n");
  fclose(statfile);
  return 0;
}
