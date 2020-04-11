// 本例子使用中文注释
// 本例子模拟个人和公司在政府做的一些背书
// 只做演示之用
// 本例子假设有2个公司和2个自然人
// Alice同时在alpha和beta工作，Bob只在alpha工作

#include <assert.h>
#include "idemix.h"

#define L 16
#define ALPHA_ID 10001
#define BETA_ID  10002
#define ALICE_ID 20001
#define BOB_ID   20002

static pairing_t pairing;

static schema_t schema_employee; // 公司员工信息
static schema_t schema_company; // 公司信息

void init_schemas()
{
  // 前三个属性为保留属性
  // 根据文档， m1和m3是隐藏的，m2是已知的
  // 这里的隐藏和已知，是Issuer和Holder之间的概念
  // 隐藏属性是Holder设置的，Issuer不知道
  // 已知属性是Issuer设置的，根据文档，可以和Holder提前约定该值
  // Holder知道所有属性的值

  // employee schema，共7个属性，四个自定义属性，两个已知，两个隐藏
  schema_init(schema_employee, 7);
  schema_attr_set_hidden(schema_employee, 0);
  schema_attr_set_known(schema_employee, 1);
  schema_attr_set_hidden(schema_employee, 2);
  schema_attr_set_known(schema_employee, 3);  // 个人身份id
  schema_attr_set_known(schema_employee, 4);  // 公司名称(id)
  schema_attr_set_hidden(schema_employee, 5); // 个人薪水
  schema_attr_set_hidden(schema_employee, 6); // 入职日期

  // company schema，共6个属性，三个自定义属性，一个已知，两个隐藏
  schema_init(schema_company, 6);
  schema_attr_set_hidden(schema_company, 0);
  schema_attr_set_known(schema_company, 1);
  schema_attr_set_hidden(schema_company, 2);
  schema_attr_set_known(schema_company, 3); // 公司名称(id)
  schema_attr_set_hidden(schema_company, 4); // 公司现金
  schema_attr_set_hidden(schema_company, 5); // 公司负债
}

static mpz_t ZERO, ONE; // 常量
static unsigned long Index; // 累加器相关的全局索引变量
static mpz_t Alice_LinkSecret, Bob_LinkSecret;
void init_assistant_globals() {
  mpz_inits(ZERO, ONE, NULL);
  mpz_set_ui(ZERO, 0);
  mpz_set_ui(ONE,  1);

  Index = 0; // start from Zero

  mpz_inits(Alice_LinkSecret, Bob_LinkSecret, NULL);
  random_num_bits(Alice_LinkSecret, 64);
  random_num_bits(Bob_LinkSecret, 64);
}
static unsigned long next_Index() {
  return Index++;
}

// 政府作为Issuer的公私钥
static mpz_t p_apos, q_apos;
static issuer_sk_t gov_sk; // 私钥
static issuer_pk_t gov_pk; // 公钥
int init_issuer_keys(char *file_path) {
  mpz_inits(p_apos, q_apos, NULL);
  FILE *fp = fopen(file_path, "r");
  if (gmp_fscanf(fp, "p' %Zd\nq' %Zd\n", p_apos, q_apos) != 2) {
    return -1;
  }
  issuer_keys_init_assign(gov_sk, gov_pk, L, p_apos, q_apos);
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

// Alice_alpha 相关
static unsigned long Alice_alpha_Index;
static mpz_t Alice_alpha_holder_id, Alice_alpha_n0, Alice_alpha_v_apos;
static element_t Alice_alpha_s_apos;
static attr_vec_t Alice_alpha_Ah, Alice_alpha_Ak;
static primary_pre_credential_prepare_t Alice_alpha_ppc_prep;
static nonrev_pre_credential_prepare_t  Alice_alpha_nrpc_prep;
static primary_pre_credential_t         Alice_alpha_ppc;
static nonrev_pre_credential_t          Alice_alpha_nrpc;
static primary_credential_t             Alice_alpha_pc;
static nonrev_credential_t              Alice_alpha_nrc;
int setup_holder_Alice_alpha() {
  mpz_inits(Alice_alpha_holder_id, Alice_alpha_n0, Alice_alpha_v_apos, NULL);
  element_init_Zr(Alice_alpha_s_apos, pairing);

  printf("个人Alice_alpha制作'预凭证准备'\n");
  attr_vec_init(Alice_alpha_Ah, schema_attr_cnt_hidden(schema_employee));
  attr_vec_head(Alice_alpha_Ah)[0].i = 0; // m1 = Link Secret
  mpz_set(attr_vec_head(Alice_alpha_Ah)[0].v, Alice_LinkSecret);
  attr_vec_head(Alice_alpha_Ah)[1].i = 2; // m3
  mpz_set_ui(attr_vec_head(Alice_alpha_Ah)[1].v, 0); // 未使用，设为0
  attr_vec_head(Alice_alpha_Ah)[2].i = 5; // m5 薪水
  mpz_set_ui(attr_vec_head(Alice_alpha_Ah)[2].v, 10000);
  attr_vec_head(Alice_alpha_Ah)[3].i = 6; // m6 入职日期
  mpz_set_ui(attr_vec_head(Alice_alpha_Ah)[3].v, 20200401);

  random_num_bits(Alice_alpha_holder_id, 32);
  random_num_bits(Alice_alpha_n0, 80);
  random_num_exact_bits(Alice_alpha_v_apos, 2128);
  primary_pre_credential_prepare_init(Alice_alpha_ppc_prep, schema_employee);
  primary_pre_credential_prepare_assign(Alice_alpha_ppc_prep,
					gov_pk,
					Alice_alpha_n0,
					Alice_alpha_v_apos,
					Alice_alpha_Ah);

  element_random(Alice_alpha_s_apos);
  nonrev_pre_credential_prepare_init(Alice_alpha_nrpc_prep, pairing);
  nonrev_pre_credential_prepare_assign(Alice_alpha_nrpc_prep, Alice_alpha_s_apos, nr_pk);

  printf("Issuer验证'预凭证准备'\n");
  if (primary_pre_credential_prepare_verify(Alice_alpha_ppc_prep, gov_pk, Alice_alpha_n0)) {
    printf("个人Alice_alpha预凭证准备错误\n");
    return -1;
  }
  printf("个人Alice_alpha'预凭证准备'通过，Issuer制作'预凭证'\n");

  Alice_alpha_Index = next_Index();
  mpz_t index;
  mpz_init_set_ui(index, Alice_alpha_Index);
  attr_vec_init(Alice_alpha_Ak, schema_attr_cnt_known(schema_employee));
  attr_vec_head(Alice_alpha_Ak)[0].i = 1;
  compute_m2(attr_vec_head(Alice_alpha_Ak)[0].v, index, Alice_alpha_holder_id);
  attr_vec_head(Alice_alpha_Ak)[1].i = 3;
  mpz_set_ui(attr_vec_head(Alice_alpha_Ak)[1].v, ALICE_ID); // 个人id
  attr_vec_head(Alice_alpha_Ak)[2].i = 4;
  mpz_set_ui(attr_vec_head(Alice_alpha_Ak)[2].v, ALPHA_ID); // 公司id
  mpz_clear(index);

  primary_pre_credential_init(Alice_alpha_ppc, schema_employee);
  primary_pre_credential_assign(Alice_alpha_ppc,
				gov_pk, gov_sk,
				Alice_alpha_Ak, Alice_alpha_ppc_prep);

  nonrev_pre_credential_init(Alice_alpha_nrpc, pairing);
  nonrev_pre_credential_assign(Alice_alpha_nrpc,
			       attr_vec_head(Alice_alpha_Ak)[0].v,
			       Alice_alpha_Index,
			       nr_pk,
			       nr_sk,
			       acc,
			       acc_pk,
			       acc_sk,
			       Alice_alpha_nrpc_prep);

  primary_credential_init(Alice_alpha_pc, schema_employee);
  primary_credential_assign(Alice_alpha_pc, Alice_alpha_v_apos, Alice_alpha_Ah, Alice_alpha_ppc);
  if (primary_pre_credential_verify(Alice_alpha_ppc, gov_pk,
				    Alice_alpha_ppc_prep->n1,
				    Alice_alpha_pc))
    {
      printf("个人Alice_alpha'预凭证'验证错误\n");
      return -1;
    }
  printf("个人Alice_alpha'预凭证'验证通过，保存凭证\n");
  nonrev_credential_init(Alice_alpha_nrc, pairing);
  nonrev_credential_assign(Alice_alpha_nrc, Alice_alpha_s_apos, Alice_alpha_nrpc);

  return 0;
}

// Alice_beta 相关
static unsigned long Alice_beta_Index;
static mpz_t Alice_beta_holder_id, Alice_beta_n0, Alice_beta_v_apos;
static element_t Alice_beta_s_apos;
static attr_vec_t Alice_beta_Ah, Alice_beta_Ak;
static primary_pre_credential_prepare_t Alice_beta_ppc_prep;
static nonrev_pre_credential_prepare_t  Alice_beta_nrpc_prep;
static primary_pre_credential_t         Alice_beta_ppc;
static nonrev_pre_credential_t          Alice_beta_nrpc;
static primary_credential_t             Alice_beta_pc;
static nonrev_credential_t              Alice_beta_nrc;
int setup_holder_Alice_beta() {
  mpz_inits(Alice_beta_holder_id, Alice_beta_n0, Alice_beta_v_apos, NULL);
  element_init_Zr(Alice_beta_s_apos, pairing);

  printf("个人Alice_beta制作'预凭证准备'\n");
  attr_vec_init(Alice_beta_Ah, schema_attr_cnt_hidden(schema_employee));
  attr_vec_head(Alice_beta_Ah)[0].i = 0; // m1 = Link Secret
  mpz_set(attr_vec_head(Alice_beta_Ah)[0].v, Alice_LinkSecret);
  attr_vec_head(Alice_beta_Ah)[1].i = 2; // m3
  mpz_set_ui(attr_vec_head(Alice_beta_Ah)[1].v, 0); // 未使用，设为0
  attr_vec_head(Alice_beta_Ah)[2].i = 5; // m5 薪水
  mpz_set_ui(attr_vec_head(Alice_beta_Ah)[2].v, 5000);
  attr_vec_head(Alice_beta_Ah)[3].i = 6; // m6 入职日期
  mpz_set_ui(attr_vec_head(Alice_beta_Ah)[3].v, 20200501);

  random_num_bits(Alice_beta_holder_id, 32);
  random_num_bits(Alice_beta_n0, 80);
  random_num_exact_bits(Alice_beta_v_apos, 2128);
  primary_pre_credential_prepare_init(Alice_beta_ppc_prep, schema_employee);
  primary_pre_credential_prepare_assign(Alice_beta_ppc_prep,
					gov_pk,
					Alice_beta_n0,
					Alice_beta_v_apos,
					Alice_beta_Ah);

  element_random(Alice_beta_s_apos);
  nonrev_pre_credential_prepare_init(Alice_beta_nrpc_prep, pairing);
  nonrev_pre_credential_prepare_assign(Alice_beta_nrpc_prep, Alice_beta_s_apos, nr_pk);

  printf("Issuer验证'预凭证准备'\n");
  if (primary_pre_credential_prepare_verify(Alice_beta_ppc_prep, gov_pk, Alice_beta_n0)) {
    printf("个人Alice_beta预凭证准备错误\n");
    return -1;
  }
  printf("个人Alice_beta'预凭证准备'通过，Issuer制作'预凭证'\n");

  Alice_beta_Index = next_Index();
  mpz_t index;
  mpz_init_set_ui(index, Alice_beta_Index);
  attr_vec_init(Alice_beta_Ak, schema_attr_cnt_known(schema_employee));
  attr_vec_head(Alice_beta_Ak)[0].i = 1;
  compute_m2(attr_vec_head(Alice_beta_Ak)[0].v, index, Alice_beta_holder_id);
  attr_vec_head(Alice_beta_Ak)[1].i = 3;
  mpz_set_ui(attr_vec_head(Alice_beta_Ak)[1].v, ALICE_ID); // 个人id
  attr_vec_head(Alice_beta_Ak)[2].i = 4;
  mpz_set_ui(attr_vec_head(Alice_beta_Ak)[2].v, BETA_ID); // 公司id
  mpz_clear(index);

  primary_pre_credential_init(Alice_beta_ppc, schema_employee);
  primary_pre_credential_assign(Alice_beta_ppc,
				gov_pk, gov_sk,
				Alice_beta_Ak, Alice_beta_ppc_prep);

  nonrev_pre_credential_init(Alice_beta_nrpc, pairing);
  nonrev_pre_credential_assign(Alice_beta_nrpc,
			       attr_vec_head(Alice_beta_Ak)[0].v,
			       Alice_beta_Index,
			       nr_pk,
			       nr_sk,
			       acc,
			       acc_pk,
			       acc_sk,
			       Alice_beta_nrpc_prep);

  primary_credential_init(Alice_beta_pc, schema_employee);
  primary_credential_assign(Alice_beta_pc, Alice_beta_v_apos, Alice_beta_Ah, Alice_beta_ppc);
  if (primary_pre_credential_verify(Alice_beta_ppc, gov_pk,
				    Alice_beta_ppc_prep->n1,
				    Alice_beta_pc))
    {
      printf("个人Alice_beta'预凭证'验证错误\n");
      return -1;
    }
  printf("个人Alice_beta'预凭证'验证通过，保存凭证\n");
  nonrev_credential_init(Alice_beta_nrc, pairing);
  nonrev_credential_assign(Alice_beta_nrc, Alice_beta_s_apos, Alice_beta_nrpc);

  return 0;
}

// Bob_alpha 相关
static unsigned long Bob_alpha_Index;
static mpz_t Bob_alpha_holder_id, Bob_alpha_n0, Bob_alpha_v_apos;
static element_t Bob_alpha_s_apos;
static attr_vec_t Bob_alpha_Ah, Bob_alpha_Ak;
static primary_pre_credential_prepare_t Bob_alpha_ppc_prep;
static nonrev_pre_credential_prepare_t  Bob_alpha_nrpc_prep;
static primary_pre_credential_t         Bob_alpha_ppc;
static nonrev_pre_credential_t          Bob_alpha_nrpc;
static primary_credential_t             Bob_alpha_pc;
static nonrev_credential_t              Bob_alpha_nrc;
int setup_holder_Bob_alpha() {
  mpz_inits(Bob_alpha_holder_id, Bob_alpha_n0, Bob_alpha_v_apos, NULL);
  element_init_Zr(Bob_alpha_s_apos, pairing);

  printf("个人Bob_alpha制作'预凭证准备'\n");
  attr_vec_init(Bob_alpha_Ah, schema_attr_cnt_hidden(schema_employee));
  attr_vec_head(Bob_alpha_Ah)[0].i = 0; // m1 = Link Secret
  mpz_set(attr_vec_head(Bob_alpha_Ah)[0].v, Bob_LinkSecret);
  attr_vec_head(Bob_alpha_Ah)[1].i = 2; // m3
  mpz_set_ui(attr_vec_head(Bob_alpha_Ah)[1].v, 0); // 未使用，设为0
  attr_vec_head(Bob_alpha_Ah)[2].i = 5; // m5 薪水
  mpz_set_ui(attr_vec_head(Bob_alpha_Ah)[2].v, 10000);
  attr_vec_head(Bob_alpha_Ah)[3].i = 6; // m6 入职日期
  mpz_set_ui(attr_vec_head(Bob_alpha_Ah)[3].v, 20200401);

  random_num_bits(Bob_alpha_holder_id, 32);
  random_num_bits(Bob_alpha_n0, 80);
  random_num_exact_bits(Bob_alpha_v_apos, 2128);
  primary_pre_credential_prepare_init(Bob_alpha_ppc_prep, schema_employee);
  primary_pre_credential_prepare_assign(Bob_alpha_ppc_prep,
					gov_pk,
					Bob_alpha_n0,
					Bob_alpha_v_apos,
					Bob_alpha_Ah);

  element_random(Bob_alpha_s_apos);
  nonrev_pre_credential_prepare_init(Bob_alpha_nrpc_prep, pairing);
  nonrev_pre_credential_prepare_assign(Bob_alpha_nrpc_prep, Bob_alpha_s_apos, nr_pk);

  printf("Issuer验证'预凭证准备'\n");
  if (primary_pre_credential_prepare_verify(Bob_alpha_ppc_prep, gov_pk, Bob_alpha_n0)) {
    printf("个人Bob_alpha预凭证准备错误\n");
    return -1;
  }
  printf("个人Bob_alpha'预凭证准备'通过，Issuer制作'预凭证'\n");

  Bob_alpha_Index = next_Index();
  mpz_t index;
  mpz_init_set_ui(index, Bob_alpha_Index);
  attr_vec_init(Bob_alpha_Ak, schema_attr_cnt_known(schema_employee));
  attr_vec_head(Bob_alpha_Ak)[0].i = 1;
  compute_m2(attr_vec_head(Bob_alpha_Ak)[0].v, index, Bob_alpha_holder_id);
  attr_vec_head(Bob_alpha_Ak)[1].i = 3;
  mpz_set_ui(attr_vec_head(Bob_alpha_Ak)[1].v, BOB_ID); // 个人id
  attr_vec_head(Bob_alpha_Ak)[2].i = 4;
  mpz_set_ui(attr_vec_head(Bob_alpha_Ak)[2].v, ALPHA_ID); // 公司id
  mpz_clear(index);

  primary_pre_credential_init(Bob_alpha_ppc, schema_employee);
  primary_pre_credential_assign(Bob_alpha_ppc,
				gov_pk, gov_sk,
				Bob_alpha_Ak, Bob_alpha_ppc_prep);

  nonrev_pre_credential_init(Bob_alpha_nrpc, pairing);
  nonrev_pre_credential_assign(Bob_alpha_nrpc,
			       attr_vec_head(Bob_alpha_Ak)[0].v,
			       Bob_alpha_Index,
			       nr_pk,
			       nr_sk,
			       acc,
			       acc_pk,
			       acc_sk,
			       Bob_alpha_nrpc_prep);

  primary_credential_init(Bob_alpha_pc, schema_employee);
  primary_credential_assign(Bob_alpha_pc, Bob_alpha_v_apos, Bob_alpha_Ah, Bob_alpha_ppc);
  if (primary_pre_credential_verify(Bob_alpha_ppc, gov_pk,
				    Bob_alpha_ppc_prep->n1,
				    Bob_alpha_pc))
    {
      printf("个人Bob_alpha'预凭证'验证错误\n");
      return -1;
    }
  printf("个人Bob_alpha'预凭证'验证通过，保存凭证\n");
  nonrev_credential_init(Bob_alpha_nrc, pairing);
  nonrev_credential_assign(Bob_alpha_nrc, Bob_alpha_s_apos, Bob_alpha_nrpc);

  return 0;
}


static mpz_vec_t C, spT, scT;
static mpz_t CH, CH1;
void init_subproof_vec() {
  mpz_vec_init(C);
  mpz_vec_init(spT);
  mpz_vec_init(scT);
  mpz_inits(CH, CH1, NULL);
}

void clear_subproof_vec() {
  mpz_vec_clear(C);
  mpz_vec_clear(spT);
  mpz_vec_clear(scT);
  mpz_clears(CH, CH1, NULL);
}

static attr_vec_t p1_Alice_alpha_Ar;
static attr_vec_t p1_Alice_alpha_m_tildes;
static nonrev_credential_subproof_auxiliary_t p1_Alice_alpha_nrcsp_aux;
static nonrev_credential_subproof_tuple_c_t p1_Alice_alpha_nrcsp_C;
static primary_credential_subproof_auxiliary_t p1_Alice_alpha_pcsp_aux;
static primary_credential_subproof_tuple_c_t p1_Alice_alpha_pcsp_C;
static predicate_t p1_pred1;
static predicate_subproof_auxiliary_t p1_pred1_aux;
static predicate_subproof_tuple_c_t p1_pred1_C;
static predicate_t p1_pred2;
static predicate_subproof_auxiliary_t p1_pred2_aux;
static predicate_subproof_tuple_c_t p1_pred2_C;

static attr_vec_t p1_Alice_beta_Ar;
static attr_vec_t p1_Alice_beta_m_tildes;
static nonrev_credential_subproof_auxiliary_t p1_Alice_beta_nrcsp_aux;
static nonrev_credential_subproof_tuple_c_t p1_Alice_beta_nrcsp_C;
static primary_credential_subproof_auxiliary_t p1_Alice_beta_pcsp_aux;
static primary_credential_subproof_tuple_c_t p1_Alice_beta_pcsp_C;
static predicate_t p1_pred3;
static predicate_subproof_auxiliary_t p1_pred3_aux;
static predicate_subproof_tuple_c_t p1_pred3_C;
static predicate_t p1_pred4;
static predicate_subproof_auxiliary_t p1_pred4_aux;
static predicate_subproof_tuple_c_t p1_pred4_C;

static attr_vec_t p1_Bob_alpha_Ar;
static attr_vec_t p1_Bob_alpha_m_tildes;
static nonrev_credential_subproof_auxiliary_t p1_Bob_alpha_nrcsp_aux;
static nonrev_credential_subproof_tuple_c_t p1_Bob_alpha_nrcsp_C;
static primary_credential_subproof_auxiliary_t p1_Bob_alpha_pcsp_aux;
static primary_credential_subproof_tuple_c_t p1_Bob_alpha_pcsp_C;
static predicate_t p1_pred5;
static predicate_subproof_auxiliary_t p1_pred5_aux;
static predicate_subproof_tuple_c_t p1_pred5_C;
static predicate_t p1_pred6;
static predicate_subproof_auxiliary_t p1_pred6_aux;
static predicate_subproof_tuple_c_t p1_pred6_C;
static predicate_t p1_pred7;
static predicate_subproof_auxiliary_t p1_pred7_aux;
static predicate_subproof_tuple_c_t p1_pred7_C;
void setup_proof1() {
  mpz_t z;
  mpz_init(z);

  // Alice在alpha的员工信息，暴露个人身份id和公司id
  // 不暴露其他五项信息
  attr_vec_init(p1_Alice_alpha_Ar, 2);
  attr_vec_head(p1_Alice_alpha_Ar)[0].i = 3;
  mpz_set(attr_vec_head(p1_Alice_alpha_Ar)[0].v,
	  attr_vec_head(Alice_alpha_pc->Cs)[3].v);
  attr_vec_head(p1_Alice_alpha_Ar)[1].i = 4;
  mpz_set(attr_vec_head(p1_Alice_alpha_Ar)[1].v,
	  attr_vec_head(Alice_alpha_pc->Cs)[4].v);

  attr_vec_init_random(p1_Alice_alpha_m_tildes, 5, 592);
  attr_vec_head(p1_Alice_alpha_m_tildes)[0].i = 0;
  attr_vec_head(p1_Alice_alpha_m_tildes)[1].i = 1;
  attr_vec_head(p1_Alice_alpha_m_tildes)[2].i = 2;
  attr_vec_head(p1_Alice_alpha_m_tildes)[3].i = 5; // 薪资
  attr_vec_head(p1_Alice_alpha_m_tildes)[4].i = 6; // 入职时间

  nonrev_credential_update(Alice_alpha_nrc, acc); // 最新的V和A都在acc里面

  nonrev_credential_subproof_auxiliary_init(p1_Alice_alpha_nrcsp_aux, pairing);
  nonrev_credential_subproof_auxiliary_assign(p1_Alice_alpha_nrcsp_aux,
					      Alice_alpha_nrc);
  nonrev_credential_subproof_tuple_c_init(p1_Alice_alpha_nrcsp_C, pairing);
  nonrev_credential_subproof_tuple_c_assign(p1_Alice_alpha_nrcsp_C, nr_pk,
					    Alice_alpha_nrc,
					    p1_Alice_alpha_nrcsp_aux,
					    acc);
  nonrev_credential_subproof_tuple_c_into_vec(C, p1_Alice_alpha_nrcsp_C);
  nonrev_credential_subproof_dump_t(spT, pairing,
				    nr_pk, acc,
				    p1_Alice_alpha_nrcsp_aux,
				    p1_Alice_alpha_nrcsp_C);

  primary_credential_subproof_auxiliary_init(p1_Alice_alpha_pcsp_aux);
  primary_credential_subproof_auxiliary_assign(p1_Alice_alpha_pcsp_aux,
					       Alice_alpha_pc);
  primary_credential_subproof_tuple_c_init(p1_Alice_alpha_pcsp_C);
  primary_credential_subproof_tuple_c_assign(p1_Alice_alpha_pcsp_C,
					     gov_pk,
					     Alice_alpha_pc,
					     p1_Alice_alpha_pcsp_aux);
  primary_credential_subproof_tuple_c_into_vec(C, p1_Alice_alpha_pcsp_C);
  primary_credential_subproof_dump_t(spT, gov_pk,
				     p1_Alice_alpha_m_tildes,
				     p1_Alice_alpha_pcsp_aux,
				     p1_Alice_alpha_pcsp_C);

  // Alice在beta的员工信息，暴露个人身份id和公司id
  // 不暴露其他五项信息
  attr_vec_init(p1_Alice_beta_Ar, 2);
  attr_vec_head(p1_Alice_beta_Ar)[0].i = 3;
  mpz_set(attr_vec_head(p1_Alice_beta_Ar)[0].v,
	  attr_vec_head(Alice_beta_pc->Cs)[3].v);
  attr_vec_head(p1_Alice_beta_Ar)[1].i = 4;
  mpz_set(attr_vec_head(p1_Alice_beta_Ar)[1].v,
	  attr_vec_head(Alice_beta_pc->Cs)[4].v);

  attr_vec_init_random(p1_Alice_beta_m_tildes, 5, 592);
  attr_vec_head(p1_Alice_beta_m_tildes)[0].i = 0;
  attr_vec_head(p1_Alice_beta_m_tildes)[1].i = 1;
  attr_vec_head(p1_Alice_beta_m_tildes)[2].i = 2;
  attr_vec_head(p1_Alice_beta_m_tildes)[3].i = 5; // 薪资
  attr_vec_head(p1_Alice_beta_m_tildes)[4].i = 6; // 入职时间

  nonrev_credential_update(Alice_beta_nrc, acc); // 最新的V和A都在acc里面

  nonrev_credential_subproof_auxiliary_init(p1_Alice_beta_nrcsp_aux, pairing);
  nonrev_credential_subproof_auxiliary_assign(p1_Alice_beta_nrcsp_aux,
					      Alice_beta_nrc);
  nonrev_credential_subproof_tuple_c_init(p1_Alice_beta_nrcsp_C, pairing);
  nonrev_credential_subproof_tuple_c_assign(p1_Alice_beta_nrcsp_C, nr_pk,
					    Alice_beta_nrc,
					    p1_Alice_beta_nrcsp_aux,
					    acc);
  nonrev_credential_subproof_tuple_c_into_vec(C, p1_Alice_beta_nrcsp_C);
  nonrev_credential_subproof_dump_t(spT, pairing,
				    nr_pk, acc,
				    p1_Alice_beta_nrcsp_aux,
				    p1_Alice_beta_nrcsp_C);

  primary_credential_subproof_auxiliary_init(p1_Alice_beta_pcsp_aux);
  primary_credential_subproof_auxiliary_assign(p1_Alice_beta_pcsp_aux,
					       Alice_beta_pc);
  primary_credential_subproof_tuple_c_init(p1_Alice_beta_pcsp_C);
  primary_credential_subproof_tuple_c_assign(p1_Alice_beta_pcsp_C,
					     gov_pk,
					     Alice_beta_pc,
					     p1_Alice_beta_pcsp_aux);
  primary_credential_subproof_tuple_c_into_vec(C, p1_Alice_beta_pcsp_C);
  primary_credential_subproof_dump_t(spT, gov_pk,
				     p1_Alice_beta_m_tildes,
				     p1_Alice_beta_pcsp_aux,
				     p1_Alice_beta_pcsp_C);

  // Bob在alpha的员工信息，暴露个人身份id和公司id
  // 不暴露其他五项信息
  attr_vec_init(p1_Bob_alpha_Ar, 2);
  attr_vec_head(p1_Bob_alpha_Ar)[0].i = 3;
  mpz_set(attr_vec_head(p1_Bob_alpha_Ar)[0].v,
	  attr_vec_head(Bob_alpha_pc->Cs)[3].v);
  attr_vec_head(p1_Bob_alpha_Ar)[1].i = 4;
  mpz_set(attr_vec_head(p1_Bob_alpha_Ar)[1].v,
	  attr_vec_head(Bob_alpha_pc->Cs)[4].v);

  attr_vec_init_random(p1_Bob_alpha_m_tildes, 5, 592);
  attr_vec_head(p1_Bob_alpha_m_tildes)[0].i = 0;
  attr_vec_head(p1_Bob_alpha_m_tildes)[1].i = 1;
  attr_vec_head(p1_Bob_alpha_m_tildes)[2].i = 2;
  attr_vec_head(p1_Bob_alpha_m_tildes)[3].i = 5; // 薪资
  attr_vec_head(p1_Bob_alpha_m_tildes)[4].i = 6; // 入职时间

  nonrev_credential_update(Bob_alpha_nrc, acc); // 最新的V和A都在acc里面

  nonrev_credential_subproof_auxiliary_init(p1_Bob_alpha_nrcsp_aux, pairing);
  nonrev_credential_subproof_auxiliary_assign(p1_Bob_alpha_nrcsp_aux,
					      Bob_alpha_nrc);
  nonrev_credential_subproof_tuple_c_init(p1_Bob_alpha_nrcsp_C, pairing);
  nonrev_credential_subproof_tuple_c_assign(p1_Bob_alpha_nrcsp_C, nr_pk,
					    Bob_alpha_nrc,
					    p1_Bob_alpha_nrcsp_aux,
					    acc);
  nonrev_credential_subproof_tuple_c_into_vec(C, p1_Bob_alpha_nrcsp_C);
  nonrev_credential_subproof_dump_t(spT, pairing,
				    nr_pk, acc,
				    p1_Bob_alpha_nrcsp_aux,
				    p1_Bob_alpha_nrcsp_C);

  primary_credential_subproof_auxiliary_init(p1_Bob_alpha_pcsp_aux);
  primary_credential_subproof_auxiliary_assign(p1_Bob_alpha_pcsp_aux,
					       Bob_alpha_pc);
  primary_credential_subproof_tuple_c_init(p1_Bob_alpha_pcsp_C);
  primary_credential_subproof_tuple_c_assign(p1_Bob_alpha_pcsp_C,
					     gov_pk,
					     Bob_alpha_pc,
					     p1_Bob_alpha_pcsp_aux);
  primary_credential_subproof_tuple_c_into_vec(C, p1_Bob_alpha_pcsp_C);
  primary_credential_subproof_dump_t(spT, gov_pk,
				     p1_Bob_alpha_m_tildes,
				     p1_Bob_alpha_pcsp_aux,
				     p1_Bob_alpha_pcsp_C);

  // 七个谓词
  mpz_set_ui(z, 9999);
  predicate_init_assign(p1_pred1,
			GREATER_THAN,
			attr_vec_head(Alice_alpha_pc->Cs)[5].v,
			z);

  predicate_subproof_auxiliary_init(p1_pred1_aux);
  predicate_subproof_auxiliary_assign(p1_pred1_aux,
				      p1_pred1,
				      attr_vec_head(p1_Alice_alpha_m_tildes)[3].v);

  predicate_subproof_tuple_c_init(p1_pred1_C);
  predicate_subproof_tuple_c_assign(p1_pred1_C,
				    gov_pk,
				    p1_pred1_aux);
  predicate_subproof_tuple_c_into_vec(C, p1_pred1_C);
  predicate_subproof_dump_t(spT, gov_pk,
			    p1_pred1_aux,
			    p1_pred1_C);

  mpz_set_ui(z, 10001);
  predicate_init_assign(p1_pred2,
			LESS_THAN,
			attr_vec_head(Alice_alpha_pc->Cs)[5].v,
			z);

  predicate_subproof_auxiliary_init(p1_pred2_aux);
  predicate_subproof_auxiliary_assign(p1_pred2_aux,
				      p1_pred2,
				      attr_vec_head(p1_Alice_alpha_m_tildes)[3].v);

  predicate_subproof_tuple_c_init(p1_pred2_C);
  predicate_subproof_tuple_c_assign(p1_pred2_C,
				    gov_pk,
				    p1_pred2_aux);
  predicate_subproof_tuple_c_into_vec(C, p1_pred2_C);
  predicate_subproof_dump_t(spT, gov_pk,
			    p1_pred2_aux,
			    p1_pred2_C);

  mpz_set_ui(z, 5000);
  predicate_init_assign(p1_pred3,
			GREATER_THAN_OR_EQUAL_TO,
			attr_vec_head(Alice_beta_pc->Cs)[5].v,
			z);

  predicate_subproof_auxiliary_init(p1_pred3_aux);
  predicate_subproof_auxiliary_assign(p1_pred3_aux,
				      p1_pred3,
				      attr_vec_head(p1_Alice_beta_m_tildes)[3].v);

  predicate_subproof_tuple_c_init(p1_pred3_C);
  predicate_subproof_tuple_c_assign(p1_pred3_C,
				    gov_pk,
				    p1_pred3_aux);
  predicate_subproof_tuple_c_into_vec(C, p1_pred3_C);
  predicate_subproof_dump_t(spT, gov_pk,
			    p1_pred3_aux,
			    p1_pred3_C);

  mpz_set_ui(z, 5000);
  predicate_init_assign(p1_pred4,
			LESS_THAN_OR_EQUAL_TO,
			attr_vec_head(Alice_beta_pc->Cs)[5].v,
			z);

  predicate_subproof_auxiliary_init(p1_pred4_aux);
  predicate_subproof_auxiliary_assign(p1_pred4_aux,
				      p1_pred4,
				      attr_vec_head(p1_Alice_beta_m_tildes)[3].v);

  predicate_subproof_tuple_c_init(p1_pred4_C);
  predicate_subproof_tuple_c_assign(p1_pred4_C,
				    gov_pk,
				    p1_pred4_aux);
  predicate_subproof_tuple_c_into_vec(C, p1_pred4_C);
  predicate_subproof_dump_t(spT, gov_pk,
			    p1_pred4_aux,
			    p1_pred4_C);

  mpz_set_ui(z, 0); // Bob在alpha有收入
  predicate_init_assign(p1_pred5,
			GREATER_THAN,
			attr_vec_head(Bob_alpha_pc->Cs)[5].v,
			z);

  predicate_subproof_auxiliary_init(p1_pred5_aux);
  predicate_subproof_auxiliary_assign(p1_pred5_aux,
				      p1_pred5,
				      attr_vec_head(p1_Bob_alpha_m_tildes)[3].v);

  predicate_subproof_tuple_c_init(p1_pred5_C);
  predicate_subproof_tuple_c_assign(p1_pred5_C,
				    gov_pk,
				    p1_pred5_aux);
  predicate_subproof_tuple_c_into_vec(C, p1_pred5_C);
  predicate_subproof_dump_t(spT, gov_pk,
			    p1_pred5_aux,
			    p1_pred5_C);

  mpz_set_ui(z, 20200401); // Bob是在2020年四月份入职的
  predicate_init_assign(p1_pred6,
			GREATER_THAN_OR_EQUAL_TO,
			attr_vec_head(Bob_alpha_pc->Cs)[6].v,
			z);

  predicate_subproof_auxiliary_init(p1_pred6_aux);
  predicate_subproof_auxiliary_assign(p1_pred6_aux,
				      p1_pred6,
				      attr_vec_head(p1_Bob_alpha_m_tildes)[4].v);

  predicate_subproof_tuple_c_init(p1_pred6_C);
  predicate_subproof_tuple_c_assign(p1_pred6_C,
				    gov_pk,
				    p1_pred6_aux);
  predicate_subproof_tuple_c_into_vec(C, p1_pred6_C);
  predicate_subproof_dump_t(spT, gov_pk,
			    p1_pred6_aux,
			    p1_pred6_C);

  mpz_set_ui(z, 20200430); // Bob是在2020年四月份入职的
  predicate_init_assign(p1_pred7,
			LESS_THAN_OR_EQUAL_TO,
			attr_vec_head(Bob_alpha_pc->Cs)[6].v,
			z);

  predicate_subproof_auxiliary_init(p1_pred7_aux);
  predicate_subproof_auxiliary_assign(p1_pred7_aux,
				      p1_pred7,
				      attr_vec_head(p1_Bob_alpha_m_tildes)[4].v);

  predicate_subproof_tuple_c_init(p1_pred7_C);
  predicate_subproof_tuple_c_assign(p1_pred7_C,
				    gov_pk,
				    p1_pred7_aux);
  predicate_subproof_tuple_c_into_vec(C, p1_pred7_C);
  predicate_subproof_dump_t(spT, gov_pk,
			    p1_pred7_aux,
			    p1_pred7_C);

  sm3_TCn(CH, spT, C, Alice_alpha_ppc_prep->n1);
  mpz_clear(z);
}

static tuple_x_t p1_Alice_alpha_X;
static primary_credential_subproof_t p1_Alice_alpha_pcsp;
static predicate_subproof_t p1_pred1_sp;
static predicate_subproof_t p1_pred2_sp;

static tuple_x_t p1_Alice_beta_X;
static primary_credential_subproof_t p1_Alice_beta_pcsp;
static predicate_subproof_t p1_pred3_sp;
static predicate_subproof_t p1_pred4_sp;

static tuple_x_t p1_Bob_alpha_X;
static primary_credential_subproof_t p1_Bob_alpha_pcsp;
static predicate_subproof_t p1_pred5_sp;
static predicate_subproof_t p1_pred6_sp;
static predicate_subproof_t p1_pred7_sp;
void finalize_proof1() {
  tuple_x_init(p1_Alice_alpha_X, pairing);
  tuple_x_assign(p1_Alice_alpha_X, CH,
		 attr_vec_head(Alice_alpha_pc->Cs)[1].v,
		 Alice_alpha_nrc,
		 p1_Alice_alpha_nrcsp_aux);

  primary_credential_subproof_init(p1_Alice_alpha_pcsp, 5);
  primary_credential_subproof_assign(p1_Alice_alpha_pcsp,
				     CH,
				     p1_Alice_alpha_m_tildes,
				     Alice_alpha_pc,
				     p1_Alice_alpha_pcsp_aux,
				     p1_Alice_alpha_pcsp_C->A_apos);

  tuple_x_init(p1_Alice_beta_X, pairing);
  tuple_x_assign(p1_Alice_beta_X, CH,
		 attr_vec_head(Alice_beta_pc->Cs)[1].v,
		 Alice_beta_nrc,
		 p1_Alice_beta_nrcsp_aux);

  primary_credential_subproof_init(p1_Alice_beta_pcsp, 5);
  primary_credential_subproof_assign(p1_Alice_beta_pcsp,
				     CH,
				     p1_Alice_beta_m_tildes,
				     Alice_beta_pc,
				     p1_Alice_beta_pcsp_aux,
				     p1_Alice_beta_pcsp_C->A_apos);

  tuple_x_init(p1_Bob_alpha_X, pairing);
  tuple_x_assign(p1_Bob_alpha_X, CH,
		 attr_vec_head(Bob_alpha_pc->Cs)[1].v,
		 Bob_alpha_nrc,
		 p1_Bob_alpha_nrcsp_aux);

  primary_credential_subproof_init(p1_Bob_alpha_pcsp, 5);
  primary_credential_subproof_assign(p1_Bob_alpha_pcsp,
				     CH,
				     p1_Bob_alpha_m_tildes,
				     Bob_alpha_pc,
				     p1_Bob_alpha_pcsp_aux,
				     p1_Bob_alpha_pcsp_C->A_apos);

  predicate_subproof_init(p1_pred1_sp);
  predicate_subproof_assign(p1_pred1_sp, CH, p1_pred1, p1_pred1_aux);
  predicate_subproof_init(p1_pred2_sp);
  predicate_subproof_assign(p1_pred2_sp, CH, p1_pred2, p1_pred2_aux);
  predicate_subproof_init(p1_pred3_sp);
  predicate_subproof_assign(p1_pred3_sp, CH, p1_pred3, p1_pred3_aux);
  predicate_subproof_init(p1_pred4_sp);
  predicate_subproof_assign(p1_pred4_sp, CH, p1_pred4, p1_pred4_aux);
  predicate_subproof_init(p1_pred5_sp);
  predicate_subproof_assign(p1_pred5_sp, CH, p1_pred5, p1_pred5_aux);
  predicate_subproof_init(p1_pred6_sp);
  predicate_subproof_assign(p1_pred6_sp, CH, p1_pred6, p1_pred6_aux);
  predicate_subproof_init(p1_pred7_sp);
  predicate_subproof_assign(p1_pred7_sp, CH, p1_pred7, p1_pred7_aux);
}

void check_proof1() {
  nonrev_credential_subcheck_dump_t(scT, pairing, CH,
				    acc, acc_pk,
				    nr_pk, p1_Alice_alpha_X,
				    p1_Alice_alpha_nrcsp_C);
  primary_credential_subcheck_dump_t(scT, gov_pk, CH,
				     p1_Alice_alpha_Ar,
				     p1_Alice_alpha_pcsp);

  nonrev_credential_subcheck_dump_t(scT, pairing, CH,
				    acc, acc_pk,
				    nr_pk, p1_Alice_beta_X,
				    p1_Alice_beta_nrcsp_C);
  primary_credential_subcheck_dump_t(scT, gov_pk, CH,
				     p1_Alice_beta_Ar,
				     p1_Alice_beta_pcsp);

  nonrev_credential_subcheck_dump_t(scT, pairing, CH,
				    acc, acc_pk,
				    nr_pk, p1_Bob_alpha_X,
				    p1_Bob_alpha_nrcsp_C);
  primary_credential_subcheck_dump_t(scT, gov_pk, CH,
				     p1_Bob_alpha_Ar,
				     p1_Bob_alpha_pcsp);

  predicate_subcheck_dump_t(scT, gov_pk, CH, p1_pred1,
			    p1_pred1_C, p1_pred1_sp);
  predicate_subcheck_dump_t(scT, gov_pk, CH, p1_pred2,
			    p1_pred2_C, p1_pred2_sp);
  predicate_subcheck_dump_t(scT, gov_pk, CH, p1_pred3,
			    p1_pred3_C, p1_pred3_sp);
  predicate_subcheck_dump_t(scT, gov_pk, CH, p1_pred4,
			    p1_pred4_C, p1_pred4_sp);
  predicate_subcheck_dump_t(scT, gov_pk, CH, p1_pred5,
			    p1_pred5_C, p1_pred5_sp);
  predicate_subcheck_dump_t(scT, gov_pk, CH, p1_pred6,
			    p1_pred6_C, p1_pred6_sp);
  predicate_subcheck_dump_t(scT, gov_pk, CH, p1_pred7,
			    p1_pred7_C, p1_pred7_sp);


  sm3_TCn(CH1, scT, C, Alice_alpha_ppc_prep->n1);
}

// company aplha 相关
static unsigned long alpha_Index;
static mpz_t alpha_holder_id, alpha_n0, alpha_v_apos;
static element_t alpha_s_apos;
static attr_vec_t alpha_Ah, alpha_Ak;
static primary_pre_credential_prepare_t alpha_ppc_prep;
static nonrev_pre_credential_prepare_t  alpha_nrpc_prep;
static primary_pre_credential_t         alpha_ppc;
static nonrev_pre_credential_t          alpha_nrpc;
static primary_credential_t             alpha_pc;
static nonrev_credential_t              alpha_nrc;
int setup_holder_alpha() {
  mpz_inits(alpha_holder_id, alpha_n0, alpha_v_apos, NULL);
  element_init_Zr(alpha_s_apos, pairing);

  printf("公司alpha制作'预凭证准备'\n");
  attr_vec_init(alpha_Ah, schema_attr_cnt_hidden(schema_company));
  attr_vec_head(alpha_Ah)[0].i = 0; // m1 = Link Secret
  random_num_bits(attr_vec_head(alpha_Ah)[0].v, 64);
  attr_vec_head(alpha_Ah)[1].i = 2; // m3
  mpz_set_ui(attr_vec_head(alpha_Ah)[1].v, 0); // 未使用，设为0
  attr_vec_head(alpha_Ah)[2].i = 4; // m5 现金
  mpz_set_ui(attr_vec_head(alpha_Ah)[2].v, 190000000);
  attr_vec_head(alpha_Ah)[3].i = 5; // m6 负债
  mpz_set_ui(attr_vec_head(alpha_Ah)[3].v, 0);

  random_num_bits(alpha_holder_id, 32);
  random_num_bits(alpha_n0, 80);
  random_num_exact_bits(alpha_v_apos, 2128);
  primary_pre_credential_prepare_init(alpha_ppc_prep, schema_company);
  primary_pre_credential_prepare_assign(alpha_ppc_prep,
					gov_pk,
					alpha_n0,
					alpha_v_apos,
					alpha_Ah);

  element_random(alpha_s_apos);
  nonrev_pre_credential_prepare_init(alpha_nrpc_prep, pairing);
  nonrev_pre_credential_prepare_assign(alpha_nrpc_prep, alpha_s_apos, nr_pk);

  printf("Issuer验证'预凭证准备'\n");
  if (primary_pre_credential_prepare_verify(alpha_ppc_prep, gov_pk, alpha_n0)) {
    printf("公司alpha预凭证准备错误\n");
    return -1;
  }
  printf("公司alpha'预凭证准备'通过，Issuer制作'预凭证'\n");

  alpha_Index = next_Index();
  mpz_t index;
  mpz_init_set_ui(index, alpha_Index);
  attr_vec_init(alpha_Ak, schema_attr_cnt_known(schema_company));
  attr_vec_head(alpha_Ak)[0].i = 1;
  compute_m2(attr_vec_head(alpha_Ak)[0].v, index, alpha_holder_id);
  attr_vec_head(alpha_Ak)[1].i = 3;
  mpz_set_ui(attr_vec_head(alpha_Ak)[1].v, ALPHA_ID); // 公司id
  mpz_clear(index);

  primary_pre_credential_init(alpha_ppc, schema_company);
  primary_pre_credential_assign(alpha_ppc,
				gov_pk, gov_sk,
				alpha_Ak, alpha_ppc_prep);

  nonrev_pre_credential_init(alpha_nrpc, pairing);
  nonrev_pre_credential_assign(alpha_nrpc,
			       attr_vec_head(alpha_Ak)[0].v,
			       alpha_Index,
			       nr_pk,
			       nr_sk,
			       acc,
			       acc_pk,
			       acc_sk,
			       alpha_nrpc_prep);

  primary_credential_init(alpha_pc, schema_company);
  primary_credential_assign(alpha_pc, alpha_v_apos, alpha_Ah, alpha_ppc);
  if (primary_pre_credential_verify(alpha_ppc, gov_pk,
				    alpha_ppc_prep->n1, alpha_pc)) {
    printf("公司alpha'预凭证'验证错误\n");
    return -1;
  }
  printf("公司alpha'预凭证'验证通过，保存凭证\n");
  nonrev_credential_init(alpha_nrc, pairing);
  nonrev_credential_assign(alpha_nrc, alpha_s_apos, alpha_nrpc);

  return 0;
}

static attr_vec_t p2_alpha_Ar;
static attr_vec_t p2_alpha_m_tildes;
static nonrev_credential_subproof_auxiliary_t p2_alpha_nrcsp_aux;
static nonrev_credential_subproof_tuple_c_t p2_alpha_nrcsp_C;
static primary_credential_subproof_auxiliary_t p2_alpha_pcsp_aux;
static primary_credential_subproof_tuple_c_t p2_alpha_pcsp_C;

static attr_vec_t p2_Alice_alpha_Ar;
static attr_vec_t p2_Alice_alpha_m_tildes;
static nonrev_credential_subproof_auxiliary_t p2_Alice_alpha_nrcsp_aux;
static nonrev_credential_subproof_tuple_c_t p2_Alice_alpha_nrcsp_C;
static primary_credential_subproof_auxiliary_t p2_Alice_alpha_pcsp_aux;
static primary_credential_subproof_tuple_c_t p2_Alice_alpha_pcsp_C;

static predicate_t p2_pred1;
static predicate_subproof_auxiliary_t p2_pred1_aux;
static predicate_subproof_tuple_c_t p2_pred1_C;
static predicate_t p2_pred2;
static predicate_subproof_auxiliary_t p2_pred2_aux;
static predicate_subproof_tuple_c_t p2_pred2_C;
static predicate_t p2_pred3;
static predicate_subproof_auxiliary_t p2_pred3_aux;
static predicate_subproof_tuple_c_t p2_pred3_C;
void setup_proof2() {
  mpz_t z;
  mpz_init(z);
  // alpha的信息，隐藏所有属性
  attr_vec_init(p2_alpha_Ar, 0);
  attr_vec_init_random(p2_alpha_m_tildes, 6, 592);
  attr_vec_head(p2_alpha_m_tildes)[0].i = 0;
  attr_vec_head(p2_alpha_m_tildes)[1].i = 1;
  attr_vec_head(p2_alpha_m_tildes)[2].i = 2;
  attr_vec_head(p2_alpha_m_tildes)[3].i = 3;
  attr_vec_head(p2_alpha_m_tildes)[4].i = 4;
  attr_vec_head(p2_alpha_m_tildes)[5].i = 5;

  nonrev_credential_update(alpha_nrc, acc); // 最新的V和A都在acc里面

  nonrev_credential_subproof_auxiliary_init(p2_alpha_nrcsp_aux, pairing);
  nonrev_credential_subproof_auxiliary_assign(p2_alpha_nrcsp_aux,
					      alpha_nrc);
  nonrev_credential_subproof_tuple_c_init(p2_alpha_nrcsp_C, pairing);
  nonrev_credential_subproof_tuple_c_assign(p2_alpha_nrcsp_C, nr_pk,
					    alpha_nrc,
					    p2_alpha_nrcsp_aux,
					    acc);
  nonrev_credential_subproof_tuple_c_into_vec(C, p2_alpha_nrcsp_C);
  nonrev_credential_subproof_dump_t(spT, pairing,
				    nr_pk, acc,
				    p2_alpha_nrcsp_aux,
				    p2_alpha_nrcsp_C);

  primary_credential_subproof_auxiliary_init(p2_alpha_pcsp_aux);
  primary_credential_subproof_auxiliary_assign(p2_alpha_pcsp_aux,
					       alpha_pc);
  primary_credential_subproof_tuple_c_init(p2_alpha_pcsp_C);
  primary_credential_subproof_tuple_c_assign(p2_alpha_pcsp_C,
					     gov_pk,
					     alpha_pc,
					     p2_alpha_pcsp_aux);
  primary_credential_subproof_tuple_c_into_vec(C, p2_alpha_pcsp_C);
  primary_credential_subproof_dump_t(spT, gov_pk,
				     p2_alpha_m_tildes,
				     p2_alpha_pcsp_aux,
				     p2_alpha_pcsp_C);

  /*
  // Alice 在alpha的信息，隐藏所有属性
  attr_vec_init(p2_Alice_alpha_Ar, 0);
  attr_vec_init_random(p2_Alice_alpha_m_tildes, 7, 592);
  attr_vec_head(p2_Alice_alpha_m_tildes)[0].i = 0;
  attr_vec_head(p2_Alice_alpha_m_tildes)[1].i = 1;
  attr_vec_head(p2_Alice_alpha_m_tildes)[2].i = 2;
  attr_vec_head(p2_Alice_alpha_m_tildes)[3].i = 3;
  attr_vec_head(p2_Alice_alpha_m_tildes)[4].i = 4;
  attr_vec_head(p2_Alice_alpha_m_tildes)[5].i = 5;
  attr_vec_head(p2_Alice_alpha_m_tildes)[6].i = 6;

  // 关联个人和公司
  mpz_set(attr_vec_head(p2_Alice_alpha_m_tildes)[4].v,
	  attr_vec_head(p2_alpha_m_tildes)[3].v);

  nonrev_credential_update(Alice_alpha_nrc, acc); // 最新的V和A都在acc里面

  nonrev_credential_subproof_auxiliary_init(p2_Alice_alpha_nrcsp_aux, pairing);
  nonrev_credential_subproof_auxiliary_assign(p2_Alice_alpha_nrcsp_aux,
					      Alice_alpha_nrc);
  nonrev_credential_subproof_tuple_c_init(p2_Alice_alpha_nrcsp_C, pairing);
  nonrev_credential_subproof_tuple_c_assign(p2_Alice_alpha_nrcsp_C, nr_pk,
					    Alice_alpha_nrc,
					    p2_Alice_alpha_nrcsp_aux,
					    acc);
  nonrev_credential_subproof_tuple_c_into_vec(C, p2_Alice_alpha_nrcsp_C);
  nonrev_credential_subproof_dump_t(spT, pairing,
				    nr_pk, acc,
				    p2_Alice_alpha_nrcsp_aux,
				    p2_Alice_alpha_nrcsp_C);

  primary_credential_subproof_auxiliary_init(p2_Alice_alpha_pcsp_aux);
  primary_credential_subproof_auxiliary_assign(p2_Alice_alpha_pcsp_aux,
					       Alice_alpha_pc);
  primary_credential_subproof_tuple_c_init(p2_Alice_alpha_pcsp_C);
  primary_credential_subproof_tuple_c_assign(p2_Alice_alpha_pcsp_C,
					     gov_pk,
					     Alice_alpha_pc,
					     p2_Alice_alpha_pcsp_aux);
  primary_credential_subproof_tuple_c_into_vec(C, p2_Alice_alpha_pcsp_C);
  primary_credential_subproof_dump_t(spT, gov_pk,
				     p2_Alice_alpha_m_tildes,
				     p2_Alice_alpha_pcsp_aux,
				     p2_Alice_alpha_pcsp_C);

  */

  // 三个谓词
  mpz_set_ui(z, 100000000); // 现金大于1亿
  predicate_init_assign(p2_pred1,
			GREATER_THAN,
			attr_vec_head(alpha_pc->Cs)[4].v,
			z);

  predicate_subproof_auxiliary_init(p2_pred1_aux);
  predicate_subproof_auxiliary_assign(p2_pred1_aux,
				      p2_pred1,
				      attr_vec_head(p2_alpha_m_tildes)[4].v);

  predicate_subproof_tuple_c_init(p2_pred1_C);
  predicate_subproof_tuple_c_assign(p2_pred1_C,
				    gov_pk,
				    p2_pred1_aux);
  predicate_subproof_tuple_c_into_vec(C, p2_pred1_C);
  predicate_subproof_dump_t(spT, gov_pk,
			    p2_pred1_aux,
			    p2_pred1_C);

  mpz_set_ui(z, 10000000); // 负债小于1千万
  predicate_init_assign(p2_pred2,
			LESS_THAN,
			attr_vec_head(alpha_pc->Cs)[5].v,
			z);

  predicate_subproof_auxiliary_init(p2_pred2_aux);
  predicate_subproof_auxiliary_assign(p2_pred2_aux,
				      p2_pred2,
				      attr_vec_head(p2_alpha_m_tildes)[5].v);

  predicate_subproof_tuple_c_init(p2_pred2_C);
  predicate_subproof_tuple_c_assign(p2_pred2_C,
				    gov_pk,
				    p2_pred2_aux);
  predicate_subproof_tuple_c_into_vec(C, p2_pred2_C);
  predicate_subproof_dump_t(spT, gov_pk,
			    p2_pred2_aux,
			    p2_pred2_C);

  /*
  mpz_set_ui(z, 20200501); // 在2020年5月1日前入职
  predicate_init_assign(p2_pred3,
			LESS_THAN,
			attr_vec_head(Alice_alpha_pc->Cs)[6].v,
			z);

  predicate_subproof_auxiliary_init(p2_pred3_aux);
  predicate_subproof_auxiliary_assign(p2_pred3_aux,
				      p2_pred3,
				      attr_vec_head(p2_Alice_alpha_m_tildes)[6].v);

  predicate_subproof_tuple_c_init(p2_pred3_C);
  predicate_subproof_tuple_c_assign(p2_pred3_C,
				    gov_pk,
				    p2_pred3_aux);
  predicate_subproof_tuple_c_into_vec(C, p2_pred3_C);
  predicate_subproof_dump_t(spT, gov_pk,
			    p2_pred3_aux,
			    p2_pred3_C);

  */

  sm3_TCn(CH, spT, C, alpha_ppc_prep->n1);
  mpz_clear(z);
}

static tuple_x_t p2_alpha_X;
static primary_credential_subproof_t p2_alpha_pcsp;
static tuple_x_t p2_Alice_alpha_X;
static primary_credential_subproof_t p2_Alice_alpha_pcsp;

static predicate_subproof_t p2_pred1_sp;
static predicate_subproof_t p2_pred2_sp;
static predicate_subproof_t p2_pred3_sp;
void finalize_proof2() {
  tuple_x_init(p2_alpha_X, pairing);
  tuple_x_assign(p2_alpha_X, CH,
		 attr_vec_head(alpha_pc->Cs)[1].v,
		 alpha_nrc,
		 p2_alpha_nrcsp_aux);

  primary_credential_subproof_init(p2_alpha_pcsp, 6);
  primary_credential_subproof_assign(p2_alpha_pcsp,
				     CH,
				     p2_alpha_m_tildes,
				     alpha_pc,
				     p2_alpha_pcsp_aux,
				     p2_alpha_pcsp_C->A_apos);

  /*
  tuple_x_init(p2_Alice_alpha_X, pairing);
  tuple_x_assign(p2_Alice_alpha_X, CH,
		 attr_vec_head(Alice_alpha_pc->Cs)[1].v,
		 Alice_alpha_nrc,
		 p2_Alice_alpha_nrcsp_aux);

  primary_credential_subproof_init(p2_Alice_alpha_pcsp, 6);
  primary_credential_subproof_assign(p2_Alice_alpha_pcsp,
				     CH,
				     p2_Alice_alpha_m_tildes,
				     Alice_alpha_pc,
				     p2_Alice_alpha_pcsp_aux,
				     p2_Alice_alpha_pcsp_C->A_apos);
  */

  predicate_subproof_init(p2_pred1_sp);
  predicate_subproof_assign(p2_pred1_sp, CH, p2_pred1, p2_pred1_aux);
  predicate_subproof_init(p2_pred2_sp);
  predicate_subproof_assign(p2_pred2_sp, CH, p2_pred2, p2_pred2_aux);
  // predicate_subproof_init(p2_pred3_sp);
  // predicate_subproof_assign(p2_pred3_sp, CH, p2_pred3, p2_pred3_aux);
}

void check_proof2() {
  nonrev_credential_subcheck_dump_t(scT, pairing, CH,
				    acc, acc_pk,
				    nr_pk, p2_alpha_X,
				    p2_alpha_nrcsp_C);
  primary_credential_subcheck_dump_t(scT, gov_pk, CH,
				     p2_alpha_Ar,
				     p2_alpha_pcsp);

  /*
  nonrev_credential_subcheck_dump_t(scT, pairing, CH,
				    acc, acc_pk,
				    nr_pk, p2_Alice_alpha_X,
				    p2_Alice_alpha_nrcsp_C);
  primary_credential_subcheck_dump_t(scT, gov_pk, CH,
				     p2_Alice_alpha_Ar,
				     p2_Alice_alpha_pcsp);
  */

  predicate_subcheck_dump_t(scT, gov_pk, CH, p2_pred1,
			    p2_pred1_C, p2_pred1_sp);
  predicate_subcheck_dump_t(scT, gov_pk, CH, p2_pred2,
			    p2_pred2_C, p2_pred2_sp);
  // predicate_subcheck_dump_t(scT, gov_pk, CH, p2_pred3,
  //			    p2_pred3_C, p2_pred3_sp);

  sm3_TCn(CH1, scT, C, alpha_ppc_prep->n1);
}

void checkCH() {
  gmp_printf("CH : %Zd\nCH1: %Zd\n", CH, CH1);
  if (mpz_cmp(CH, CH1)) {
    printf("size(spT): %d, size(scT): %d\n",
	   mpz_vec_size(spT), mpz_vec_size(scT));

    for (unsigned long i = 0; i < mpz_vec_size(spT); ++i) {
      mpz_ptr t1 = mpz_vec_head(spT) + i;
      mpz_ptr t2 = mpz_vec_head(scT) + i;
      if (!mpz_cmp(t1, t2)) {
	continue;
      }
      gmp_printf("%d:\n%Zd\n%Zd\n", i, t1, t2);
    }
  }
}

int main(int argc, char *argv[]) {
  if (argc < 3) {
    gmp_printf("usage:\n  %s param_file pq_crypto_file\n", argv[0]);
    return -1;
  }

  printf("初始化双线性对数据\n");
  if (pbc_pairing_init_from_path(pairing, argv[1])) {
    gmp_printf("pairing load error.\n");
    return -1;
  }

  // 公司和个人(Holder)，都前去政府(Issuer)寻求背书(Credential)
  printf("Issuer准备密码学工具\n");
  {
    // 自行生成p q等参数很慢，直接读取之前生成的数据
    printf("Issuer Key...\n");
    if (init_issuer_keys(argv[2])) {
      printf("p', q'读取错误.\n");
      return -1;
    }
    gmp_printf("从%s读取：\np': %Zd\nq': %Zd\n", argv[2], p_apos, q_apos);

    printf("Non-revocation Key...\n");
    init_nonrev_keys();

    printf("累加器...\n");
    accumulator_init_assign(acc, acc_sk, acc_pk,
			    pairing, L,
			    g1_gen, g2_gen);
  }
  printf("密码学工具准备完毕\n");

  printf("初始化schema等常量数据\n");
  init_schemas();
  init_assistant_globals();

  printf("为个人Alice和Bob申请凭证\n");
  if (setup_holder_Alice_alpha()) {
    printf("个人Alice在alpha凭证生成错误\n");
    return -1;
  }

  if (setup_holder_Alice_beta()) {
    printf("个人Alice在beta凭证生成错误\n");
    return -1;
  }

  if (setup_holder_Bob_alpha()) {
    printf("个人Bob在alpha凭证生成错误\n");
    return -1;
  }

  // 注意：当前只有Bob的Non-revocation credential中的V和w是最新的
  // 也就是和账本(即这里的acc)中的一致


  /*
  printf("第一个证明\n");
  init_subproof_vec();
  setup_proof1();
  finalize_proof1();
  check_proof1();

  printf("检查第一个证明\n");
  checkCH();
  clear_subproof_vec();
  */

  printf("为公司alpha申请凭证\n");
  if (setup_holder_alpha()) {
    printf("公司alpha凭证生成错误\n");
    return -1;
  }

  printf("第二个证明\n");
  printf("1111111\n");
  init_subproof_vec();
  printf("222222\n");
  setup_proof2();
  printf("33333333\n");
  finalize_proof2();
  printf("44444444444\n");
  check_proof2();

  printf("检查第二个证明\n");
  checkCH();
  clear_subproof_vec();

  printf("另一个Verifier要求第二个证明\n");
  init_subproof_vec();
  setup_proof2();
  finalize_proof2();
  check_proof2();

  printf("另一个Verifier检查第二个证明\n");
  checkCH();
  clear_subproof_vec();

  printf("例子结束，bye!\n");
  return 0;
}
