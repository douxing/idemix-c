# 数据结构和函数

本项目的数据结构使用尽量仿效了GMP库的实现风格，若该数据结构为`xxx`:

- 为其定义结构体`struct xxx_s {...};`
- 为其定义数据类型`typedef xxx_s xxx_t[1];`
- 为其定义指针类型`typedef xxx_s *xxx_ptr;`
- 为其定义构造函数`void xxx_init(xxx_t);`
- 为其定义赋值函数`void xxx_assign(xxx_t);`
- 为其定义析构函数`void xxx_clear(xxx_t);`

所有的数据结构，都必须在使用前通过`*_init`或相关函数初始化，
然后使用`*_assign`函数赋值。
有的数据结构，这两个函数可能有其他变体，或合二为一
（如有的数据结构内部是辅助用的随机数，
这时可使用`*_init_random`函数直接完成初始化和赋值）。
最后通过`*_clear`或相关函数释放资源。

## 数据结构和关联函数

#### bitmap 位图

定义为`mpz_t`的别名，并封装了一些辅助函数:

- void bitmap_setbit(bitmap_t v, mp_bitcnt_t index)：将v的第index位设为1
- void bitmap_clrbit(bitmap_t v, mp_bitcnt_t index)：将v的第index位设为0
- int bitmap_tstbit(const bitmap_t v, mp_bitcnt_t index)：返回v的第index位
- mp_bitcnt_t bitmap_scan0(const bitmap_t v, mp_bitcnt_t cnt)：返回v下一个0的位置，从cnt开始向后遍历
- mp_bitcnt_t bitmap_scan1(const bitmap_t v, mp_bitcnt_t cnt)：返回v下一个1的位置，从cnt开始向后遍历
- mp_bitcnt_t bitmap_cnt0(const bitmap_t v, mp_bitcnt_t end)：计数v中[0, end)区间中的0
- mp_bitcnt_t bitmap_cnt1(const bitmap_t v, mp_bitcnt_t end)：计数v中[0, end)区间中的1

#### mpz_vec mpz的容器结构

``` C
struct mpz_vec_s {
  unsigned long next; // 下一个插入点
  unsigned long cap;  // 当前容器分配的容量
  mpz_ptr v;          // 实际保存位置
};
```

本数据结构是`mpz_t`的顺序容器，只能向后增加`mpz_t`。

- void mpz_vec_append(mpz_vec_t v, const mpz_t val)：在v的最后插入val，若内部容量不足会重新分配容量
- mpz_ptr mpz_vec_head(mpz_vec_t v)：返回v内部容器的头部
- unsigned long mpz_vec_size(mpz_vec_t v)：返回v内部容器现有的数据个数，即next的值

#### attribute 属性

``` C
struct attribute_s {
  unsigned long i; // 属性在schema中对应的下标
  mpz_t v;         // 属性的值
};
```

#### attribute_vec 属性容器

``` C
struct attribute_vec_s {
  unsigned long l; // 属性数量

  attr_ptr attrs;  // 属性数组
};
```

固定长度的容器，长度在初始化时就已确定。另外提供了一些辅助函数：

- void attr_vec_init_random(attr_vec_t av, const unsigned long l, const unsigned long bits): 以长度l初始化av，每个内部属性有bits长
- unsigned long attr_vec_size(attr_vec_t av)：返回av的长度l
- attr_ptr attr_vec_head(attr_vec_t av)：返回av内部属性数组地址
- void attr_vec_set(attr_vec_t dst, attr_vec_t src)：将src深拷贝至dst
- void attr_vec_combine(attr_vec_t dst, attr_vec_t one, attr_vec_t two)：将one，two合并深拷贝至dst，dst中属性的顺序按照one，two中i值的顺序

### accumulator 累加器相关

``` C
struct accumulator_s {
  unsigned long L;  // 累加器的容量
  element_t g;      // G1中的生成元
  element_t g_apos; // G2中的生成元

  element_t *g1_v;  // G1中的元素，长度为2L
  element_t *g2_v;  // G2中的元素, 长度为2L

  bitmap_t V;       // 索引容器
  element_t acc;    // 累加器的值
};
typedef struct accumulator_s *accumulator_ptr;
typedef struct accumulator_s accumulator_t[1];

void accumulator_sk_clear(accumulator_sk_t sk);

struct accumulator_sk_s {
  element_t gamma; // Zr中的元素，对应文档中的私钥gamma
};
typedef struct accumulator_sk_s *accumulator_sk_ptr;
typedef struct accumulator_sk_s accumulator_sk_t[1];

struct accumulator_pk_s {
  element_t z; // GT中的元素，累加器公钥，同时也是其ID
};
typedef struct accumulator_pk_s *accumulator_pk_ptr;
typedef struct accumulator_pk_s accumulator_pk_t[1];

void accumulator_pk_clear(accumulator_pk_t pk);

void accumulator_init_assign
(accumulator_t acc,   // OUT
 accumulator_sk_t sk, // OUT
 accumulator_pk_t pk, // OUT
 pairing_t pairing,
 unsigned long L,
 element_t g,
 element_t _g_apos);

```

**注意**：因为累加器和其公私钥的高度关联，
其共用同一个构造函数`accumulator_init_assign`。

### issuer_key issuer的公私钥

``` C
struct issuer_secret_key_s {
  mpz_t p_apos;
  mpz_t q_apos;
  mpz_t p;
  mpz_t q;
  mpz_t xZ;
  unsigned long xR_c;
  mpz_ptr xR_v;
};
typedef struct issuer_secret_key_s *issuer_sk_ptr;
typedef struct issuer_secret_key_s issuer_sk_t[1];

struct issuer_public_key_s {
  mpz_t n;
  mpz_t S;
  mpz_t Z;
  unsigned long R_c;
  mpz_ptr R_v;
};
typedef struct issuer_public_key_s *issuer_pk_ptr;
typedef struct issuer_public_key_s issuer_pk_t[1];

void issuer_keys_init_random(issuer_sk_t sk,
			     issuer_pk_t pk,
			     const unsigned long L);
void issuer_keys_init_assign(issuer_sk_t sk,
			     issuer_pk_t pk,
			     const unsigned long L,
			     const mpz_t p_apos,
			     const mpz_t q_apos);
```

按照文档实现的Issuer的公私钥，有两种初始化方式，
一种是自动生成p'和q'(issuer_keys_init_random)，
另一种是对其赋值(issuer_keys_init_assign)。
之后随机生成私钥中的xZ和xRi，并初始化公钥中的Z和Ri数据。

### nonrev_key non-revocation 公私钥

``` C
struct nonrev_secret_key_s {
  element_t sk; // in Zr
  element_t x;  // in Zr
};
typedef struct nonrev_secret_key_s *nonrev_sk_ptr;
typedef struct nonrev_secret_key_s nonrev_sk_t[1];

struct nonrev_public_key_s {
  // in G1
  element_t h;
  element_t h0;
  element_t h1;
  element_t h2;
  element_t h_tilde;

  // in G2
  element_t u;
  element_t h_caret;

  // in Zr
  element_t pk;
  element_t y;
};
typedef struct nonrev_public_key_s *nonrev_pk_ptr;
typedef struct nonrev_public_key_s nonrev_pk_t[1];

void nonrev_keys_init_assign(nonrev_sk_t sk, // OUTPUT
                             nonrev_pk_t pk, // OUTPUT
                             pairing_t pairing,
                             element_t g1_gen,
                             element_t _g2_gen);
```

完全按照文档实现，使用者一般不需要了解结构体内部数据。

#### schema schema的实现

``` C
struct schema_s {
  unsigned long l;
  bitmap_t map;
};
typedef struct schema_s *schema_ptr;
typedef struct schema_s schema_t[1];
```

schema数据结构用于保存相对下标位置的属性是否隐藏。

- int schema_attr_is_hidden(schema_t s, unsigned long i)：s第i个属性是否隐藏
- void schema_attr_set_hidden(schema_t s, unsigned long i)：设置s第i个属性为隐藏
- unsigned long schema_attr_cnt_hidden(schema_t s)：返回s中隐藏属性的个数
- void schema_attr_set_known(schema_t s, unsigned long i)：设置s中第i个属性为公开
- void schema_attr_set_revealed(schema_t s, unsigned long i)：设置s中第i个属性为公开
- unsigned long schema_attr_cnt_known(schema_t s)：返回s中公开属性的个数
- unsigned long schema_attr_cnt_revealed(schema_t s)：返回s中公开属性的个数

### primary credential 相关

``` C
struct primary_pre_credential_prepare_s {
  mpz_t U;
  mpz_t c;
  mpz_t v_apos_caret;

  // contains hidden mi_caret
  attr_vec_t m_carets;

  mpz_t n1;
};
typedef struct primary_pre_credential_prepare_s \
               *primary_pre_credential_prepare_ptr;
typedef struct primary_pre_credential_prepare_s \
               primary_pre_credential_prepare_t[1];

void primary_pre_credential_prepare_init
(primary_pre_credential_prepare_t ppc_prep,
 schema_t s);

void primary_pre_credential_prepare_clear
(primary_pre_credential_prepare_t ppc_prep);

// 赋值primary_pre_credential_prepare
void primary_pre_credential_prepare_assign
(primary_pre_credential_prepare_t ppc_prep,
 issuer_pk_t pk, // Issuer的公钥
 mpz_t n0,       // 根据文档，Holder和Issuer有相同的n0值
 mpz_t v_apos,   // v'
 attr_vec_t Ah); // 由Holder设置

int primary_pre_credential_prepare_verify
(primary_pre_credential_prepare_t ppc_prep,
 issuer_pk_t pk,
 mpz_t n0);

struct primary_pre_credential_s {
  attr_vec_t Ak; // only contains known mi

  mpz_t A;
  mpz_t e;
  mpz_t v_apos_apos;
  mpz_t s_e;
  mpz_t c_apos;
};
typedef struct primary_pre_credential_s \
               *primary_pre_credential_ptr;
typedef struct primary_pre_credential_s \
               primary_pre_credential_t[1];

void primary_pre_credential_init
(primary_pre_credential_t ppc,
 schema_t s);

void primary_pre_credential_clear
(primary_pre_credential_t ppc);

void primary_pre_credential_assign
(primary_pre_credential_t ppc,
 issuer_pk_t pk,
 issuer_sk_t sk,
 attr_vec_t Ak,
 primary_pre_credential_prepare_t ppc_prep);

struct primary_credential_s {
  attr_vec_t Cs; // 包括所有的属性
  
  mpz_t e;
  mpz_t A;
  mpz_t v;
};
typedef struct primary_credential_s *primary_credential_ptr;
typedef struct primary_credential_s primary_credential_t[1];

void primary_credential_init
(primary_credential_t pc,
 schema_t s); // l = |Cs| in the schema

void primary_credential_clear
(primary_credential_t pr);

void primary_credential_assign
(primary_credential_t pr,
 mpz_t v_apos,
 attr_vec_t Ah,                 // Cs中隐藏属性来源
 primary_pre_credential_t ppc); // Cs中公开属性来源

int primary_pre_credential_verify
(primary_pre_credential_t ppc,
 issuer_pk_t pk,
 mpz_t n1,
 primary_credential_t pc); // 使用primary_credential验证
```

根据文档第五章，主证书(primary credential)的生成流程实现：

1. Holder生成primary_pre_credential_prepare，并发送给Issuer
2. Issuer通过primary_pre_credential_prepare_verify检查primary_pre_credential_prepare，并通过Issuer生成primary_pre_credential，发送给Holder
3. Holder生成primary_credential，然后通过primary_pre_credential_prepare函数检查primary_pre_credential数据结构，若返回成功，则将primary_credential保存，这里因为检查函数需要用到primary_credential，所以顺序颠倒了

以上步骤中，后面的数据结构的构建，都需要前面的数据结构。

### non-revocation credential 相关

``` C
struct nonrev_pre_credential_prepare_s {
  element_t U; // in G1
};
typedef struct nonrev_pre_credential_prepare_s \
               *nonrev_pre_credential_prepare_ptr;
typedef struct nonrev_pre_credential_prepare_s \
               nonrev_pre_credential_prepare_t[1];

void nonrev_pre_credential_prepare_init
(nonrev_pre_credential_prepare_t nrpc_prep, // OUT
 pairing_t pairing);

void nonrev_pre_credential_prepare_clear
(nonrev_pre_credential_prepare_t nrpc_prep);

// 5.2 Holder prepares for non-revocation credential:
void nonrev_pre_credential_prepare_assign
(nonrev_pre_credential_prepare_t nrpc_prep,
 element_t s_apos,
 nonrev_pk_t pk);

struct nonrev_pre_credential_s {
  element_t IA;          // IA = z = IDa in GT
  element_t sigma;       // in G1
  element_t c;           // in Zr
  element_t s_apos_apos; // in Zr

  witness_t wit_i;

  element_t g_i;         // in G1
  element_t g_apos_i;    // in G2
  unsigned long i;
};
typedef struct nonrev_pre_credential_s \
               *nonrev_pre_credential_ptr;
typedef struct nonrev_pre_credential_s \
               nonrev_pre_credential_t[1];

void nonrev_pre_credential_init(nonrev_pre_credential_t nrpc, // OUT
                                pairing_t pairing);

void nonrev_pre_credential_clear
(nonrev_pre_credential_t nrpc); // OUT

void nonrev_pre_credential_assign
(nonrev_pre_credential_t nrpc,
 mpz_t m2,               // 由辅助函数compute_m2算出
 unsigned long i,
 nonrev_pk_t pk,
 nonrev_sk_t sk,
 accumulator_t acc,
 accumulator_pk_t acc_pk,
 accumulator_sk_t acc_sk,
 nonrev_pre_credential_prepare_t nrpc_prep);

int nonrev_pre_credential_verify
(const nonrev_pre_credential_t nrpc,
 const mpz_t v_apos);

struct nonrev_credential_s {
  element_t IA;       // IA = z = IDa in GT
  element_t sigma;    // in G1
  element_t c;        // in Zr
  element_t s;        // in Zr
  
  witness_t wit_i;

  element_t g_i;      // in G1
  element_t g_apos_i; // in G2
  unsigned long i;
};
typedef struct nonrev_credential_s *nonrev_credential_ptr;
typedef struct nonrev_credential_s nonrev_credential_t[1];

void nonrev_credential_init(nonrev_credential_t nrc, pairing_t pairing);
void nonrev_credential_clear(nonrev_credential_t nrc);

void nonrev_credential_assign
(nonrev_credential_t nrc,
 element_t s_apos,
 nonrev_pre_credential_t nrpc);
```

根据文档第五章，non-revocation credential的生成流程实现：

1. Holder生成nonrev_pre_credential_prepare，并发送给Issuer
2. Issuer生成nonrev_pre_credential，发送给Holder
3. Holder生成nonrev_credential

以上步骤中，后面的数据结构的构建，都需要前面的数据结构。

包含的witness数据结构为：

#### witness

``` C
struct witness_s {
  element_t sigma_i; // in G2
  element_t u_i;     // in G2
  element_t g_i;     // in G1
  element_t w;       // in G2
  bitmap_t V;
};
```

### 证明预备相关

non-revocation credential、primary credential和predicate的的证明预备，
需要用到三种数据结构。

1. 辅助数据结构(*_auxiliary)，主要包含各种随机函数
2. 元组C相关数据结构(*_tuple_c)，包含和元组C相关的所有参数
3. 子证明本身（其中non-revocation的子证明，参照文档命名为tuple_x）

在使用时，按照文档：

1. 准备好需要的数据
2. 初始化并随机赋值辅助数据结构
3. 初始化并赋值元组C相关的数据结构，并导入元组C相关的数组
4. 计算元组T相关的数据并导入元组T相关的数组
5. 完成子证明的初始化和赋值

#### non-revocation subproof辅助数据结构

``` C
struct nonrev_credential_subproof_auxiliary_s {
  // page 7 - 5. Select aux ... mod q in Zr
  element_t rho;
  element_t rho_apos;
  element_t r;
  element_t r_apos;
  element_t r_apos2;
  element_t r_apos3;
  element_t o;
  element_t o_apos;

  // page 7 - 7 Compute m,t,m',t' Eq. (26) (27)
  element_t m;      // in Zr
  element_t t;      // in Zr
  element_t m_apos; // in Zr
  element_t t_apos; // in Zr

  // page 7 - 8. Generate aux ... mod q in Zr
  element_t rho_tilde;
  element_t o_tilde;
  element_t o_apos_tilde;
  element_t c_tilde;
  element_t m_tilde;
  element_t m_apos_tilde;
  element_t t_tilde;
  element_t t_apos_tilde;
  element_t m2_tilde;
  element_t s_tilde;
  element_t r_tilde;
  element_t r_apos_tilde;
  element_t r_apos2_tilde;
  element_t r_apos3_tilde;
};
typedef struct nonrev_credential_subproof_auxiliary_s \
               *nonrev_credential_subproof_auxiliary_ptr;
typedef struct nonrev_credential_subproof_auxiliary_s \
               nonrev_credential_subproof_auxiliary_t[1];

void nonrev_credential_subproof_auxiliary_init
(nonrev_credential_subproof_auxiliary_t nrcspa,
 pairing_t pairing);

void nonrev_credential_subproof_auxiliary_clear
(nonrev_credential_subproof_auxiliary_t nrcspa);

void nonrev_credential_subproof_auxiliary_assign
(nonrev_credential_subproof_auxiliary_t nrcspa,
 nonrev_credential_t nrc);
```

`void nonrev_credential_subproof_auxiliary_assign`需要用到
`nonrev_credential`中的`c`。

#### non-revocation subproof的C元组

``` C
struct nonrev_credential_subproof_tuple_c_s {
  // page 7 Eq. (22)~(25), will be added to C
  element_t E; // in G1
  element_t D; // in G1
  element_t A; // in G1
  element_t G; // in G1
  element_t W; // in G2
  element_t S; // in G2
  element_t U; // in G2
};
typedef struct nonrev_credential_subproof_tuple_c_s \
               *nonrev_credential_subproof_tuple_c_ptr;
typedef struct nonrev_credential_subproof_tuple_c_s \
               nonrev_credential_subproof_tuple_c_t[1];

void nonrev_credential_subproof_tuple_c_init
(nonrev_credential_subproof_tuple_c_t C,
 pairing_t pairing);

void nonrev_credential_subproof_tuple_c_clear
(nonrev_credential_subproof_tuple_c_t C);

void nonrev_credential_subproof_tuple_c_assign
(nonrev_credential_subproof_tuple_c_t C,
 nonrev_pk_t pk,
 nonrev_credential_t nrc,
 nonrev_credential_subproof_auxiliary_t nrcspa,
 accumulator_t acc);

void nonrev_credential_subproof_tuple_c_into_vec
(mpz_vec_t v,
 nonrev_credential_subproof_tuple_c_t C);
```

non-revocation credential元组C的赋值需要用到non-revocation公钥，
non-revocation本身，non-revocation辅助类和累加器。

`nonrev_credential_subproof_tuple_c_into_vec`是用来加入元组C数组，
在最后参与sm3运算使用。

#### non-revocation subproof的T元组

元组T不需要数据结构，算出之后直接导出即可

``` C
void nonrev_credential_subproof_dump_t
(mpz_vec_t T,
 pairing_t pairing,
 nonrev_pk_t pk,
 accumulator_t acc,
 nonrev_credential_subproof_auxiliary_t nrcspa,
 nonrev_credential_subproof_tuple_c_t C);
```

直接调用`nonrev_credential_subproof_dump_t`以导出元组T数组。

#### non-revocation subproof

**注意**：遵循文档中的名称，该数据结构叫做tuple_x

``` C
struct tuple_x_s {
  element_t rho_caret;
  element_t o_caret;
  element_t c_caret;
  element_t o_apos_caret;
  element_t m_caret;
  element_t m_apos_caret;
  element_t t_caret;
  element_t t_apos_caret;
  element_t m2_caret;
  element_t s_caret;
  element_t r_caret;
  element_t r_apos_caret;
  element_t r_apos2_caret;
  element_t r_apos3_caret;
};
typedef struct tuple_x_s *tuple_x_ptr;
typedef struct tuple_x_s tuple_x_t[1];

void tuple_x_init
(tuple_x_t X,
 pairing_t pairing);

void tuple_x_clear(tuple_x_t X);


void tuple_x_assign
(tuple_x_t X,
 mpz_t CH,
 mpz_t m2,
 nonrev_credential_t nrc,
 nonrev_credential_subproof_auxiliary_t nrcspa);

void tuple_x_into_vec(mpz_vec_t v, tuple_x_t X);
```

使用`tuple_x_into_vec`函数将元组X中的值导入X数组。

#### primary subproof 的辅助数据结构

``` C
struct primary_credential_subproof_auxiliary_s {
  mpz_t r;       // 2128 bits

  mpz_t v_apos;  // v - e*r Eq. (33)
  mpz_t e_apos;  // e - 2^596
  mpz_t v_tilde; // 3060 bits
  mpz_t e_tilde; // 456  bits
};
typedef struct primary_credential_subproof_auxiliary_s \
               *primary_credential_subproof_auxiliary_ptr;
typedef struct primary_credential_subproof_auxiliary_s \
               primary_credential_subproof_auxiliary_t[1];

void primary_credential_subproof_auxiliary_init
(primary_credential_subproof_auxiliary_t aux);

void primary_credential_subproof_auxiliary_clear
(primary_credential_subproof_auxiliary_t aux);

void primary_credential_subproof_auxiliary_assign
(primary_credential_subproof_auxiliary_t pcspa,
 primary_credential_t pc);
```

#### primary subproof 的元组C

``` C
struct primary_credential_subproof_tuple_c_s {
  mpz_t A_apos; // Eq. (33) A' = AS^r (mod n)
};
typedef struct primary_credential_subproof_tuple_c_s \
               *primary_credential_subproof_tuple_c_ptr;
typedef struct primary_credential_subproof_tuple_c_s \
               primary_credential_subproof_tuple_c_t[1];

void primary_credential_subproof_tuple_c_init
(primary_credential_subproof_tuple_c_t C);

void primary_credential_subproof_tuple_c_clear
(primary_credential_subproof_tuple_c_t C);

void primary_credential_subproof_tuple_c_assign
(primary_credential_subproof_tuple_c_t C,
 issuer_pk_t pk,
 primary_credential_t pc,
 primary_credential_subproof_auxiliary_t pcspa);

void primary_credential_subproof_tuple_c_into_vec
(mpz_vec_t v, // OUT
 primary_credential_subproof_tuple_c_t C);
```

#### primary subproof 的元组T

元组T不需要数据结构，算出之后直接导出即可

``` C
void primary_credential_subproof_dump_t
(mpz_vec_t T,
 issuer_pk_t pk,
 attr_vec_t m_tildes,  // intersection(Cs, Ar)
 primary_credential_subproof_auxiliary_t pcspa,
 primary_credential_subproof_tuple_c_t C);
```

直接调用`primary_credential_subproof_dump_t`以导出元组T数组。

#### primary subproof

``` C
struct primary_credential_subproof_s {
  mpz_t e_caret;
  mpz_t v_caret;

  attr_vec_t m_carets; // {mj_caret} = Intersection(Cs, Ar_bar)

  mpz_t A_apos; // set directly from primary_credential_subproof_prepare_s->A_apos
};
typedef struct primary_credential_subproof_s *primary_credential_subproof_ptr;
typedef struct primary_credential_subproof_s primary_credential_subproof_t[1];

void primary_credential_subproof_init
(primary_credential_subproof_t p,
 const unsigned long l);

void primary_credential_subproof_clear(primary_credential_subproof_t p);

void primary_credential_subproof_assign
(primary_credential_subproof_t pcsp,
 mpz_t CH,            // result of Eq. (41)
 attr_vec_t m_tildes, // Intersection(Cs, Ar_bar)
 primary_credential_t pc,
 primary_credential_subproof_auxiliary_t pcspa,
 mpz_t A_apos); // from tuple C
```

#### predicate subproof 的辅助数据结构

``` C
struct predicate_subproof_auxiliary_s {
  mpz_t delta;         // 由op决定, delta = u1^2 + u2^2 + u3^2 + u4^2
  mpz_t u[4];          // 7.2.(Validity Proof).4.2

  mpz_t a;             // 1 or -1

  mpz_t m_tilde;       // 7.2.(Validity Proof).1

  mpz_t r_delta;       // 7.2.(Validity Proof).4.3
  mpz_t r[4];          // 7.2.(Validity Proof).4.3

  mpz_t u_tilde[4];    // 7.2.(Validity Proof).4.5

  mpz_t r_delta_tilde; // 7.2.(Validity Proof).4.6
  mpz_t r_tilde[4];    // 7.2.(Validity Proof).4.6

  mpz_t alpha_tilde;   // 7.2.(Validity Proof).4.7
};
typedef struct predicate_subproof_auxiliary_s \
               *predicate_subproof_auxiliary_ptr;
typedef struct predicate_subproof_auxiliary_s \
               predicate_subproof_auxiliary_t[1];

void predicate_subproof_auxiliary_init
(predicate_subproof_auxiliary_t pspa);

void predicate_subproof_auxiliary_clear
(predicate_subproof_auxiliary_t pspa);

void predicate_subproof_auxiliary_assign
(predicate_subproof_auxiliary_t pspa,
 predicate_t p,
 mpz_t m_tilde); // 属性对应的随机数
```

#### predicate subproof 的元组C

``` C
struct predicate_subproof_tuple_c_s {
  mpz_t T[4];    // Eq. (36)
  mpz_t T_delta; // Eq. (37)
};
typedef struct predicate_subproof_tuple_c_s *predicate_subproof_tuple_c_ptr;
typedef struct predicate_subproof_tuple_c_s predicate_subproof_tuple_c_t[1];

void predicate_subproof_tuple_c_init
(predicate_subproof_tuple_c_t C);

void predicate_subproof_tuple_c_clear
(predicate_subproof_tuple_c_t C);

void predicate_subproof_tuple_c_assign
(predicate_subproof_tuple_c_t C,
 issuer_pk_t pk,
 predicate_subproof_auxiliary_t pspa);

void predicate_subproof_tuple_c_into_vec
(mpz_vec_t v,
 predicate_subproof_tuple_c_t C);
```

#### predicate subproof 的元组T

``` C
void predicate_subproof_dump_t
(mpz_vec_t T,
 issuer_pk_t pk,
 predicate_subproof_auxiliary_t pspa,
 predicate_subproof_tuple_c_t C);
```

#### predicate subproof

``` C
struct predicate_subproof_s {
  mpz_t u_caret[4];   // Eq. (45)
  mpz_t r_caret[4];   // Eq. (46)
  mpz_t r_delta_caret; // Eq. (47)
  mpz_t alpha_caret;   // Eq. (48)
  mpz_t m_caret;
};
typedef struct predicate_subproof_s *predicate_subproof_ptr;
typedef struct predicate_subproof_s predicate_subproof_t[1];

void predicate_subproof_init
(predicate_subproof_t psp);

void predicate_subproof_clear
(predicate_subproof_t psp);

void predicate_subproof_assign
(predicate_subproof_t psp,
 mpz_t CH,
 predicate_t p,
 predicate_subproof_auxiliary_t pspa);
```

### 证明验证相关

根据文档7.2.3，验证方Verifier需要接受(CH, {X}, {PrC}, {PrP}, C)的数据。
然后生成T数组相关的数据，最后将生成的hash值和CH比较。若相同则通过验证。

#### non-revocation subcheck 元组T

``` C
void nonrev_credential_subcheck_dump_t
(mpz_vec_t T,
 pairing_t pairing,
 mpz_t CH,
 accumulator_t acc,
 accumulator_pk_t accpk,
 nonrev_pk_t pk,
 tuple_x_t X, // 事实上的 nonrev_credential_subproof
 nonrev_credential_subproof_tuple_c_t C);
```

#### primary subcheck 元组T

``` C
void primary_credential_subcheck_dump_t
(mpz_vec_t T,
 issuer_pk_t pk,
 mpz_t CH,
 attr_vec_t v,
 primary_credential_subproof_t pcsp);
```

#### predicate subcheck 元组T

``` C
void predicate_subproof_dump_t
(mpz_vec_t T,
 issuer_pk_t pk,
 predicate_subproof_auxiliary_t pspa,
 predicate_subproof_tuple_c_t C);
```

## 辅助函数

### 随机（质）数相关

宏定义`#define REPS_VAL 15`

该宏定义影响所有带随机质数的函数，其取值范围为15~50，
具体请查看[GMP库的相应文档](https://gmplib.org/manual/Number-Theoretic-Functions.html#Number-Theoretic-Functions)。

``` C
void random_num_bits(mpz_t num, unsigned long bits);
```

随机[0, 2^bits-1]区间之内的数。

``` C
void random_num_exact_bits(mpz_t num, unsigned long bits);
```

随机[2^(bits-1), 2^bits-1]区间之内的数。

``` C
void random_range(mpz_t num, mpz_t min, mpz_t max);
```

随机[min, max-1]区间之内的数。

``` C
void random_prime_range(mpz_t num, mpz_t min, mpz_t max);
```

随机[0, 2^bits-1]区间之内的质数。

``` C
void random_prime_exact_bits(mpz_t prime, unsigned long bits);
```

随机[2^(bits-1), 2^bits-1]区间之内的质数。

随机[min, max-1]区间之内的质数。

``` C
void random_prime_bits(mpz_t prime, unsigned long bits);
```

### PBC库相关

``` C
static inline int pbc_pairing_init_from_path
(pairing_t pairing,
 char *path);
```

从path读取参数并放入pairing。


``` C
static inline void pbc_element_to_mpz(mpz_t z, element_t e);
```

将PBC库中的element元素转化为GMP库中的mpz_t元素。
**注意**：PBC库中有转化函数，但是有一些问题，具体可以查看PBC库的源代码。

### 四平方和相关

``` C
#define FOUR 4

void four_squares_init(mpz_t fours[FOUR]);
void four_squares_clear(mpz_t fours[FOUR]);

int special_case_p(mpz_t fours[FOUR], mpz_t input);
int iunit(mpz_t iu, const mpz_t p);
int decompose_prime(mpz_t a, mpz_t b, const mpz_t n);

int decompose(mpz_t fours[FOUR], mpz_t n);
```

其中four_squares_init和four_squares_clear函数不言自明。
用户只需要使用decompose函数即可，该函数将n分解成4个整数，这四个整数的平方和等于n。
special_case_p，iunit函数和decompose_prime函数是内部使用函数。

**注意**：进一步了解四平方数内部原理，访问[该地址](https://schorn.ch/lagrange.html)。

### SM3相关

``` C
typedef struct {
	uint32_t digest[8];
	int nblocks;
	unsigned char block[64];
	int num;
} sm3_ctx_t;

void sm3_init(sm3_ctx_t *ctx);
void sm3_update(sm3_ctx_t *ctx, const unsigned char* data, size_t data_len);
void sm3_final(sm3_ctx_t *ctx, unsigned char digest[SM3_DIGEST_LENGTH]);
void sm3(const unsigned char *data, size_t datalen, unsigned char digest[SM3_DIGEST_LENGTH]);

void sm3_mpzs(mpz_ptr dest, mpz_ptr n, ...);
void sm3_TCn(mpz_ptr dst, mpz_vec_t T, mpz_vec_t C, mpz_t n1);
```

sm3的生成，首先使用init函数初始化ctx，然后通过update，不断加入新的数据，
最后通过final函数生成sm3的值。sm3函数是辅助函数，可以直接使用该函数生成sm3数据。
其中sm3_mpzs将输入和输出以mpz_t的形式操作，可以处理不定长度的输入，
但注意要以NULL作为其最后一个输入。
sm3_TCn用以计算T数组，C数组和n的集合。用以计算算法中的特定hash值。





















