# 如何使用

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

接下来讲述本库的接口使用，
C语言都是独立的数据结构和函数，没有明确的对象概念，
因此它们之间相对独立和分散，为了让用户更好地理解和使用，
特意增加了本章内容，
可以结合文档Anonymouse credentials with type-3 revocation一起看。
接下来以example/simple.c作为例子，详细讲解接口的使用方式。

## 简单例子 simple.c 详解

### 0. 基础知识

gnu mp库中提供的函数和数据结构包括：
- gmp_printf函数
- mpz_t和mpz_开头的所有函数

pbc库中提供的函数和数据结构包括：
- element_printf函数
- element_t和elmeent_开头的所有函数

请前去相应的库查询其用法。

### 1. 初始化双线性对数据结构，pairing_t

程序要求在argv[1]中传入a.param文件，这个文件包括了曲线需要的参数。
使用本库提供的`pbc_pairing_init_from_path`辅助函数完成pairing数据结构的初始化。

``` C
  pairing_t pairing;
  if (pbc_pairing_init_from_path(pairing, argv[1])) {
	gmp_printf("pairing load error.\n");
	return -1;
  }
```

### 2. Schema 创建 - 4.1 Attributes

首先要创建相应的schema，根据文档，m1和m3是隐藏的，m2是公开的。
从m4开始是用户自定义属性，可以任意设置为隐藏(hidden)还是公开(known)。
这里的隐藏和公开表示的是Issuer和Holder的关系。
若属性为隐藏，则由Holder自己设置，
若属性为公开，则由Issuer设置，并会在证书生成过程种发送给Holder。
因此，所有的属性，对于Holder而言都是已知的。
对于Issuer而言，只知道公开的属性。

**注意**：本库并不强制属性的公开还是隐藏，需要用户自行设置m1和m3为隐藏。

**注意**：这里的公开和隐藏和7.1中的暴露和未知是两个概念。

在simple.c中，除了m1和m3为隐藏属性，其他两个属性都是公开的，由Issuer设置。

``` C
  schema_t schema;
  schema_init(schema, 5); // 3 internal + 2 user defined
  schema_attr_set_hidden(schema, 0);
  schema_attr_set_known(schema, 1);
  schema_attr_set_hidden(schema, 2);
  schema_attr_set_known(schema, 3);  // nationality
  schema_attr_set_known(schema, 4);  // age
```

### 3. 生成主凭证公私钥 - 4.2 Primary Credential Cryptographic Setup

simple.c中写入了p'和q’的值，并公国gmp_sscanf将其读入到本地变量中:
``` C
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
```

这两个值用来生成Issuer需要的公私钥。

``` C
  issuer_sk_t iss_sk;
  issuer_pk_t iss_pk;
  issuer_keys_init_assign(iss_sk, iss_pk, L, p_apos, q_apos);
```

iss_sk就是文档中的Pk = (n, S, Z, {Ri}1<=i<=l)

iss_pk就是文档中的Sk = (p, q, x_Z, x_R1, ..., xRl)

**注意**：可以使用另一个函数`issuer_keys_init_random`直接生成p'和q'，
代码会变得简单，但这是非常耗时的操作。

### 4. 生成撤销用凭证公私钥 - 4.4 Non-revocation Credential Cryptographic Setup

生成撤销用凭证的公私钥，需要用到G1和G2中的两个随机点，作为其随机点。

``` C
  element_t g1_gen;
  element_t g2_gen;
  element_init_G1(g1_gen, pairing);
  element_init_G2(g2_gen, pairing);
  element_random(g1_gen);
  element_random(g2_gen);

  nonrev_sk_t nr_sk;
  nonrev_pk_t nr_pk;
  nonrev_keys_init_assign(nr_sk, nr_pk, pairing, g1_gen, g2_gen);
```

nr_pk就是文档中的Pr = (h, h0, h1, h2, h~, h^, u, pk, y)

nr_sk就是文档中的私钥 = (x, sk)

### 5. 生成累加器 - 4.4.1 New Accumulator Setup

累加器可以完全靠随机函数生成，直接将数据结构代入初始化函数即可。
需要注意的是，L越大，累加器的生成耗时越长。

``` C
  accumulator_t acc;
  accumulator_sk_t acc_sk;
  accumulator_pk_t acc_pk;
  accumulator_init_assign(acc, acc_sk, acc_pk,
			  pairing, L,
			  g1_gen, g2_gen);
```

acc就是累加器数据结构，其中包括最新的累加器的值(acc->acc)
和已经使用的下标i的值(acc->V)

acc_pk就是文档中的Pa = (z)，同时是该累加器的值

acc_sk就是文档中的私钥 = (gamma)

### 6. Holder准备申请证书 - 5.1 Holder Setup

Holder先为`主凭证`生成准备数据，
其首先读取schema S，以便了解哪些属性是隐藏，哪些是暴露的。
之后Holder设置隐藏属性，在simple.c中式m1和m3，
这里使用了随机函数`random_num_bits`为m1生成了随机64位（二进制）数字。
而m3没有用到，将其保留，设置为0即可。

``` C
  random_num_bits(m1, 64); // link secret
  mpz_set_ui(m3, 0); // dx: not using this value
```

接下来要用到属性和属性容器，其定义如下：

``` C
// 属性本身
struct attribute_s {
  unsigned long i; // 表示对应的属性的下标
  mpz_t v;         // 表示对应的属性的值
};

// 属性的容器
struct attribute_vec_s {
  unsigned long l; // 属性列表的长度
  attr_ptr attrs;  // [attribute_s, attribute_s, ...]
};

```

在simple.c中，隐藏的属性容器名为Ah，其长度为2，因其只包含m1和m3属性。
接下来通过`attr_vec_head`函数取到其属性数组`attrs`。
然后设置属性的下标和值。
Ah的第一个属性的下标和值对应m1的下标和值。
Ah的第二个属性的下标和值对应m3的下标和值。

注意下标是从0开始计数的。

``` C
  attr_vec_t Ah;
  attr_vec_init(Ah, 2); // m1 and m3
  attr_vec_head(Ah)[0].i = 0; // 第一个属性的下标等于m1的下标
  mpz_set(attr_vec_head(Ah)[0].v, m1);
  attr_vec_head(Ah)[1].i = 2; // 第二个属性的下标等于m3的下标
  mpz_set(attr_vec_head(Ah)[1].v, m3);
```

然后还要获取n0, holder_id(花体H)和2128位长度的v'，
这里n0是随机获取的，实际上是从Issuer处获取

``` C
  random_num_bits(n0, 80); // nonce from Issuer, make it 80 bits
  random_num_bits(holder_id, 32); // generate holder_id

  // ...

  random_num_exact_bits(v_apos, 2128);
```

最后生成`主凭证请求`:

``` C
  primary_credential_request_t pc_req;
  primary_credential_request_init(pc_req, schema);
  primary_credential_request_assign(pc_req, iss_pk, n0, v_apos, Ah);
```

Holder接下来生成`撤销用凭证请求`。
这里需要用到在Zr中的随机数s'。

``` C
  element_t s_apos;
  element_init_Zr(s_apos, pairing);
  element_random(s_apos);
  nonrev_credential_request_t nrc_req;
  nonrev_credential_request_init(nrc_req, pairing);
  nonrev_credential_request_assign(nrc_req, s_apos, nr_pk);
```

之后将`pc_req`和`nrc_req`发送给Issuer。本例中忽略。

### 7. Issuer收到`主凭证请求`，生成`主凭证响应` - 5.2 Primary Credential Issuerance

首先Issuer校验`主凭证的请求`:

``` C
  gmp_printf("Issuer veriﬁes the correctness of Holder’s input\n");
  if (!primary_credential_request_verify(pc_req, iss_pk, n0)) {
	gmp_printf("primary pre credential prepare verifyed: okay\n");
  } else {
	gmp_printf("primary pre credential prepare verifyed: error\n");
	return -1;
  }
```

之后计算m2, 设置m4和m5的值

``` C
  compute_m2(m2, index, holder_id);
  mpz_set_ui(m4, 86); // country code of China
  mpz_set_ui(m5, 18); // age
```

接下来如法炮制已知属性容器，即Ak:

``` C
  attr_vec_t Ak;
  attr_vec_init(Ak, schema_attr_cnt_known(schema));
  attr_vec_head(Ak)[0].i = 1;
  mpz_set(attr_vec_head(Ak)[0].v, m2);
  attr_vec_head(Ak)[1].i = 3;
  mpz_set(attr_vec_head(Ak)[1].v, m4);
  attr_vec_head(Ak)[2].i = 4;
  mpz_set(attr_vec_head(Ak)[2].v, m5);
```

使用之前的参数，生成`主凭证响应`

``` C
  primary_credential_response_t pc_res;
  primary_credential_response_init(pc_res, schema);
  primary_credential_response_assign(pc_res, iss_pk, iss_sk, Ak, pc_req);
```

将其发送给Holder，本例子中忽略。

### 8. Issuer收到`撤销用凭证请求`，生成`撤销用凭证响应` - 5.3. Non-revocation Credential Issuerance

``` C
  nonrev_credential_response_t nrc_res;
  nonrev_credential_response_init(nrc_res, pairing);
  nonrev_credential_response_assign(nrc_res, m2, INDEX, nr_pk, nr_sk,
                                    acc, acc_pk, acc_sk, nrc_req);
```

将其发送给Holder，本例子中忽略。
这个函数同时更新了累加器acc中的值(acc->acc)和累加器容器(acc->A)

### 9. Holder收到`主凭证响应`和`撤销用凭证响应`，生成并`主凭证`和`撤销用凭证` - 5.4 Storing Credentials

首先生成`主凭证`，然后用主凭证去检查Issuer发过来的数据是否合法。
之后再生成`撤销用凭证`。

``` C
  primary_credential_t pc;
  primary_credential_init(pc, schema);
  primary_credential_assign(pc, v_apos, Ah, pc_res);

  if (!primary_credential_response_verify(pc_res, iss_pk, pc_req->n1, pc)) {
	gmp_printf("primary pre credential okay\n");
  } else {
	gmp_printf("primary pre credential error\n");
	return -1;
  }

  nonrev_credential_t nrc;
  nonrev_credential_init(nrc, pairing);
  nonrev_credential_assign(nrc, s_apos, nrc_res);
```

### 10. 证明请求 - 7.1 Proof Request

本例中，设置m4为暴露属性，即直接告诉Verifier m4的值。
其他属性设置为未知属性。
首先为m1, m2, m3和m5生成属性的随机值。
`attr_vec_init_random`会为其四个属性的v生成随机592位数字。

``` C
  attr_vec_t Ar_bar; // m_tildes
  attr_vec_init_random(Ar_bar, 4, 592); // open m4
  attr_vec_head(Ar_bar)[0].i = 0;
  attr_vec_head(Ar_bar)[1].i = 1;
  attr_vec_head(Ar_bar)[2].i = 2;
  attr_vec_head(Ar_bar)[3].i = 4; // m5_tilde
```

### 11. 准备证明 - 7.2 Proof Preparetion

首先准备两个容器，spT和spC。对应文档中的T容器和C容器。

``` C
  mpz_vec_t spT, spC; // T for subproof
  mpz_vec_init(spT);
  mpz_vec_init(spC);
```

对`撤销用凭证`做以下操作：
1. 使用最新的累加器更新其内部的值
2. 初始化并赋值辅助数据结构nonrev_credential_subproof_auxiliary_t
3. 初始化并赋值关于元组C的数据结构nonrev_credential_subproof_tuple_c_t
4. 导出相关数据到T容器和C容器

``` C
  nonrev_credential_update(nrc, acc); // 更新累加器

  nonrev_credential_subproof_auxiliary_t nrcsp_aux; // 辅助数据结构
  nonrev_credential_subproof_auxiliary_init(nrcsp_aux, pairing);
  nonrev_credential_subproof_auxiliary_assign(nrcsp_aux, nrc);

  nonrev_credential_subproof_tuple_c_t nrspC; // 撤销用凭证的元组C
  nonrev_credential_subproof_tuple_c_init(nrspC, pairing);
  nonrev_credential_subproof_tuple_c_assign(nrspC, nr_pk, nrc, nrcsp_aux, acc);

  // 导出至C容器和T容器
  nonrev_credential_subproof_tuple_c_into_vec(spC, nrspC);
  nonrev_credential_subproof_dump_t(spT, pairing, nr_pk, acc, nrcsp_aux, nrspC);
```

对`主凭证`做以下操作：
1. 初始化并赋值辅助数据结构primary_credential_subproof_auxiliary_t
2. 初始化并赋值关于元组C的数据结构primary_credential_subproof_tuple_c_t
3. 导出相关数据到T容器和C容器

``` C
  primary_credential_subproof_auxiliary_t pcsp_aux; // 辅助数据结构
  primary_credential_subproof_auxiliary_init(pcsp_aux);
  primary_credential_subproof_auxiliary_assign(pcsp_aux, pc);

  primary_credential_subproof_tuple_c_t pcspC; // 主凭证的元组C
  primary_credential_subproof_tuple_c_init(pcspC);
  primary_credential_subproof_tuple_c_assign(pcspC, iss_pk, pc, pcsp_aux);

  // 导出至C容器和T容器
  primary_credential_subproof_tuple_c_into_vec(spC, pcspC);
  primary_credential_subproof_dump_t(spT, iss_pk, Ar_bar, pcsp_aux, pcspC);
```

simple.c中包含一个谓词证明，要求证明凭证中的年龄小于20。
首先准备该谓词：

``` C
  mpz_t z5;
  mpz_init_set_ui(z5, 20);
  predicate_t pred;

  // 这个谓词的意思是：m5(18) < z5(20)
  predicate_init_assign(pred, LESS_THAN, m5, z5);
```

之后对该谓词作出以下操作：
1. 初始化并赋值辅助数据结构predicate_subproof_auxiliary_t
2. 初始化并赋值关于元组C的数据结构predicate_subproof_tuple_c_t
3. 导出相关数据到T容器和C容器

``` C
 // 辅助数据结构, 需要用到对应的m~数据，从Ar_bar中获取
  predicate_subproof_auxiliary_t pred_aux;
  predicate_subproof_auxiliary_init(pred_aux);
  predicate_subproof_auxiliary_assign(pred_aux, pred, attr_vec_head(Ar_bar)[3].v);

  predicate_subproof_tuple_c_t predC; // 元组C
  predicate_subproof_tuple_c_init(predC);
  predicate_subproof_tuple_c_assign(predC, iss_pk, pred_aux);

  // 导出至C容器和T容器
  predicate_subproof_tuple_c_into_vec(spC, predC);
  predicate_subproof_dump_t(spT, iss_pk, pred_aux, predC);
```

接下来计算hash值(7.2.1)，sm3_TCn是一个辅助函数

``` C
  mpz_t CH;
  mpz_init(CH);
  sm3_TCn(CH, spT, spC, pc_req->n1);
```

最终准备(7.2.2)

``` C
  tuple_x_t X; // 撤销用凭证的子证明
  tuple_x_init(X, pairing);
  tuple_x_assign(X, CH, m2, nrc, nrcsp_aux);


  primary_credential_subproof_t pcsp;  // 主凭证的子证明
  primary_credential_subproof_init(pcsp, 4);
  primary_credential_subproof_assign(pcsp, CH, Ar_bar, pc,
                                     pcsp_aux, pcspC->A_apos);

  predicate_subproof_t predsp; // 谓词的子证明
  predicate_subproof_init(predsp);
  predicate_subproof_assign(predsp, CH, pred, pred_aux);
```

这里CH就是文档中的c，
X就是文档中的花体X(这是事实上的nonrev subproof)，
pcsp就是文档中的Pr_C，
predsp就是文档中的Pr_P，
spC就是文档中的花体C。

Prover将这些数据发送给Verifier，本例中不用做。

### 12. 证明确认 - 7.3 Verification

Verifier使用Prover发送的数据导出T的值，
并生成CH，和Prover发送过来的CH做比对，
若相同，则证明通过，否则证明失败。

``` C
  mpz_vec_t checkT;
  mpz_vec_init(checkT);
  nonrev_credential_subcheck_dump_t(checkT, pairing, CH, acc,
                                    acc_pk, nr_pk, X, nrspC);
  primary_credential_subcheck_dump_t(checkT, iss_pk, CH, Ar, pcsp);
  predicate_subcheck_dump_t(checkT, iss_pk, CH, pred, predC, predsp);

  mpz_t CH1;
  mpz_init(CH1);
  sm3_TCn(CH1, checkT, spC, pc_req->n1);
```
