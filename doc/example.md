# 例子程序

## 一个简单而完整的例子(simple)

本例子可以在项目example中找到。
其依次做了如下工作：

#### 准备数据，包括schema数据、双线性对数据和密码学数据

1. 初始化pairing数据，从在a.param文本文件中读取该数据。
2. 准备schema，遵循文档的规定，m1, m3是隐藏属性，m2是公开属性，本例添加的m4为国家编码信息，m5为年龄。这里所谓的公开和隐藏是在Issuer和Holder之间的。
3. 准备primary credential的公私钥，因为质数生成需要一定的时间，本例使用预先生成的p'和q'来做初始化的任务。
4. 使用pairing生成G1和G2群中的生成元，并生成nonrev credential的公私钥。
5. 生成累加器

#### Issuer和Holder交互，生成credential数据

首先Holder准备数据：

1. 设置隐藏属性，在本例中是m1和m3，由于m3还没用到，因此设置为0，使用m1和m3初始化Ah属性容器。
2. 生成随机数n0和holder_id，这两个数Issuer也知晓
3. 生成随机数v'
4. 生成primary_pre_credential_prepare并使用之前生成的数据赋值之
5. 生成随机数s'
6. 生成nonrev_pre_credential_prepare并使用之前生成的数据赋值之

接下来Holder将primary_pre_credential_prepare和non-revocation_pre_credential_prepare数据发送给Issuer。Issuer接着做：

1. 调用primary_pre_credential_prepare_verify检查primary_pre_credential_prepare的数据正确性
2. 设置m2，m4和m5，其中m2通过函数compute_m2实现，m4设置为86，m5设置为18，并初始化Ak属性数组
3. 生成primary_pre_credential并使用之前生成的数据赋值之
4. 生成nonrev_pre_credential并使用之前生成的数据赋值之
5. 在账本中更新V和A，这一步在本例子中不需要

Issuer将primary_pre_credential和nonrev_pre_credential发送给Holder，
Holder接着做：

1. 初始化并赋值primary_credential
2. 初始化并赋值nonrev_credential

此时Holder是知道Cs中所有属性的明文值，且这些值是对其他人隐藏的（除了Issuer知道Ak的值）。

#### Prover和Verifier交互，以完成证明

**注意**：这里的Prover就是之前的Holder。

首先Verifier需要构建proof request，里面包括需要暴露哪些属性给自己，且对非暴露的值，设置谓词。在本例中，将会暴露m4，隐藏其他4个属性，并对m5的值做一个谓词，要求m5小于20。

Prover准备如下数据：

1. 初始化T数组和C数组
2. 生成nonrev_credential_subproof_auxiliary数据并随机赋值。生成元组C数据并将其导入C数组。直接调用nonrev_credential_subproof_dump_t生成并直接导入T数组。
3. 生成primary_credential_subproof_auxiliary数据并随机赋值。生成元组C数据并将其导入C数组。直接调用primary_credential_subproof_dump_t生成并直接导入T数组。
4. 为4个非暴露属性生成随机数，加入Ar_bar数组中。
5. 为m5生成谓词m5<20。为谓词生成predicate_subproof_auxiliary数据并赋值。生成元组C数据并将其导入c数组。直接调用predicate_subproof_dump_t生成并直接导入T数组。
6. 使用sm3_TCn生成CH。
7. 根据CH初始化并生成X元组(dx注：即nonrev_subproof)，primary_credential_subproof和predicate_subproof
8. 发送(CH, {X}, {PrC}, {PrP}, 元组C)给Verifier，本例中不需要做。

Verifier拿到数据后，初始化本地T数组并开始计算：

1. 调用nonrev_credential_subcheck_dump_t计算并导入T数组
2. 调用primary_credential_subcheck_dump_t计算并导入T数组
3. 调用predicate_subcheck_dump_t计算并导入T数组
4. 使用sm3_TCn生成本地CH

若本地CH和CH相同，则证明通过，否则证明失败。

## 一个稍显复杂的例子(medium)

本例子中的schema定义如下：

```
schema employee {
  m1: LinkSecret,
  m2: context,
  m3: 保留,
  m4: 个人身份id,
  m5: 公司名称(id),
  m6: 个人薪水,
  m7: 入职日期
}
```

前提假设：
- Alice于20200401入职公司alpha，待遇10000
- Alice于20200501入职公司beta，待遇5000
- Bob于20200401入职公司alpha，待遇20000

本例子中包括5个证明
1. Alice在alpha和beta公司都有工作，且Alice在alpha的待遇为10000(通过大于9999和小于10001两个谓词实现)，在beta的待遇为5000(通过大于等于5000和小于等于5000两个谓词实现)
2. Bob在alpha有工作，且有待遇(通过谓词大于0实现)，其入职为2020年4月份(通过谓词大于等于20200401和小于等于20200430两个谓词实现)
3. Alice和Bob都在Alice工作，但是这个例子是现实中不会发生的例子，本例子着重为了说明，Verifier需要先验证LinkSecret对应的m1^是否相同，这是计算CH1的前提瞧见，若LinkSecret不相同，那可以直接认为其证明失败，即便CH和CH1相同(这是完全有可能的)，也没有意义。
4. 仅证明Alice在alpha有工作(作撤销证明用)
5. 仅证明Alice在beta有工作(作撤销证明用)


首先为Alice颁发了alpha和beta的证书，为Bob颁发了alpha的证书。
要保证Alice的LinkSecret是相同的。
之后开始证明1和证明2，其中证明2运行了两次，因为算法中有随机数，所以两次CH的结果不会相同，但每一次的CH和CH1是一样的。之后运行了证明3，再次强调，这一个错误的示范。之后撤销Alice在alpha中的证书，再次运行证明1，其必然不会通过。然后再运行证明4，其也不会通过。但是Alice在beta的证书还没有撤销，因此证明5会通过。再撤销Alice在beta中的证书，可以发现证明5也无法通过了。
