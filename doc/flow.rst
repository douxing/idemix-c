========
 数据流
========

请配合简单例子simple.c阅读

证书申请
============

.. mermaid::

   sequenceDiagram
      participant I as Issuer
      participant H as Holder
      participant L as 账本（区块链）
      Note over H: LinkSecret为私钥
      Note over H: PolicyAddress未使用设为0
      Note over H: 本Holder的id为holder_id
      I->>H: 双方约定nonce: n0
      H->>H: 读取Schema
      H->>H: schema的m1设置为LinkSecret
      H->>H: schema的m3设置为PolicyAddress(值为0)
      H->>H: 设置schema的其他隐藏属性(若有)
      H->>H: 生成2028位随机数v'
      H->>H: 生成主凭证请求(primary_credential_request)
      H->>H: 生成撤销用凭证请求(nonrev_credential_request)
      H->>I: 主凭证请求，撤销用凭证请求
      I->>I: 使用n0验证主凭证请求是否合法
      I->>I: 计算并设置schema的m2
      I->>I: 设置schema的其他公开属性
      I->>I: 生成主凭证响应(primary_credential_response)
      I->>I: 为该请求选择一个未使用的累加器索引INDEX
      I->>I: 生成撤销用凭证响应(nonrev_credential_response)
      I->>L: 更新累加器的值和索引容器
      I->>H: 主凭证响应，撤销用凭证响应
      H->>H: 生成主凭证(primary_credential)
      H->>H: 验证主凭证是否合法
      H->>H: 生成撤销用凭证(nonrev_credential)
      H->>H: 保存主凭证，撤销用凭证

证明准备和验证
==============

.. mermaid::

   sequenceDiagram
      participant P as Prover
      participant V as Verifier
      participant L as 账本（区块链）
      V->>V: 读取schema
      V->>V: 确认暴露属性
      V->>V: 确认隐藏属性的谓词
      V->>P: 证明请求
      P->>P: 为隐藏属性生成随机数容器
      P->>P: 生成容器C和容器T
      L->>P: 最新累加器的值和索引容器
      P->>P: 生成撤销用凭证子证明，相关数据导出至容器C和容器T
      P->>P: 生成主凭证子证明，相关数据导出至容器C和容器T
      P->>P: 生成谓词子证明，相关数据导出至容器C和容器T
      P->>P: 生成hash值CH
      P->>V: 所有撤销用凭证的子证明，主凭证的子证明，谓词的子证明，CH和容器C
      V->>V: 生成容器T
      V->>V: 撤销用凭证子证明相关数据导出至容器T
      V->>V: 主凭证子证明相关数据导出至容器T
      V->>V: 谓词子证明相关数据导出至容器T
      V->>V: 生成hash值CH1
      V->>V: 校验CH是否等于CH1
