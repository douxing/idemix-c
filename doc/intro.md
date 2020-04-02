# 简介

本项目实现了idemix 1.0相关的算法，该加密算法主要实现了属性的隐藏和暴露，
隐藏属性的谓词操作(<=, <, >=, >)，以及相关证书的发放和撤销功能。

本项目使用c语言实现，除了c标准库外，本项目在内部使用了[GMP库][GMP]和[PBC库][PBC]。
本库使用了GMP的mpz_t大整数类型，以及其数学和数论相关的函数。
PBC库是是来执行双线性对操作的，最主要用到的`element_pairing`函数，将(G1, G2)映射到GT中。

# 预备知识

在使用本库前，请尽量对相关算法有所了解，可以适当阅读本项目doc目录下的相关pdf文档：

1. anoncred-usecase0.pdf
2. anoncred-usecase1.pdf
3. Anonymous credentials with type-3 revocation.pdf
4. Specification of the Identity Mixer Cryptographic Library.pdf

# 实现中的问题

本库是完全按照`3. Anonymous credentials with type-3 revocation.pdf`实现的，
但是其描述的公式中`(39)`、`(56)`式有错误。
正确的实现在`4. Specification of the Identity Mixer Cryptographic Library.pdf`中：

- `文档3. (39)`式中的T应该根据`文档4. 6.2.6 1. Proof Setup`实现
- `文档3. (56)`式中的T应该根据`文档4. 6.2.15`实现

[GMP]: https://gmplib.org/
[PBC]: https://crypto.stanford.edu/pbc/
