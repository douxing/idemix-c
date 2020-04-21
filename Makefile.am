SUBDIRS = . example

SO_VERSION = 0:1:0

ACLOCAL_AMFLAGS = -I m4

maintainer-clean-local:
	-rm -rf Makefile.in config.h.in \
configure autom4e.cache aclocal.m4 tmp build-aux

lib_LTLIBRARIES = libidemix.la

library_includedir = $(includedir)/idemix
library_include_HEADERS = include/idemix.h \
include/idemix_accumulator.h \
include/idemix_attribute.h \
include/idemix_bitmap.h \
include/idemix_byteorder.h \
include/idemix_decompose.h \
include/idemix_holder.h \
include/idemix_issuer.h \
include/idemix_issuer_key.h \
include/idemix_mpz_vec.h \
include/idemix_nonrev_credential.h \
include/idemix_nonrev_credential_request.h \
include/idemix_nonrev_credential_response.h \
include/idemix_nonrev_credential_subcheck_dump_t.h \
include/idemix_nonrev_credential_subproof_auxiliary.h \
include/idemix_nonrev_credential_subproof_dump_t.h \
include/idemix_nonrev_credential_subproof.h \
include/idemix_nonrev_credential_subproof_tuple_c.h \
include/idemix_nonrev_key.h \
include/idemix_pairing.h \
include/idemix_parameters.h \
include/idemix_predicate.h \
include/idemix_predicate_subcheck_dump_t.h \
include/idemix_predicate_subproof_auxiliary.h \
include/idemix_predicate_subproof_dump_t.h \
include/idemix_predicate_subproof.h \
include/idemix_predicate_subproof_tuple_c.h \
include/idemix_primary_credential.h \
include/idemix_primary_credential_request.h \
include/idemix_primary_credential_response.h \
include/idemix_primary_credential_subcheck_dump_t.h \
include/idemix_primary_credential_subproof_auxiliary.h \
include/idemix_primary_credential_subproof_dump_t.h \
include/idemix_primary_credential_subproof.h \
include/idemix_primary_credential_subproof_tuple_c.h \
include/idemix_prover.h \
include/idemix_random.h \
include/idemix_schema.h \
include/idemix_sm3.h \
include/idemix_verifier.h \
include/idemix_witness.h

libidemix_la_CPPFLAGS = -Iinclude
libidemix_la_SOURCES = accumulator.c \
attribute.c \
bitmap.c \
decompose.c \
issuer.c \
issuer_key.c \
mpz_vec.c \
nonrev_credential.c \
nonrev_credential_request.c \
nonrev_credential_response.c \
nonrev_credential_subcheck_dump_t.c \
nonrev_credential_subproof_auxiliary.c \
nonrev_credential_subproof.c \
nonrev_credential_subproof_dump_t.c \
nonrev_credential_subproof_tuple_c.c \
nonrev_key.c \
predicate.c \
predicate_subcheck_dump_t.c \
predicate_subproof_auxiliary.c \
predicate_subproof.c \
predicate_subproof_dump_t.c \
predicate_subproof_tuple_c.c \
primary_credential.c \
primary_credential_request.c \
primary_credential_response.c \
primary_credential_subcheck_dump_t.c \
primary_credential_subproof_auxiliary.c \
primary_credential_subproof.c \
primary_credential_subproof_dump_t.c \
primary_credential_subproof_tuple_c.c \
prover.c \
random.c \
schema.c \
sm3.c \
verifier.c \
witness.c

libidemix_la_LDFLAGS = -lgmp -lpbc -version-info $(SO_VERSION)
