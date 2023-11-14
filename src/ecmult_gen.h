/*
 * @Author: king
 * @Date: 2023-03-09 16:46:49
 * @LastEditors: error: error: git config user.name & please set dead value or install git && error: git config user.email & please set dead value or install git & please set dead value or install git
 * @LastEditTime: 2023-03-18 16:53:36
 * @FilePath: /secp256k1-master/src/ecmult_gen.h
 * @Description: 
 * 
 * Copyright (c) 2023 by ${git_name_email}, All Rights Reserved. 
 */
/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_ECMULT_GEN_H
#define SECP256K1_ECMULT_GEN_H

#include "scalar.h"
#include "group.h"

#ifndef ECMULT_GEN_PREC_BITS
#  define ECMULT_GEN_PREC_BITS 4
#  ifdef DEBUG_CONFIG
#     pragma message DEBUG_CONFIG_MSG("ECMULT_GEN_PREC_BITS undefined, assuming default value")
#  endif
#endif

#ifdef DEBUG_CONFIG
#  pragma message DEBUG_CONFIG_DEF(ECMULT_GEN_PREC_BITS)
#endif

#if ECMULT_GEN_PREC_BITS != 2 && ECMULT_GEN_PREC_BITS != 4 && ECMULT_GEN_PREC_BITS != 8
#  error "Set ECMULT_GEN_PREC_BITS to 2, 4 or 8."
#endif

#define ECMULT_GEN_PREC_G(bits) (1 << bits)
#define ECMULT_GEN_PREC_N(bits) (256 / bits)

typedef struct {
    /* Whether the context has been built. */
    int built;

    /* Blinding values used when computing (n-b)G + bG. */
    /*计算（n-b）G+bG时使用的blind*/
    secp256k1_scalar blind; /* -b */
    /*初始化主要初始化这个点 gej格式的点*/
    secp256k1_gej initial;  /* bG */
} secp256k1_ecmult_gen_context;

static void secp256k1_ecmult_gen_context_build(secp256k1_ecmult_gen_context* ctx);
static void secp256k1_ecmult_gen_context_clear(secp256k1_ecmult_gen_context* ctx);

/** Multiply with the generator: R = a*G */
static void secp256k1_ecmult_gen(const secp256k1_ecmult_gen_context* ctx, secp256k1_gej *r, const secp256k1_scalar *a);

static void secp256k1_ecmult_gen_blind(secp256k1_ecmult_gen_context *ctx, const unsigned char *seed32);

#endif /* SECP256K1_ECMULT_GEN_H */
