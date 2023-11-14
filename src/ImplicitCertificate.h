/*
 * @Author: king
 * @Date: 2023-03-22 11:46:34
 * @LastEditors: kinghyt12138 kinghyt12138@example.com
 * @LastEditTime: 2023-10-27 18:26:06
 * @FilePath: /secp256k1-master/src/ImplicitCertificate.h
 * @Description: 隐式证书头文件
 * 
 * Copyright (c) 2023 by ${git_name_email}, All Rights Reserved. 
 */

#ifndef IMPLICITCERTIFICATE_H_
#define IMPLICITCERTIFICATE_H_

#include "group.h"
#include "ecmult.h"
#include "scalar.h"
/**
 * 生成密钥对和gama值
*/
static int Generate_key_pairs_and_gamma_values(const secp256k1_ecmult_gen_context *ctx,const secp256k1_scalar *nonce1,const secp256k1_scalar *nonce2,const secp256k1_scalar *seckey1,const secp256k1_scalar * DLCV,secp256k1_scalar *seckey2,secp256k1_ge *gama);
/**
 * 验证隐式证书 包含一层重构公钥
*/
static void ImplicitCertificate_Verify(const secp256k1_ecmult_gen_context *ctx,const secp256k1_ge *gama,const secp256k1_scalar *DLCV,
const secp256k1_ge *CA_pub,secp256k1_ge *pub);
/**
 * 模拟硬件层启动
*/
static void HardwareLayer_device_startup_process(const secp256k1_ecmult_gen_context *ctx,const secp256k1_scalar *d,
const secp256k1_scalar *C0,secp256k1_scalar *DLCV0,secp256k1_scalar *seckey0,secp256k1_ge *pub0);
/* 模拟硬件层启动 全部使用隐式证书 */
static int HardwareLayer_device_startup_process3(const secp256k1_ecmult_gen_context *ctx,const secp256k1_scalar *CApri,const secp256k1_scalar *d,
const secp256k1_scalar *C0,secp256k1_scalar *DLCV0,secp256k1_ge *gama0,secp256k1_scalar *seckey0);
/**
 * 模拟可更新固件层的启动
*/
static int Layer_n_device_startup_process(const secp256k1_ecmult_gen_context *ctx,const secp256k1_scalar *seckey,const secp256k1_scalar *DLCV_n_1,
const secp256k1_scalar *C_n,secp256k1_scalar *DLCV_n,secp256k1_scalar *seckey2,secp256k1_ge *gama);
/**
 * 层层重构公钥
*/
static void Recursive_Reconstruction_of_Public_Key(const secp256k1_ecmult_gen_context *ctx,const secp256k1_ge *gama,const secp256k1_scalar *DLCV,
secp256k1_ge *CA_pub,const secp256k1_ge *pub0,const secp256k1_scalar *DLCVlist,const secp256k1_ge *gamalist,secp256k1_ge *pubn,int n);
/* 重构公钥 一个式子计算 */
static void Recursive_Reconstruction_of_Public_Key2(const secp256k1_ecmult_gen_context *ctx,const secp256k1_ge *pub0,
const secp256k1_scalar *DLCVlist,const secp256k1_ge *gamalist,secp256k1_ge *pubn,int n);

typedef struct Equipment_Certification_Report_struct Equipment_Certification_Report;
/*清空结构体函数*/
static void Equipment_Certification_Report_clear(Equipment_Certification_Report *data);
/* 结构体打印 */
static void Equipment_Certification_Report_Print(Equipment_Certification_Report data);

#endif 

















