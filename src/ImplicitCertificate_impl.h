/*
 * @Author: king
 * @Date: 2023-03-21 22:03:58
 * @LastEditors: kinghyt12138 kinghyt12138@example.com
 * @LastEditTime: 2023-11-02 10:26:15
 * @FilePath: /secp256k1-master/src/ImplicitCertificate_impl.h
 * @Description: 隐式证书实现文件
 * 
 * Copyright (c) 2023 by ${git_name_email}, All Rights Reserved. 
 */

#ifndef IMPLICITCERTIFICATE_IMPL_H_
#define IMPLICITCERTIFICATE_IMPL_H_

#include "field.h"
#include "group.h"
#include "ecmult.h"
#include "ecmult_gen.h"
#include "scalar.h"
#include "scalar_impl.h"
#include "ImplicitCertificate.h"


/**
 * 定义新结构体存储验证时设备所需要提交的数据
*/
struct Equipment_Certification_Report_struct
{
    /* data */
    /*设备固件信息dfi 不具体做描述 */
    // unsigned char message[100];
    secp256k1_scalar m;
    /*DLCV0 */
    secp256k1_scalar DLCV_0;
    /*gama list gama1-n*/
    secp256k1_ge gama_list[2];
    /*签名值*/
    secp256k1_scalar sigd;
    secp256k1_scalar sigz;
    /* 第n层公钥 */
    secp256k1_ge pubn;
};

/**
 * @description: 隐式证书过程
 * @param {secp256k1_scalar} *nonce1 随机数1 由密钥推导函数生成 随机数2随机生成
 * @param {secp256k1_scalar} *nonce2
 * @param {secp256k1_scalar} *seckey1 私钥1 本层私钥
 * @param {secp256k1_scalar} *DLCV 下一层的TCI值 作为身份标识使用
 * @param {secp256k1_scalar} *seckey2 私钥2 生成的下一层私钥
 * @param {secp256k1_ge} *gamma  计算过程中的gama值
 * @return {*}
 */
static int Generate_key_pairs_and_gamma_values(const secp256k1_ecmult_gen_context *ctx,const secp256k1_scalar *nonce1,const secp256k1_scalar *nonce2,
const secp256k1_scalar *seckey1,const secp256k1_scalar * DLCV,secp256k1_scalar *seckey2,secp256k1_ge *gama){
    secp256k1_gej pubj;
    secp256k1_gej pubj2;
    secp256k1_gej k_Gj;
    secp256k1_gej gamaj;
    secp256k1_gej Aj;
    secp256k1_fe zr;
    secp256k1_sha256 hasher;
    unsigned char gama_char[64];
    unsigned char dlcv_char[32];
    secp256k1_scalar e;
    secp256k1_scalar s;
    unsigned char output_hash[32];
    int overflow=0;
    /* 首先计算Aj=nonce1×G */
    secp256k1_ecmult_gen(ctx, &Aj, nonce1);
    /* 计算 k_G*/
    secp256k1_ecmult_gen(ctx, &k_Gj, nonce2);
    /* 计算gama值 gama=A+k_G 椭圆曲线点加*/
    secp256k1_gej_add_var(&gamaj,&Aj,&k_Gj,secp256k1_gej_is_infinity(&Aj) ? NULL : &zr);
    /* 坐标变换 */
    secp256k1_ge_set_gej(gama, &gamaj);
    /* 将gama和dlcv转成字符形式 */
    secp256k1_ge_to_char(gama_char, gama);
    secp256k1_scalar_get_b32(dlcv_char, DLCV);
    /* 计算hash（gama，dlcv） */
    secp256k1_sha256_initialize(&hasher);
    secp256k1_sha256_write(&hasher, gama_char, sizeof(gama_char));
    secp256k1_sha256_write(&hasher, dlcv_char, sizeof(dlcv_char));
    secp256k1_sha256_finalize(&hasher,output_hash);
    /* e=hash（gama，dlcv） */
    secp256k1_scalar_set_b32(&e, output_hash, &overflow);
    VERIFY_CHECK(overflow == 0);
    
    /*计算s=e×nonce2+seckey1 mod n, */
    secp256k1_scalar_mul(&s,&e,nonce2);
    secp256k1_scalar_add(&s,&s,seckey1);
    /* mod n */
    
    /* 计算下一层私钥 seckey2 = e*nonce1+s mod n */
    secp256k1_scalar_mul(seckey2,&e,nonce1);
    secp256k1_scalar_add(seckey2,seckey2,&s);
   /* mod n */
   
    /* 计算公钥 PK=e×gama+pub */
    secp256k1_ecmult(&pubj, &gamaj, &e, seckey1);    /* PK = gama*e + seckey1*G  */
    /* 验证公私钥是否符合椭圆曲线 */
    secp256k1_ecmult_gen(ctx, &pubj2, seckey2);

    int ret = secp256k1_gej_eq_var(&pubj,&pubj2);
      /* 做一下clear
    secp256k1_gej Aj;
    secp256k1_gej pubj;
    secp256k1_gej pubj2;
    secp256k1_gej k_Gj;
    secp256k1_gej gamaj; 
    secp256k1_scalar e;
    secp256k1_scalar s;*/
    secp256k1_gej_clear(&pubj);
    secp256k1_gej_clear(&pubj2);
    secp256k1_gej_clear(&k_Gj);
    secp256k1_gej_clear(&gamaj);
    secp256k1_scalar_clear(&e);
    if(ret){
        /*printf("密钥验证成功！");*/
        return 1;
    }
    return 0;
}

/**
 * @description: 重构公钥
 * @param {secp256k1_ecmult_gen_context} *ctx
 * @param {secp256k1_ge} *gama 公钥重构值
 * @param {secp256k1_scalar} *DLCV 身份标识
 * @param {secp256k1_ge} *CA_pub CA公钥
 * @param {secp256k1_ge} *pub 重构出来的公钥
 * @return {*}
 */
static void ImplicitCertificate_Verify(const secp256k1_ecmult_gen_context *ctx,const secp256k1_ge *gama,const secp256k1_scalar *DLCV,
const secp256k1_ge *CA_pub,secp256k1_ge *pub){
    /* 证书验证需要一个消息 使用私钥签名，使用gama dlcv以及CA公钥构造出公钥验证 判断是否验证成功！
    或许可以调用ecdsa签名验证 此函数仅用于重构公钥 */
    secp256k1_gej pubj;
    secp256k1_gej tmp;
    secp256k1_gej CA_pubj;
    secp256k1_scalar e;
    secp256k1_sha256 hasher;
    secp256k1_fe zr;
    int overflow = 0;
    unsigned char gama_char[64];
    unsigned char dlcv_char[32];
    unsigned char output_hash[32];
    static const secp256k1_scalar zero = SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 0);
    /* 构造公钥 */
    /* 将gama和dlcv转成字符形式 */
    secp256k1_ge_to_char(gama_char, gama);
    secp256k1_scalar_get_b32(dlcv_char, DLCV);
    /* 计算hash（gama，dlcv） */
    secp256k1_sha256_initialize(&hasher);
    secp256k1_sha256_write(&hasher, gama_char, sizeof(gama_char));
    secp256k1_sha256_write(&hasher, dlcv_char, sizeof(dlcv_char));
    secp256k1_sha256_finalize(&hasher,output_hash);
    /* e=hash（gama，dlcv） */
    secp256k1_scalar_set_b32(&e, output_hash, &overflow);
    VERIFY_CHECK(overflow == 0);
    /* 重构公钥 pub = e*gama+CA_pub */
    /* 坐标变换 */
    secp256k1_gej_set_ge(&CA_pubj, CA_pub);
    secp256k1_gej_set_ge(&pubj, gama);
    /* 实现e×gama 最后一个参数设置为0常量 */
    secp256k1_ecmult(&tmp, &pubj, &e, &zero);
    secp256k1_gej_add_var(&pubj,&tmp,&CA_pubj,secp256k1_gej_is_infinity(&tmp) ? NULL : &zr);
    secp256k1_ge_set_gej(pub, &pubj);


    secp256k1_gej_clear(&pubj);
    secp256k1_gej_clear(&tmp);
    secp256k1_gej_clear(&CA_pubj);
    secp256k1_scalar_clear(&e);
    secp256k1_fe_clear(&zr);
    return ;
}

/**
 * @description: 递归重构公钥
 * @param {secp256k1_ecmult_gen_context} *ctx
 * @param {secp256k1_ge} *gama 第n层的gama值
 * @param {secp256k1_scalar} *DLCV 第n层的DLCV值
 * @param {secp256k1_ge} *CA_pub CA公钥 临时变量作为在递归之间的传递变量
 * @param {secp256k1_ge} *pub0 第0层的公钥
 * @param {secp256k1_scalar} *DLCVlist DLCV值列表
 * @param {secp256k1_ge} *gamalist gama值列表
 * @param {secp256k1_ge} *pubn 重构出来的设备第n层的公钥
 * @param {int} n  设备除硬件层以外的层数
 * @return {*}
 */
static void Recursive_Reconstruction_of_Public_Key(const secp256k1_ecmult_gen_context *ctx,const secp256k1_ge *gama,const secp256k1_scalar *DLCV,
secp256k1_ge *CA_pub,const secp256k1_ge *pub0,const secp256k1_scalar *DLCVlist,const secp256k1_ge *gamalist,secp256k1_ge *pubn,int n){
    secp256k1_gej pubj;
    secp256k1_gej tmp;
    secp256k1_gej CA_pubj;
    secp256k1_scalar e;
    secp256k1_sha256 hasher;
    secp256k1_fe zr;
    int overflow = 0;
    unsigned char gama_char[64];
    unsigned char dlcv_char[32];
    unsigned char output_hash[32];
    static const secp256k1_scalar zero = SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 0);
    /* 构造公钥 */
    /* 将gama和dlcv转成字符形式 */
    secp256k1_ge_to_char(gama_char, gama);
    secp256k1_scalar_get_b32(dlcv_char, DLCV);
    /* 计算hash（gama，dlcv） */
    secp256k1_sha256_initialize(&hasher);
    secp256k1_sha256_write(&hasher, gama_char, sizeof(gama_char));
    secp256k1_sha256_write(&hasher, dlcv_char, sizeof(dlcv_char));
    secp256k1_sha256_finalize(&hasher,output_hash);
    /* e=hash（gama，dlcv） */
    secp256k1_scalar_set_b32(&e, output_hash, &overflow);
    VERIFY_CHECK(overflow == 0);

    /* 递归限制条件 */
    if (n==0){
        /* 第0层构造的是第一层的公钥 CA_pub就是pub0 */
        *CA_pub = *pub0;
    }else{
        /* 重构公钥 pub = e*gama+CA_pub */
        Recursive_Reconstruction_of_Public_Key(ctx,gamalist+(n-1),DLCVlist+(n-1),CA_pub,pub0,DLCVlist,gamalist,pubn,n-1);
    }
    
    
    /* 坐标变换 */
    secp256k1_gej_set_ge(&CA_pubj, CA_pub);
    secp256k1_gej_set_ge(&pubj, gama);
    /* 实现e×gama 最后一个参数设置为0常量 */
    secp256k1_ecmult(&tmp, &pubj, &e, &zero);
    secp256k1_gej_add_var(&pubj,&tmp,&CA_pubj,secp256k1_gej_is_infinity(&tmp) ? NULL : &zr);
    secp256k1_ge_set_gej(pubn, &pubj);
    /* CA公钥则需要变化 */
    *CA_pub = *pubn;


    secp256k1_gej_clear(&pubj);
    secp256k1_gej_clear(&tmp);
    secp256k1_gej_clear(&CA_pubj);
    secp256k1_scalar_clear(&e);
    secp256k1_fe_clear(&zr);
    return ;

}


/**
 * @description: 重构公钥 不采用递归
 * @param {secp256k1_ge} *pub0 第0层的公钥
 * @param {secp256k1_scalar} *DLCVlist TCI值列表
 * @param {secp256k1_ge} *gamalist gama值列表
 * @param {secp256k1_ge} *pubn 重构出来的设备第n层的公钥
 * @param {int} n  设备除硬件层以外的层数 具体值示调用而定
 * @return {*}
 */
static void Recursive_Reconstruction_of_Public_Key2(const secp256k1_ecmult_gen_context *ctx,const secp256k1_ge *pub0,
const secp256k1_scalar *DLCVlist,const secp256k1_ge *gamalist,secp256k1_ge *pubn,int n){
    secp256k1_gej pubj;
    secp256k1_gej tmp;
    secp256k1_gej CA_pubj;

    secp256k1_scalar e;
    secp256k1_sha256 hasher;
    secp256k1_fe zr;
    int overflow = 0;
    unsigned char gama_char[64];
    unsigned char dlcv_char[32];
    unsigned char output_hash[32];
    static const secp256k1_scalar zero = SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 0);
    /* 构造公钥 有n个式子e*gama 都是哈希*/
    secp256k1_gej_set_ge(&CA_pubj, pub0);
    for (int i = 0; i < n; i++)
    {
        /* 将gama和dlcv转成字符形式 */
        secp256k1_ge_to_char(gama_char, gamalist+i);
        secp256k1_scalar_get_b32(dlcv_char, DLCVlist+i);
        /* 计算hash（gama，dlcv） */
        secp256k1_sha256_initialize(&hasher);
        secp256k1_sha256_write(&hasher, gama_char, sizeof(gama_char));
        secp256k1_sha256_write(&hasher, dlcv_char, sizeof(dlcv_char));
        secp256k1_sha256_finalize(&hasher, output_hash);
        /* e=hash（gama，dlcv） */
        secp256k1_scalar_set_b32(&e, output_hash, &overflow);
        VERIFY_CHECK(overflow == 0);
        /* 坐标变换 */
        secp256k1_gej_set_ge(&pubj, gamalist+i);
        /* 实现e×gama 最后一个参数设置为0常量 */
        secp256k1_ecmult(&tmp, &pubj, &e, &zero);
        /* 实现相加 */
        secp256k1_gej_add_var(&pubj,&tmp,&CA_pubj,secp256k1_gej_is_infinity(&tmp) ? NULL : &zr);
        CA_pubj = pubj;
    }
    secp256k1_ge_set_gej(pubn, &pubj);

    secp256k1_gej_clear(&pubj);
    secp256k1_gej_clear(&tmp);
    secp256k1_gej_clear(&CA_pubj);
    secp256k1_scalar_clear(&e);
    secp256k1_fe_clear(&zr);
    return ;

}

/**
 * @description: 设备初始化 硬件层所做工作
 * @param {secp256k1_ecmult_gen_context} *ctx
 * @param {secp256k1_scalar} *d 每个设备的机密随机数
 * @param {secp256k1_scalar} *C0 第0层部件特征度量值
 * @param {secp256k1_scalar} *DLCV0 第0层DLCV
 * @param {secp256k1_scalar} *seckey0 第0层私钥
 * @param {secp256k1_ge} *pub0 第0层公钥 由设备制造商签发证书
 * @return {*}
 */
static void HardwareLayer_device_startup_process(const secp256k1_ecmult_gen_context *ctx,const secp256k1_scalar *d,
const secp256k1_scalar *C0,secp256k1_scalar *DLCV0,secp256k1_scalar *seckey0,secp256k1_ge *pub0){
    /* 首先计算下一层DLCV值 由DLCV_n_1和Cn联合得出 */
     unsigned char d_char[32];
    unsigned char tmp_char[32];
    unsigned char out[32];
    secp256k1_gej pubj;
    secp256k1_hmac_sha256 hmac_hash;
    secp256k1_sha256 hasha;
    int overflow = 0;
    secp256k1_scalar_get_b32(d_char,d);
    secp256k1_scalar_get_b32(tmp_char, C0);
     /* 使用Hmac计算 */
    static const char *keys = "\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";
    secp256k1_hmac_sha256_initialize(&hmac_hash,keys,strlen(keys));
    secp256k1_hmac_sha256_write(&hmac_hash,d_char,sizeof(d_char));
    secp256k1_hmac_sha256_write(&hmac_hash,tmp_char,sizeof(tmp_char));
    secp256k1_hmac_sha256_finalize(&hmac_hash,out);
    /* 得到第0层的DLCV */
    secp256k1_scalar_set_b32(DLCV0, out, &overflow);
    VERIFY_CHECK(overflow == 0);
    secp256k1_scalar_get_b32(tmp_char, DLCV0);
    /* 确定性密钥推导函数生成私钥*/
    secp256k1_sha256_initialize(&hasha);
    secp256k1_sha256_write(&hasha, tmp_char, sizeof(tmp_char));
    secp256k1_sha256_finalize(&hasha,out);
    /* 得到第0层私钥 */
    secp256k1_scalar_set_b32(seckey0, out, &overflow);
    VERIFY_CHECK(overflow == 0);
    secp256k1_ecmult_gen(ctx,&pubj,seckey0);
    secp256k1_ge_set_gej(pub0, &pubj);
    secp256k1_gej_clear(&pubj);
    return ;
}


/**
 * @description: 设备初始化 全部使用隐式证书 该函数不需要了
 * @param {secp256k1_ecmult_gen_context} *ctx
 * @param {secp256k1_scalar} *capriv CA的私钥
 * @param {secp256k1_scalar} *d 每个设备的机密随机数
 * @param {secp256k1_scalar} *C0 第0层部件特征度量值
 * @param {secp256k1_scalar} *DLCV0 第0层DLCV
 * @param {secp256k1_ge} gama0 第0层gama值
 * @param {secp256k1_scalar} *seckey0 第0层私钥
 * @return {*}
 */
// static int HardwareLayer_device_startup_process3(const secp256k1_ecmult_gen_context *ctx,const secp256k1_scalar *CApri,const secp256k1_scalar *d,
// const secp256k1_scalar *C0,secp256k1_scalar *DLCV0,secp256k1_ge *gama0,secp256k1_scalar *seckey0){
//     /* 首先计算下一层DLCV值 由DLCV_n_1和Cn联合得出 */
//      unsigned char d_char[32];
//     unsigned char tmp_char[32];
//     unsigned char out[32];
//     secp256k1_gej pubj;
//     secp256k1_hmac_sha256 hmac_hash;
//     secp256k1_sha256 hasha;
//     secp256k1_scalar nonce1,nonce2;
//     int overflow = 0;
//     secp256k1_scalar_get_b32(d_char,d);
//     secp256k1_scalar_get_b32(tmp_char, C0);
//      /* 使用Hmac计算 */
//     static const char *keys = "\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";
//     secp256k1_hmac_sha256_initialize(&hmac_hash,keys,strlen(keys));
//     secp256k1_hmac_sha256_write(&hmac_hash,d_char,sizeof(d_char));
//     secp256k1_hmac_sha256_write(&hmac_hash,tmp_char,sizeof(tmp_char));
//     secp256k1_hmac_sha256_finalize(&hmac_hash,out);
//     /* 得到第0层的DLCV */
//     secp256k1_scalar_set_b32(DLCV0, out, &overflow);
//     VERIFY_CHECK(overflow == 0);
//     secp256k1_scalar_get_b32(tmp_char, DLCV0);

//     /* 以下过程作为与制造商的交互过程 */
//     /* 确定性密钥推导函数生成随机数 一个用hash 一个用hmac*/
//     secp256k1_sha256_initialize(&hasha);
//     secp256k1_sha256_write(&hasha, tmp_char, sizeof(tmp_char));
//     secp256k1_sha256_finalize(&hasha,out);
//     /* 得到第一个随机数 */
//     secp256k1_scalar_set_b32(&nonce1, out, &overflow);
//     VERIFY_CHECK(overflow == 0);
//     /* HMAC */
//     // static const char *keys2 = "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f";
//     // secp256k1_hmac_sha256_initialize(&hmac_hash,keys2,strlen(keys2));
//     // secp256k1_hmac_sha256_write(&hmac_hash,tmp_char,sizeof(tmp_char));
//     // secp256k1_hmac_sha256_finalize(&hmac_hash,out);
//     /* 得到第二个随机数 */
//     // secp256k1_scalar_set_b32(&nonce2, out, &overflow);
//     // VERIFY_CHECK(overflow == 0);
//     /* 调用函数 生成密钥对和gama值 */
//     int res = Generate_key_pairs_and_gamma_values(ctx,&nonce1,CApri,DLCV0,seckey0,gama0);
//     if(res == 1){
//         /* printf("第0层设备启动成功！\n"); */
//         return 1;
//     }
//     return 0;
// }

/**
 * @description: 假设第0层已有显式证书 即已有公私钥 则第n层启动过程如下：
 * 输入本层dlcv值 以及第n层部件特征数据度量值 由此计算下一层的dlcv值
 * 由一个确定性密钥推导函数得到一个随机数a 对应nonce1
 * 由一个不同于上述确定性密钥推导函数得到一个随机数k 对应于nonce2
 * 还需要本层私钥帮助计算
 * 输出下一层的dlcv
 * @param {secp256k1_ecmult_gen_context} *ctx
 * @param {secp256k1_scalar} *seckey 本层私钥
 * @param {secp256k1_scalar} *DLCV_n_1 本层DLCV
 * @param {secp256k1_scalar} *C_n 下一层的部件特征度量值
 * @param {secp256k1_scalar} *DLCV_n 下一层的DLCV
 * @param {secp256k1_scalar} *seckey2 下一层的私钥
 * @param {secp256k1_ge} *gama 下一层的gama值
 * @return {*}
 */
static int Layer_n_device_startup_process(const secp256k1_ecmult_gen_context *ctx,const secp256k1_scalar *seckey,const secp256k1_scalar *DLCV_n_1,
const secp256k1_scalar *C_n,secp256k1_scalar *DLCV_n,secp256k1_scalar *seckey2,secp256k1_ge *gama){
    /* 首先计算下一层DLCV值 由DLCV_n_1和Cn联合得出 */
    unsigned char DLCV_n_1_char[32];
    unsigned char tmp_char[32];
    unsigned char out[32];
    // secp256k1_hmac_sha256 hmac_hash;
    secp256k1_sha256 hasha;
    secp256k1_scalar nonce1;
    secp256k1_scalar nonce2;
    int overflow = 0;
    secp256k1_scalar_get_b32(DLCV_n_1_char, DLCV_n_1);
    secp256k1_scalar_get_b32(tmp_char, C_n);
    /* 使用hash DLCV=H（DLCV_n_1 ,C_n）*/
    secp256k1_sha256_initialize(&hasha);
    secp256k1_sha256_write(&hasha,DLCV_n_1_char, sizeof(DLCV_n_1_char));
    secp256k1_sha256_write(&hasha,tmp_char, sizeof(tmp_char));
    secp256k1_sha256_finalize(&hasha,out);
    /* 使用Hmac计算 */
    // static const char *keys = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    // secp256k1_hmac_sha256_initialize(&hmac_hash,keys,strlen(keys));
    // secp256k1_hmac_sha256_write(&hmac_hash,DLCV_n_1_char,sizeof(DLCV_n_1_char));
    // secp256k1_hmac_sha256_write(&hmac_hash,tmp_char,sizeof(tmp_char));
    // secp256k1_hmac_sha256_finalize(&hmac_hash,out);
    /* 得到下一层的DLCV */
    secp256k1_scalar_set_b32(DLCV_n, out, &overflow);
    VERIFY_CHECK(overflow == 0);
    secp256k1_scalar_get_b32(tmp_char, DLCV_n);
    /* 确定性密钥推导函数生成随机数 一个用hash*/
    secp256k1_sha256_initialize(&hasha);
    secp256k1_sha256_write(&hasha, tmp_char, sizeof(tmp_char));
    secp256k1_sha256_finalize(&hasha,out);
    /* 得到第一个随机数 */
    secp256k1_scalar_set_b32(&nonce1, out, &overflow);
    VERIFY_CHECK(overflow == 0);
    /* 第二个随机数 随机生成 */
    random_scalar_generation(&nonce2);
    // VERIFY_CHECK(overflow == 0);
    /* 调用函数 生成密钥对和gama值 */
    int res = Generate_key_pairs_and_gamma_values(ctx,&nonce1,&nonce2,seckey,C_n,seckey2,gama);

    secp256k1_scalar_clear(&nonce1);

    if(res == 1){
        /*printf("第n层设备启动成功！\n");*/
        return 1;
    }
    
    return 0;
}

static void Equipment_Certification_Report_clear(Equipment_Certification_Report *data) {
    // memset(data->message,'\0',sizeof(data->message));
    secp256k1_scalar_clear(&data->m);
    /*这样清空只会清空第一个地址的 确定字节数的数据可以不清空 会被覆盖 复制给数组时好像使用了引用而不是复制 如此第一个地址的数据就被清空了
    secp256k1_scalar_clear(data->DLCV);
    secp256k1_ge_clear(data->gama);*/
    // secp256k1_scalar_clear(&data->DLCV_n);
    // secp256k1_ge_clear(&data->gama_n);
    
    secp256k1_scalar_clear(&data->sigd);
    secp256k1_scalar_clear(&data->sigz);
    secp256k1_ge_clear(&data->pubn);
}

static void Equipment_Certification_Report_Print(Equipment_Certification_Report data) {
    /* 打印结构体 */
    printf("设备第n层生成的随机数：");
    printScalar(&data.m,1);
    printf("设备认证签名值d：");
    printScalar(&data.sigd,1);
    printf("设备认证签名值z：");
    printScalar(&data.sigz,1);
    printf("设备第n层的公钥值：");
    printGe(&data.pubn,1);
    
}


#endif