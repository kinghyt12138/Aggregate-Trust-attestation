

#ifndef EXPLICITCERTIFICATE_IMPL_H_
#define EXPLICITCERTIFICATE_IMPL_H_

#include "field.h"
#include "group.h"
#include "ecmult.h"
#include "ecmult_gen.h"
#include "scalar.h"
#include "scalar_impl.h"
#include "ExplicitCertificate.h"


/**
 * 定义新结构体存储验证时设备所需要提交的数据
*/
struct EC_Equipment_Certification_Report_struct
{
    /* data */
    /*设备相关信息*/
    // unsigned char message[100];
    secp256k1_scalar m;
    /*签名值*/
    secp256k1_scalar sigd;
    secp256k1_scalar sigz;
    /* 第n层公钥 */
    secp256k1_ge pubn;
};


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
static void HardwareLayer_device_startup_process2(const secp256k1_ecmult_gen_context *ctx,const secp256k1_scalar *d,
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
 * @description: 假设第0层已有显式证书 即已有公私钥 则第n层启动过程如下：
 * 输入本层dlcv值 以及第n层部件特征数据度量值 由此计算下一层的dlcv值
 * 由下一层的DLCV值得到下一层的私钥
 * 输出下一层的dlcv
 * @param {secp256k1_ecmult_gen_context} *ctx
 * @param {secp256k1_scalar} *seckey 本层私钥
 * @param {secp256k1_scalar} *DLCV_n_1 本层DLCV
 * @param {secp256k1_scalar} *C_n 下一层的部件特征度量值
 * @param {secp256k1_scalar} *DLCV_n 下一层的DLCV
 * @param {secp256k1_scalar} *seckey2 下一层的私钥
 * @param {int}设备标识和设备层数 为了标识证书用
 * @return {*}
 */
void Layer_n_device_startup_process2(const secp256k1_ecmult_gen_context *ctx,const secp256k1_scalar *seckey,const secp256k1_scalar *DLCV_n_1,
const secp256k1_scalar *C_n,secp256k1_scalar *DLCV_n,secp256k1_scalar *seckey2,secp256k1_ge *pub_n){
    /* 首先计算下一层DLCV值 由DLCV_n_1和Cn联合得出 */
    unsigned char DLCV_n_1_char[32];
    unsigned char tmp_char[32];
    unsigned char out[32];
    secp256k1_sha256 hasher;
    // secp256k1_hmac_sha256 hmac_hash;
    secp256k1_gej pubj;
    int overflow = 0;
    secp256k1_scalar_get_b32(DLCV_n_1_char, DLCV_n_1);
    secp256k1_scalar_get_b32(tmp_char, C_n);
    /* 使用hash计算 */
    secp256k1_sha256_initialize(&hasher);
    secp256k1_sha256_write(&hasher,DLCV_n_1_char,sizeof(DLCV_n_1_char));
    secp256k1_sha256_write(&hasher,tmp_char,sizeof(tmp_char));
    secp256k1_sha256_finalize(&hasher,out);
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
    /* hash计算下一层私钥 */
    secp256k1_sha256_initialize(&hasher);
    secp256k1_sha256_write(&hasher,tmp_char,sizeof(tmp_char));
    secp256k1_sha256_finalize(&hasher,out);
    /* HMAC计算下一层私钥 */
    // static const char *keys2 = "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f";
    // secp256k1_hmac_sha256_initialize(&hmac_hash,keys2,strlen(keys2));
    // secp256k1_hmac_sha256_write(&hmac_hash,tmp_char,sizeof(tmp_char));
    // secp256k1_hmac_sha256_finalize(&hmac_hash,out);
    /* 私钥 */
    secp256k1_scalar_set_b32(seckey2, out, &overflow);
    VERIFY_CHECK(overflow == 0);
    secp256k1_ecmult_gen(ctx,&pubj,seckey2);
    secp256k1_ge_set_gej(pub_n, &pubj);
    secp256k1_gej_clear(&pubj);
    return;
}



static void EC_Equipment_Certification_Report_clear(EC_Equipment_Certification_Report *data) {
    secp256k1_scalar_clear(&data->m);
    secp256k1_scalar_clear(&data->sigd);
    secp256k1_scalar_clear(&data->sigz);
    secp256k1_ge_clear(&data->pubn);
}

static void EC_Equipment_Certification_Report_Print(EC_Equipment_Certification_Report data) {
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