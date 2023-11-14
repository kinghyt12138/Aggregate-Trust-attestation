

#ifndef EXPLICITCERTIFICATE_H_
#define EXPLICITCERTIFICATE_H_

#include "group.h"
#include "ecmult.h"
#include "scalar.h"
/**
 * 模拟硬件层启动
*/
static void HardwareLayer_device_startup_process2(const secp256k1_ecmult_gen_context *ctx,const secp256k1_scalar *d,
const secp256k1_scalar *C0,secp256k1_scalar *DLCV0,secp256k1_scalar *seckey0,secp256k1_ge *pub0);
/**
 * 模拟可更新固件层的启动
*/
 void Layer_n_device_startup_process2(const secp256k1_ecmult_gen_context *ctx,const secp256k1_scalar *seckey,const secp256k1_scalar *DLCV_n_1,
const secp256k1_scalar *C_n,secp256k1_scalar *DLCV_n,secp256k1_scalar *seckey2,secp256k1_ge *pub_n);


typedef struct EC_Equipment_Certification_Report_struct EC_Equipment_Certification_Report;
/*清空结构体函数*/
static void EC_Equipment_Certification_Report_clear(EC_Equipment_Certification_Report *data);
/* 结构体打印 */
static void EC_Equipment_Certification_Report_Print(EC_Equipment_Certification_Report data);

#endif 

















