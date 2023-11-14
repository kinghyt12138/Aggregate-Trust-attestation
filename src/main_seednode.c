#if defined HAVE_CONFIG_H
#include "libsecp256k1-config.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "secp256k1.c"
#include "../include/secp256k1.h"
#include "../include/secp256k1_preallocated.h"
#include "testrand_impl.h"
#include "checkmem.h"
#include "util.h"
#include "../contrib/lax_der_parsing.c"
#include "../contrib/lax_der_privatekey_parsing.c"
#include "modinv32_impl.h"

#ifdef SECP256K1_WIDEMUL_INT128
#include "modinv64_impl.h"
#include "int128_impl.h"
#endif

#include <sys/types.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/syscall.h> 

/*引入openssl*/
#include<openssl/x509.h>
#include<openssl/ec.h>
#include<openssl/pem.h>
#include<openssl/bn.h>
/* gossip协议 */
#include<poll.h>
#include<pittacus/gossip.h>
#include<pittacus/config.h>
/* json数据 */
#include<stdbool.h>
#include "cJSON.h"

/* 全局变量 */
static int COUNT = 2;
static secp256k1_context *CTX = NULL;
static secp256k1_context *STATIC_CTX = NULL;
static int fd = -1;
clock_t start1;
static void randombytes_fallback(unsigned char *x, size_t xlen)
{
  int i;

  if (fd == -1) {
    for (;;) {
      fd = open("/dev/urandom",O_RDONLY);
      if (fd != -1) break;
      sleep(1);
    }
  }

  while (xlen > 0) {
    if (xlen < 1048576) i = xlen; else i = 1048576;

    i = read(fd,x,i);
    if (i < 1) {
      sleep(1);
      continue;
    }

    x += i;
    xlen -= i;
  }
}
static void random_scalar_order_test(secp256k1_scalar *num) {
    do {
        unsigned char b32[32];
        int overflow = 0;
        secp256k1_testrand256_test(b32);
        secp256k1_scalar_set_b32(num, b32, &overflow);
        if (overflow || secp256k1_scalar_is_zero(num)) {
            continue;
        }
        break;
    } while(1);
}

void randombytes(unsigned char *buf,size_t buflen)
{
  size_t d = 0;
  int r;

  while(d<buflen)
  {
    r = syscall(SYS_getrandom, buf, buflen, 0);
    if(r < 0)
    {
      randombytes_fallback(buf, buflen);
      return;
    }
    buf += r;
    d += r;
  }
}

void random_scalar_generation(secp256k1_scalar *num) {
    do {
        unsigned char b32[32];
        int overflow = 0;
        randombytes(b32, 32);


        secp256k1_scalar_set_b32(num, b32, &overflow);
        if (overflow || secp256k1_scalar_is_zero(num)) {
            continue;
        }
        break;
    } while(1);
}

static void random_scalar_order(secp256k1_scalar *num) {
    do {
        unsigned char b32[32];
        int overflow = 0;
        secp256k1_testrand256(b32);
        secp256k1_scalar_set_b32(num, b32, &overflow);
        if (overflow || secp256k1_scalar_is_zero(num)) {
            continue;
        }
        break;
    } while(1);
}

void random_gamma_sign(secp256k1_scalar *sigr, secp256k1_scalar *sigs, const secp256k1_scalar *key, const secp256k1_scalar *msg, int *recid) {
    secp256k1_scalar nonce;
    do {
        random_scalar_generation(&nonce);
        /*gama签名*/
    } while(!secp256k1_gamma_sig_sign(&CTX->ecmult_gen_ctx, sigr, sigs, key, msg, &nonce, recid));


     //secp256k1_scalar nonce;

    /*固定随机数*/
    // unsigned char nonce_char[32]={0xff,0xff,0xff,0xff,0xff,0x7f,0x00,0x00,0x00,0x00,0xe0,0xff,0xff,0x1f,
    // 0x00,0x00,0x80,0xef,0xff,0xff,0xff,0x7f,0x00,0x00,0x00,0x80,0xff,0xff,0xff,0xff,0xff,0xff};
    // int overflow = 0;

    // do {
    //     /*random_scalar_generation(&nonce);*/
    //     secp256k1_scalar_set_b32(&nonce, nonce_char, &overflow);
    //      VERIFY_CHECK(overflow == 0);
    //     /*gama签名*/
    // } while(!secp256k1_gamma_sig_sign(&CTX->ecmult_gen_ctx, sigr, sigs, key, msg, &nonce, recid));
}

/* 格式转换函数 */
/* 二进制转16进制 */
void bin2hex(unsigned char *bin,char *hex,int binlength) {
	int i = 0;
	int j = 0;
	for (i = 0,j = 0; i < binlength; i++, j+=2) {
		sprintf((char*)(hex + j), "%02x", bin[i]);
	}
}

int hexcharToInt(char c)
{
	if (c >= '0' && c <= '9') return (c - '0');
	if (c >= 'A' && c <= 'F') return (c - 'A' + 10);
	if (c >= 'a' && c <= 'f') return (c - 'a' + 10);
	return 0;
}

void hex2bin(unsigned char *bin, char *hex, int binlength) {
	int i = 0;
	for (i = 0; i < strlen(hex); i += 2) {
		bin[i / 2] = (char)((hexcharToInt(hex[i]) << 4)
			| hexcharToInt(hex[i + 1]));
	}
}


/* openssl 生成显式证书 申请证书之前需要有证书请求文件 参数是设备第0层私钥和公钥 私钥用于签名 公钥要交给CA签发*/
/*证书请求文件包含用户信息 公钥 可选的一些属性 并使用私钥对其进行了签名
EC_GROUP:ECC算法中的组结构体 里面包含着曲线信息 
EC_POINT：ecc算法中的点结构体，里面有x，y，z三个值来确地曲线上的一个点
EC_KEY：ecc算法中的秘钥结构体，里面包含私钥、公钥、曲线信息
*/
int Generate_certificate_equest_file_and_Generate_X509(int deviceID,secp256k1_scalar *priv0,secp256k1_ge *pub0){
      /*证书请求变量 该结构为证书申请信息，req_info为信息主体，sig_alg为签名算法，signature为签名值(申请者对req_info的DER编码值用自己的私钥签名)*/
        X509_REQ *req=NULL;
        int ret;
        long version;
        EVP_PKEY *pkey=NULL;
        /*申请者信息 */
        X509_NAME *name=NULL;
        /* 椭圆曲线密钥 内含公私钥对
             EC curve item: 11 
            NID: 714 此为secp256k1的nid
            Comment: SECG curve over a 256 bit prime field*/
        EC_KEY *key=NULL;
        key = EC_KEY_new();/* 对应要有free */
        /* 首先指定椭圆曲线  */
        EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);/* 对应要有free */
        /* 私钥 bytes in 1 blocks are definitely lost in loss record 84 of 104*/
        BIGNUM *priv_key = BN_new();/* 对应要有free */
        /* 公钥 */
        EC_POINT *pub_key = EC_POINT_new(group);/* free */

        X509_NAME_ENTRY *entry = NULL;
        char bytes[100], mdout[20];
        int len, mdlen;
        int bits = 512;
        const EVP_MD *md;
        X509 *x509=NULL;
        BIO *b=NULL;
        STACK_OF(X509_EXTENSION) * exts;
        /* 初始化证书请求变量 */
        req = X509_REQ_new();/* free */
        version = 1;
        ret = X509_REQ_set_version(req, version);
        /* 初始化申请者信息 */
        name = X509_NAME_new();
		char buffer[80];
		sprintf(buffer, "%s%dxxxx", "device", deviceID);
        strcpy(bytes, buffer);
        len = strlen(bytes);
        entry = X509_NAME_ENTRY_create_by_txt(&entry, "commonName", V_ASN1_UTF8STRING, (unsigned char *)bytes, len);/* bytes in 1 blocks are definitely lost in loss record 85 of 104 */
        X509_NAME_add_entry(name, entry, 0, -1);
        strcpy(bytes, "CN");
        len = strlen(bytes);
        entry = X509_NAME_ENTRY_create_by_txt(&entry, "countryName", V_ASN1_UTF8STRING, (unsigned char *)bytes, len);
        X509_NAME_add_entry(name, entry, 1, -1);
        /* subject name */
        ret = X509_REQ_set_subject_name(req, name);

        /* 私钥 int BN_hex2bn(BIGNUM **a, const char *str);*/
        unsigned char priv_char_temp[32];
        secp256k1_scalar_get_b32(priv_char_temp,priv0);
        char priv_hex[2*sizeof(priv_char_temp)]={'\0'};
        bin2hex(priv_char_temp,priv_hex,sizeof(priv_char_temp));
        /*printf("16进制私钥：%s\n",priv_hex);*/
        ret = BN_hex2bn(&priv_key,priv_hex);
        if(ret == 0){
            printf("BN_hex2bn failed!\n");
            return 0;
        }
        unsigned char pub_char_temp[64];
        secp256k1_ge_to_char(pub_char_temp,pub0);
        char pub_hex[2*sizeof(pub_char_temp)];
        bin2hex(pub_char_temp,pub_hex,sizeof(pub_char_temp));
        char *pub_char = (char *) malloc((strlen("04") + sizeof(pub_hex)+1)*sizeof(char));/* +1预留\0的空间 */
        strcpy(pub_char,"04");
        strcat(pub_char,pub_hex);/* 这里提示invalid write size 1 strcat函数会在复制之后在目标字符串结尾加上\0*/
        /*printf("16进制公钥为：%s\n",pub_char);*/
        /*公钥 */
        BN_CTX *ctx1 = BN_CTX_new();/* free */
        pub_key = EC_POINT_hex2point(group, pub_char, NULL, ctx1);/*提示 Invalid read of size 1 */
        if(pub_key == NULL){
			 printf("EC_POINT_hex2point failed!\n");
			 return 0;
		}
        /* 将公钥私钥和曲线赋值给key */
        ret = EC_KEY_set_group(key, group);
        if(ret != 1){
            printf("EC_KEY_set_group failed!\n");
            return 0;
        }
        ret = EC_KEY_set_private_key(key, priv_key);
        if(ret != 1){
            printf("EC_KEY_set_private_key failed!\n");
            return 0;
        }
        ret = EC_KEY_set_public_key(key, pub_key);
        if(ret != 1){
            printf("EC_KEY_set_public_key failed!\n");
            return 0;
        }
        /* 检验一下密钥对是否配对 */
        ret = EC_KEY_check_key(key);
        if(ret != 1){
            printf("EC_KEY_check_key failed!\n");
            return 0;
        }
        pkey = EVP_PKEY_new();/* free */
        EVP_PKEY_assign_EC_KEY(pkey,key);

        ret = X509_REQ_set_pubkey(req, pkey);
        if(ret != 1){
            printf("X509_REQ_set_pubkey failed!\n");
            return 0;
        }
        /* attribute */
        strcpy(bytes, "HUBEI");
        len = strlen(bytes);
        ret = X509_REQ_add1_attr_by_txt(req, "StateOrProvinceName", V_ASN1_UTF8STRING, (unsigned char *)bytes, len);
        strcpy(bytes, "WUHAN");
        len = strlen(bytes);
        ret = X509_REQ_add1_attr_by_txt(req, "LocalityName", V_ASN1_UTF8STRING, (unsigned char *)bytes, len);
        strcpy(bytes, "Equipment manufacturer");
        len = strlen(bytes);
        ret = X509_REQ_add1_attr_by_txt(req, "OrganizationName", V_ASN1_UTF8STRING, (unsigned char *)bytes, len);
        strcpy(bytes, "Equipment manufacturerCA");
        len = strlen(bytes);
        ret = X509_REQ_add1_attr_by_txt(req, "OrganizationalUnitName", V_ASN1_UTF8STRING, (unsigned char *)bytes, len);
        md = EVP_sha1();
        ret = X509_REQ_digest(req, md, (unsigned char *)mdout, &mdlen);
        ret = X509_REQ_sign(req, pkey, md);
        if (!ret)
        {
                 printf("sign err!\n");
                 X509_REQ_free(req);
                 return 0;
        }
        /* 写入文件PEM格式 */
        char filename[50];
        sprintf(filename, "./pem/certreq%d.txt",deviceID);
        b = BIO_new_file(filename, "w");
        PEM_write_bio_X509_REQ(b, req);
        BIO_free(b);
        OpenSSL_add_all_algorithms();
        ret=X509_REQ_verify(req,pkey);
        if(ret<0){
            printf("verify err.\n");
            return 0;
        }
        /* 按一定的顺序free掉 在free掉一个对象之前需要先free掉与其相关的对象 */
        BN_free(priv_key);
        priv_key = NULL;
        BN_CTX_free(ctx1);
        ctx1 = NULL;
        EC_POINT_clear_free(pub_key);
        pub_key = NULL;
        EC_GROUP_free(group);
        group = NULL;
        EVP_PKEY_free(pkey); 
        //X509_NAME_free(name);
        X509_REQ_free(req);
        pkey = NULL;
        name=NULL;
        req=NULL;
		/* printf("生成请求文件结束！！！\n"); */
        /* 执行生成证书命令 openssl x509 -req -in cert.csr -out child.crt -CA root.crt -CAkey root.key -CAcreateserial >>./pem/out.txt 2>&1*/
        char cmd[200];
		sprintf(cmd, "openssl x509 -req -in ./pem/certreq%d.txt -out ./pem/crt/device%d.crt -CA ./pem/crt/root.crt -CAkey ./pem/crt/root.key -CAcreateserial", deviceID, deviceID);
        int ret2 = -1; 
        while(ret2 !=0){
            ret2 = system(cmd);
        }
        /* 生成证书后删除证书请求文件 */
        sprintf(cmd,"rm %s",filename);
        system(cmd);
        free(pub_char);
        pub_char = NULL;
        
        
        
        return 1;
}



int Extract_public_key_from_certificate(int deviceID,secp256k1_ge *pub0){
    /* 首先需要验证证书：
    openssl verify -verbose -CAfile ./pem/root.crt ./pem/deviceXX.crt
    输出child.crt: OK */
    char cmd[100];
    sprintf(cmd, "%s%d.crt", "openssl verify -verbose -CAfile ./pem/crt/root.crt ./pem/crt/device", deviceID);
    system(cmd);
    /* printf("证书验证完毕\n"); */
    
    char filename[50];
    sprintf(filename, "%s%d.crt", "./pem/crt/device", deviceID);
    
    /*  printf("filename:%s\n",filename);*/
    
    FILE *fp = fopen(filename, "r");
    if(fp == NULL){
        printf("file open failed！\n");
        return 0;
    }
    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    EVP_PKEY *pkey = X509_get_pubkey(cert);
	if(pkey == NULL){
		printf("提取公钥失败\n");
        return 0;
	}
	/* 转为字符形式 */
    EC_KEY *key = EVP_PKEY_get1_EC_KEY(pkey);
	if(key == NULL){
		printf("EVP_PKEY_get1_EC_KEY  failed！\n");
        return 0;
	}
	const EC_POINT *point = EC_KEY_get0_public_key(key);
	if(point == NULL){
		printf("EC_KEY_get0_public_key  failed！\n");
        return 0;
	}
	char* pubchar_temp = EC_POINT_point2hex(EC_KEY_get0_group(key),point,POINT_CONVERSION_UNCOMPRESSED,NULL);
   /*  printf("提取公钥为%s\n",pubchar_temp); */
    /* 需要将字符转为secp256k1_ge形式 */
    //secp256k1_ge_to_char();
    /*有一个load函数来加载公钥 而secp256k1_pubkey就是一个64位的字符数组
    static int secp256k1_pubkey_load(const secp256k1_context* ctx, secp256k1_ge* ge, const secp256k1_pubkey* pubkey)
     secp256k1_fe x, y;
        secp256k1_fe_set_b32(&x, pubkey->data);
        secp256k1_fe_set_b32(&y, pubkey->data + 32);
        secp256k1_ge_set_xy(ge, &x, &y);
     */
    /* 将16进制转为字符串 */
    char pubchar[128];
    strcpy(pubchar,pubchar_temp+2);
    /* printf("去掉前缀，提取公钥为%s\n",pubchar); */
    unsigned char binchar[sizeof(pubchar)/2];
    hex2bin(binchar,pubchar,sizeof(binchar));
    /* printf("提取的公钥bin格式为：");
    printChar(binchar,sizeof(binchar)); */
    secp256k1_fe x, y;
    secp256k1_fe_set_b32(&x,binchar);
    secp256k1_fe_set_b32(&y, binchar + 32);
    secp256k1_ge_set_xy(pub0, &x, &y);
    /* printf("提取的公钥ge格式为：");
    printGe(pub0,1); */
    return 1;

}

void Verification_certificate(int deviceID){
    /* 验证证书：
    openssl verify -verbose -CAfile ./pem/root.crt ./pem/deviceXX.crt
    输出child.crt: OK */
    char cmd[100];
    sprintf(cmd, "%s%d.crt", "openssl verify -verbose -CAfile ./pem/crt/root.crt ./pem/crt/device", deviceID);
    system(cmd);
    /* printf("证书验证完毕\n"); */
}
/* 隐式证书测试 */
void test_Implicitertificate(void){
    secp256k1_scalar nonce1,nonce2,seckey1,seckey2,DLCV;
    secp256k1_ge gama;
    random_scalar_order_test(&nonce1);
    random_scalar_order_test(&nonce2);
    random_scalar_order_test(&seckey1);
    random_scalar_order_test(&seckey2);
    random_scalar_order_test(&DLCV);
    int ret = Generate_key_pairs_and_gamma_values(&CTX->ecmult_gen_ctx,&nonce1,&nonce2,&seckey1,&DLCV,&seckey2,&gama);
    if(ret == 1){
        printf("密钥和gama值生成成功！\n");
    }

    /* 隐式证书验证 */
    secp256k1_scalar message;
    secp256k1_scalar sigr,sigs;
    int recid;
    int getrec;
    secp256k1_ge CA_pub,pub,pub2;
    secp256k1_gej CA_pubj,pubj,pub2j;
    random_scalar_order_test(&message);
    secp256k1_ecmult_gen(&CTX->ecmult_gen_ctx, &CA_pubj, &seckey1);
    secp256k1_ecmult_gen(&CTX->ecmult_gen_ctx, &pub2j, &seckey2);
    secp256k1_ge_set_gej(&CA_pub, &CA_pubj);
    secp256k1_ge_set_gej(&pub2, &pub2j);
    ImplicitCertificate_Verify(&CTX->ecmult_gen_ctx,&gama,&DLCV,&CA_pub,&pub);
    secp256k1_gej_set_ge(&pubj, &pub);
    if(secp256k1_gej_eq_var(&pubj,&pub2j)){
        printf("重构出来的公钥与之前一致！\n");
    }

/* 使用gama签名验证测试一下 */
    if (getrec) {
        /*  random_sign(&sigr, &sigs, &seckey2, &message, &recid); */
        random_gamma_sign(&sigr, &sigs, &seckey2, &message, &recid);
        CHECK(recid >= 0 && recid < 4);
    } else {
        random_gamma_sign(&sigr, &sigs, &seckey2, &message, NULL);
        /* random_sign(&sigr, &sigs, &seckey2, &message, NULL); */
    }
    /* int res = secp256k1_ecdsa_sig_verify(&sigr, &sigs, &pub, &message); */
    int res = secp256k1_gamma_sig_verify(&sigr, &sigs, &pub, &message);

    if(res == 1){
        printf("隐式证书验证成功！\n");
    }else{
        printf("隐式证书验证失败！\n");
    }
    return ;
}
/*模拟设备启动测试*/
void Device_nlayer_startup_test(void){
    /* 每个设备的机密随机数d */
    secp256k1_scalar d;
    random_scalar_order(&d);
    /* 第0层部件特征数据 */
    secp256k1_scalar C0;
    random_scalar_order(&C0);
    /* 第0层的DLCV值 */
    secp256k1_scalar DLCV0;
    secp256k1_scalar seckey0;
    secp256k1_ge pub0;
    HardwareLayer_device_startup_process(&CTX->ecmult_gen_ctx,&d,&C0,&DLCV0,&seckey0,&pub0);
    /* printf("设备初始化完毕！\n"); */
    
    /**
     * 假设设备是0-9层
     * 需要保存的东西有 第1层到第9层的DLCV和gama
    */
   secp256k1_scalar DLCV[9];
   secp256k1_ge gama[9];
   secp256k1_scalar tempseckey = seckey0;
   secp256k1_scalar tempDLCV = DLCV0;
    for(int i = 1;i<10;i++){
        printf("第%d层开始启动！\n",i);
         /* 下一层的度量值 C_n*/
        secp256k1_scalar C_i;
        random_scalar_order(&C_i);
        /*下一层的DLCV */
        secp256k1_scalar DLCV_i;
        /* 下一层私钥 */
        secp256k1_scalar seckeyi;
        /* 下一层gama值 */
        secp256k1_ge gamai;
        int res = Layer_n_device_startup_process(&CTX->ecmult_gen_ctx,&tempseckey,&tempDLCV,&C_i,&DLCV_i,&seckeyi,&gamai);
        /* 保存DLCV值和gama值 */
        DLCV[i-1] = DLCV_i;
        gama[i-1] = gamai;
        /* 更新temp值 */
        tempseckey = seckeyi;
        tempDLCV = DLCV_i;
        printf("第%d层启动完毕！\n",i);
    }
    /* 最后的tempseckey是第n层私钥 即用于给设备信息签名的私钥 */
    unsigned char *messagechar = "DM:test;DV:1.0;DCI:testtest";
    unsigned char dnum_char[32];
    unsigned char out[32];
    secp256k1_sha256 hasha;
    secp256k1_scalar message,sigr,sigs;
    int overflow = 0;
    int getrec;
    int recid;
    /* 随机数dum */
    secp256k1_scalar dnum;
    random_scalar_order(&dnum);
    secp256k1_scalar_get_b32(dnum_char,&dnum);
    /* 整成scalar类型 */
    secp256k1_sha256_initialize(&hasha);
    secp256k1_sha256_write(&hasha,messagechar,strlen(messagechar));
    secp256k1_sha256_write(&hasha,dnum_char,sizeof(dnum_char));
    secp256k1_sha256_finalize(&hasha,out);
    secp256k1_scalar_set_b32(&message,out,&overflow);
    VERIFY_CHECK(overflow == 0);
    /* 签名 */
    /* 使用gama签名验证测试一下 */
    if (getrec) {
        random_gamma_sign(&sigr, &sigs, &tempseckey, &message, &recid);
        CHECK(recid >= 0 && recid < 4);
    } else {
        random_gamma_sign(&sigr, &sigs, &tempseckey, &message, NULL);
    }
    /* 重构公钥 已知第0层的公钥的情况下 pub0 需要构造1-9层的公钥*/
    secp256k1_ge CA_pub;
    secp256k1_ge pubn;
    int n=8;
    Recursive_Reconstruction_of_Public_Key(&CTX->ecmult_gen_ctx,gama+n,DLCV+n,&CA_pub,&pub0,DLCV,gama,&pubn,n);
/*
    secp256k1_gej pubnj;
    secp256k1_ge pubn2;
    secp256k1_ecmult_gen(&CTX->ecmult_gen_ctx,&pubnj,&tempseckey);
    secp256k1_ge_set_gej(&pubn2,&pubnj);
    printf("重构公钥前后对比！");
    printGe(&pubn,1);
    printGe(&pubn2,1);*/

    int res = secp256k1_gamma_sig_verify(&sigr, &sigs, &pubn, &message);
    if(res !=1 ){
        printf("单个设备验证失败！\n");
        return ;
    }
    

    return;
}
/*模拟设备网络验证 此函数用于设备生成验证报告 需要参数来记录验证时所需要的信息*/
// void Single_device_startup_simulation(int deviceID,Equipment_Certification_Report *data){
//     /* 每个设备的机密随机数d */
//     secp256k1_scalar d;
//     random_scalar_order(&d);
//     /* 第0层部件特征数据 */
//     secp256k1_scalar C0;
//     random_scalar_order(&C0);
//     /* 第0层的DLCV值 */
//     secp256k1_scalar DLCV0;
//     secp256k1_scalar seckey0;
//     secp256k1_ge pub0;
//     HardwareLayer_device_startup_process(&CTX->ecmult_gen_ctx,&d,&C0,&DLCV0,&seckey0,&pub0);
//     /* 输出一下私钥和公钥： */
//    /*  printScalar(&seckey0,1);
//     printGe(pub0,1); */

//     /*由制造商签发显式证书*/
//     int ret = Generate_certificate_equest_file_and_Generate_X509(deviceID,&seckey0,&pub0);
//     if(ret!=1){
//         printf("Generate_certificate_equest_file_and_Generate_X509 failed\n");
//     }
//    /*  printf("设备初始化完毕！\n"); */
//     /**
//      * 假设设备是0-9层
//      * 需要保存的东西有 第1层到第9层的DLCV和gama
//      *    secp256k1_scalar DLCV[9];
//      *    secp256k1_ge gama[9];
//     */
//    secp256k1_scalar tempseckey = seckey0;
//    secp256k1_scalar tempDLCV = DLCV0;
//     for(int i = 1;i<10;i++){
//         /*printf("第%d层开始启动！\n",i);*/
//          /* 下一层的度量值 C_n*/
//         secp256k1_scalar C_i;
//         random_scalar_order(&C_i);
//         /*下一层的DLCV */
//         secp256k1_scalar DLCV_i;
//         /* 下一层私钥 */
//         secp256k1_scalar seckeyi;
//         /* 下一层gama值 */
//         secp256k1_ge gamai;
//         int res = Layer_n_device_startup_process(&CTX->ecmult_gen_ctx,&tempseckey,&tempDLCV,&C_i,&DLCV_i,&seckeyi,&gamai);
//         /* 保存DLCV值和gama值 */
//         data->DLCV[i-1] = DLCV_i;
//         data->gama[i-1] = gamai;
//         /* 更新temp值 */
//         tempseckey = seckeyi;
//         tempDLCV = DLCV_i;
//         /*printf("第%d层启动完毕！\n",i);*/
//     }
   
//     /* 最后的tempseckey是第n层私钥 即用于给设备信息签名的私钥 */
//     unsigned char *messagechar = "DM:test;DV:1.0;DCI:testtest";
//     /*保存设备信息*/
//     strcpy(data->message,messagechar);
    
//     unsigned char dnum_char[32];
//     unsigned char out[32];
//     secp256k1_sha256 hasha;
//     secp256k1_scalar message,sigr,sigs;
//     int overflow = 0;
//     int getrec;
//     int recid;
//     /* 随机数dum */
//     random_scalar_order(&data->dnum);
//     secp256k1_scalar_get_b32(dnum_char,&data->dnum);
//     /* 整成scalar类型 */
//     secp256k1_sha256_initialize(&hasha);
//     secp256k1_sha256_write(&hasha,messagechar,strlen(messagechar));
//     secp256k1_sha256_write(&hasha,dnum_char,sizeof(dnum_char));
//     secp256k1_sha256_finalize(&hasha,out);
//     secp256k1_scalar_set_b32(&message,out,&overflow);
//     VERIFY_CHECK(overflow == 0);
//     /* 签名 */
//     /* 使用gama签名验证测试一下 */
//     if (getrec) {
//         random_gamma_sign(&sigr, &sigs, &tempseckey, &message, &recid);
//         CHECK(recid >= 0 && recid < 4);
//     } else {
//         random_gamma_sign(&sigr, &sigs, &tempseckey, &message, NULL);
//     }
//     /*保存签名信息*/
//     data->sigd = sigr;
//     data->sigz = sigs;
    
//     secp256k1_gej pubnj;
//     secp256k1_ge pubn;
//     secp256k1_ecmult_gen(&CTX->ecmult_gen_ctx,&pubnj,&tempseckey);
//     secp256k1_ge_set_gej(&pubn,&pubnj);
//     return;
// }


/*模拟设备网络验证 此函数用于设备生成验证报告 需要参数来记录验证时所需要的信息*/
void Single_device_startup_simulation2(int deviceID,Equipment_Certification_Report *data){
    /* 每个设备的机密随机数d */
    secp256k1_scalar d;
    random_scalar_order(&d);
    /* 第0层部件特征数据 */
    secp256k1_scalar C0;
    random_scalar_order(&C0);
    /* 第0层的DLCV值 */
    secp256k1_scalar DLCV0;
    secp256k1_scalar seckey0;
    secp256k1_ge pub0;
    /* 制造阶段 硬件启动 生成第0层密钥*/
    HardwareLayer_device_startup_process(&CTX->ecmult_gen_ctx,&d,&C0,&DLCV0,&seckey0,&pub0);
    /* 输出一下私钥和公钥： */
   /*  printScalar(&seckey0,1);
    printGe(pub0,1); */

    /*由制造商签发显式证书*/
    int ret = Generate_certificate_equest_file_and_Generate_X509(deviceID,&seckey0,&pub0);
    if(ret!=1){
        printf("Generate_certificate_equest_file_and_Generate_X509 failed\n");
    }
   /*  printf("设备初始化完毕！\n"); */
    /**
     * 假设设备是0-9层
     * 需要保存的东西有 第1层到第9层的DLCV和gama
     *    secp256k1_scalar DLCV[9];
     *    secp256k1_ge gama[9];
    */
   start1 = clock();
   //按照制造阶段的方式生成第0层密钥
   HardwareLayer_device_startup_process(&CTX->ecmult_gen_ctx,&d,&C0,&DLCV0,&seckey0,&pub0);
   //保存第0层的DLCV值
   data->DLCV_0 = DLCV0;
   secp256k1_scalar tempseckey = seckey0;
   secp256k1_scalar tempDLCV = DLCV0;
   //算3层 0 1 2 只有两层gama值
    for(int i = 1;i<3;i++){
        /*printf("第%d层开始启动！\n",i);*/
         /* 下一层的度量值 C_n*/
        secp256k1_scalar C_i;
        random_scalar_order(&C_i);
        /*下一层的DLCV */
        secp256k1_scalar DLCV_i;
        /* 下一层私钥 */
        secp256k1_scalar seckeyi;
        /* 下一层gama值 */
        secp256k1_ge gamai;
        int res = Layer_n_device_startup_process(&CTX->ecmult_gen_ctx,&tempseckey,&tempDLCV,&C_i,&DLCV_i,&seckeyi,&gamai);
        if(res == 0){
            printf("设备启动失败！\n");
        }
        /* 更新temp值 */
        tempseckey = seckeyi;
        tempDLCV = DLCV_i;
        //保存每一层的gamma值
        data->gama_list[i-1] = gamai;
        
    }
   
    /* 最后的tempseckey是第n层私钥 即用于给设备信息签名的私钥 */
    unsigned char *messagechar = "DM:test;DV:1.0;DCI:testtest";
    /*保存设备信息*/
    // strcpy(data->message,messagechar);
    
    unsigned char dnum_char[32];
    unsigned char out[32];
    secp256k1_sha256 hasha;
    secp256k1_scalar message,sigr,sigs,dnum;
    int overflow = 0;
    int getrec = 0;
    int recid;
    /* 随机数dum */
    random_scalar_order(&dnum);
    secp256k1_scalar_get_b32(dnum_char,&dnum);
    /* 整成scalar类型 */
    secp256k1_sha256_initialize(&hasha);
    secp256k1_sha256_write(&hasha,messagechar,strlen(messagechar));
    secp256k1_sha256_write(&hasha,dnum_char,sizeof(dnum_char));
    secp256k1_sha256_finalize(&hasha,out);
    secp256k1_scalar_set_b32(&message,out,&overflow);
    VERIFY_CHECK(overflow == 0);
    data->m = message;
    /* 签名 */
    /* 使用gama签名验证测试一下 */
    if (getrec) {
        random_gamma_sign(&sigr, &sigs, &tempseckey, &message, &recid);
        CHECK(recid >= 0 && recid < 4);
    } else {
        random_gamma_sign(&sigr, &sigs, &tempseckey, &message, NULL);
    }
    /*保存签名信息*/
    data->sigd = sigr;
    data->sigz = sigs;
    
    secp256k1_gej pubnj;
    secp256k1_ge pubn;
    secp256k1_ecmult_gen(&CTX->ecmult_gen_ctx,&pubnj,&tempseckey);
    secp256k1_ge_set_gej(&pubn,&pubnj);
    /* 保存公钥信息 */
    data->pubn = pubn;
    return;
}
/*模拟聚合验证 即多个设备启动并生成验证报告*/
// void Device_Network_Aggregation_Validation_Simulation(void){
//     int num = 100;
//     secp256k1_ge *pub0 = (secp256k1_ge*) malloc (num*sizeof(secp256k1_ge));
//     /*用一个数组保存验证信息*/
//     Equipment_Certification_Report verifyData[num];
//     for(int i = 0;i<num;i++){
//         Equipment_Certification_Report data;
//         /* 设备启动 */
//         Single_device_startup_simulation(i+1,&data);
//         /* 如果DLCVlist和gamalist定义为指针 在赋值时是引用赋值 */
//         verifyData[i] = data;
//     }

//     /*重构每个设备的公钥*/
//     secp256k1_ge CA_pub;
//     secp256k1_ge *pubn = (secp256k1_ge*) malloc (num*sizeof(secp256k1_ge));
//     int layer_num =8;
//     int ret;
//     for(int i = 0;i<num;i++){
//          /* 从显式证书中取出第0层公钥 */
//         ret = Extract_public_key_from_certificate(i+1,pub0+i);
//         if(ret == 0){
//             printf("Extract_public_key_from_certificate failed\n");
//         }
//         /* 根据第0层公钥重构！ */
//         Recursive_Reconstruction_of_Public_Key(&CTX->ecmult_gen_ctx,&verifyData[i].gama[layer_num],&verifyData[i].DLCV[layer_num],
//         &CA_pub,pub0+i,verifyData[i].DLCV,verifyData[i].gama,pubn+i,layer_num);
//     }
//     /*聚合*/
//     secp256k1_ge *outpub = (secp256k1_ge*) malloc (num*sizeof(secp256k1_ge));
//     secp256k1_ge *A = (secp256k1_ge*) malloc (num*sizeof(secp256k1_ge));
//     secp256k1_scalar *msg =  (secp256k1_scalar*) malloc (num*sizeof(secp256k1_scalar));
//     secp256k1_scalar *outmsg =  (secp256k1_scalar*) malloc (num*sizeof(secp256k1_scalar));
//     secp256k1_scalar *sigd =  (secp256k1_scalar*) malloc (num*sizeof(secp256k1_scalar));
//     secp256k1_scalar *sigz =  (secp256k1_scalar*) malloc (num*sizeof(secp256k1_scalar));
//     secp256k1_scalar  sumZ;
//     int recid;
//     int getrec;
//     int i;
//     int overflow=0;
//     int outSize= 0;
//     secp256k1_sha256 hasha;
//     unsigned char dnum_char[32];
//     unsigned char out[32];
//     secp256k1_scalar message;
  
//     //将数据组织成链表形式
//     for(int i = 0;i<num;i++){
//         secp256k1_scalar_get_b32(dnum_char,&(verifyData[i].dnum));
//         /* 整成scalar类型 */
//         secp256k1_sha256_initialize(&hasha);
//         secp256k1_sha256_write(&hasha,verifyData[i].message,strlen(verifyData[i].message));
//         secp256k1_sha256_write(&hasha,dnum_char,sizeof(dnum_char));
//         secp256k1_sha256_finalize(&hasha,out);
//         secp256k1_scalar_set_b32(&message,out,&overflow);
//         VERIFY_CHECK(overflow == 0);
//         *(msg+i)= message;
//         *(sigd+i) = verifyData[i].sigd;
//         *(sigz+i) = verifyData[i].sigz;
//     }

//     /*聚合*/
//     secp256k1_gamma_Agg(pubn, msg, sigd, sigz, num, outpub, outmsg, A, &outSize  ,&sumZ);
//     /* 聚合验证 */
//     int res = secp256k1_gamma_Agg_verify( CTX , &CTX->error_callback,outpub, outmsg, A, outSize, &sumZ);
//       if(res ==1 ){
//         printf("设备网络验证成功\n");
//         return ;
//     }
//     printf("设备网络验证失败！\n");
//     return ;
// }


/***************************************************************节点交互部分**********************************************************/
/* 字符串包含方法  s是否包含c s包含c返回1 */
int is_in(char *s, char *c)
{
    int i=0,j=0,flag=-1;
    while(i<strlen(s) && j<strlen(c)){
        if(s[i]==c[j]){//如果字符相同则两个字符都增加
            i++;
            j++;
        }else{
            i=i-j+1; //主串字符回到比较最开始比较的后一个字符
            j=0;     //字串字符重新开始
        }
        if(j==strlen(c)){ //如果匹配成功
            flag=1;  //字串出现
            break;
        }
    }
    return flag;
}

int is_in_array(int *array,int len,int num){
    for(int i = 0;i<len;i++){
        if(array[i] == num){
            return i;
        }
    }
    return -1;
}


/* gossip协议 */
static int start_port = 11000;
static int node_ID = 10000;
/**
 * 可能发送的四种消息
 * （1）认证请求
 * （2）发送给接收到的第一个认证请求的发送节点 把它当作当前节点的父节点 相当于给父节点说一声
 * （3）设备认证报告 没有子节点的设备发送此种消息
 * （4）聚合报告 有子节点的设备发送此种消息
*/
const char DATA_MESSAGE[] = "Attestation Request!";
const char DATA_MESSAGE2[] = "First receive yours!";
const char DATA_TYPE_1[]="Equipment Certification Report";
const char DATA_TYPE_2[]="Aggregation Report";
const char DATA_TYPE_3[]="Joined cluster";
/* 父节点的ID 每个设备只有一个父节点  */
int father_ID = -1;
/* 子节点的ID数组 每个设备可以有多个子节点 */
int child_ID[100];
bool hasReceived[100]={false};
/* 子节点数目  */
int childNum = 0;
/* 聚合报告的位置索引 */
int Aggindex = 0;
bool hasAGG = false;
/* 已经接收到的设备认证报告的数量 */
int rece_report_num = 0;
/* 涉及多线程 为变量加互斥锁 */
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER; 
/* 是否是第一次接收到认证请求 只对第一次接收到的认证请求做处理 */
bool is_first = true;
/* 是否接收到聚合报告 这决定了聚合的类型 */
bool is_Agg = false;
bool is_first_AGG = true;
/* 是否有子节点 */
bool has_child = false;
/* 子节点的设备认证报告 只装还未聚合过的子节点的设备报告 因为有些子节点可能发送来的是聚合报告*/
Equipment_Certification_Report datalist[100];
/* datalist的长度 聚合时需要使用 */
int datalistnum = 0;
/* datalist中对应的节点的ID */
int datalistID[100];
/* 设备数据包个数 */
int deviceDatanum[100]={0};
/* 已加入集群的节点数 */
int clusterNum = 1;
/* 需要认证的节点数 */
int needReqNum = 0;
/* 聚合需要的参数 */
static secp256k1_ge *outpub = NULL;
static secp256k1_ge *A = NULL;
static secp256k1_scalar *outmsg =  NULL;
static secp256k1_scalar  SumZ;

//bool clusterJoin[100]={false};
/* 存储数据包 */
char data_packet[100][100][420]={""};
bool data_packet_hasRece[100][100]={false};
/* 线程参数 */
typedef struct
{
	int time;
    pittacus_gossip_t *gossip;
}Pt_arg;
pittacus_gossip_t *gossip=NULL;
// cJSON *certArray=NULL;
/* 认证报告结构体转为json数据 */
/**
 * @description: 认证报告结构体转为json数据 通过测试
 * @param {CJSON} *cjson 转换的json对象
 * @param {Equipment_Certification_Report} data 需要转换的认证报告结构体
 * @return {*}
 */

/* 计时 */
clock_t startTime,endTime;
double suTime,aggtime,runtime,dataProcessTime;
/* 存储量 */
long memory_capacity=0;

/* 将证书转为json数据 */
void cert_to_Json(cJSON *cert1,int deviceID){
    char filename[100];
    sprintf(filename,"./pem/crt/device%d.crt",deviceID);
    X509 *cert;
    const char *cert_str = NULL;
    const char *output_file = "cert_output.pem";
    // 从文件中加载证书
    FILE *fp = fopen(filename, "r");
    cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    // 将证书转换为字符串形式
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, cert);
    BUF_MEM *mem = NULL;
    BIO_get_mem_ptr(bio, &mem);
    cert_str = mem->data;
    /* 加入json数据 */
    char certname[100];
    sprintf(certname,"%dcert",deviceID);
    cJSON_AddStringToObject(cert1,certname,cert_str);
    BIO_free(bio);
    X509_free(cert);
}
/* 将json解析为证书 */
void json_to_cert(char *cert_str,int deviceID){
    char filename[100];
    sprintf(filename,"./data/crt/device%d.crt",deviceID);
    X509 *cert;
    // 将字符串转换为X.509证书对象
    BIO *bio = BIO_new_mem_buf(cert_str, -1);
    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    // 验证证书是否成功转换
    if (cert == NULL) {
        printf("Failed to parse certificate\n");
        return 1;
    }
    // 将证书写入文件
    FILE *fp = fopen(filename, "w");
    if (fp == NULL) {
        printf("Failed to open file for writing\n");
        X509_free(cert);
        return 1;
    }
    PEM_write_X509(fp, cert);
    fclose(fp);
    // 释放证书资源
    X509_free(cert);
}

/* 合并两个JSON */
char* mergeJSON(const char* json1, const char* json2) {
    cJSON* root1 = cJSON_Parse(json1);
    cJSON* root2 = cJSON_Parse(json2);
    
    cJSON* merged = cJSON_Duplicate(root1, 1);
    
    cJSON* item = NULL;
    cJSON_ArrayForEach(item, root2) {
        cJSON* existing = cJSON_GetObjectItemCaseSensitive(merged, item->string);
        if (existing != NULL) {
            cJSON_ReplaceItemInObjectCaseSensitive(merged, item->string, cJSON_Duplicate(item->child, 1));
        } else {
            cJSON_AddStringToObject(merged, item->string, item->valuestring);
        }
    }
    
    char* mergedStr = cJSON_PrintUnformatted(merged);
    
    cJSON_Delete(root1);
    cJSON_Delete(root2);
    cJSON_Delete(merged);
    
    return mergedStr;
}

/* 认证报告结构体转为json数据 */
/**
 * @description: 认证报告结构体转为json数据 通过测试
 * @param {CJSON} *cjson 转换的json对象
 * @param {Equipment_Certification_Report} data 需要转换的认证报告结构体
 * @return {*}
 */
void  Report_structure_to_JSON(cJSON *cjson,Equipment_Certification_Report data){
    /* 将数据转为字符串形式存储 */
    unsigned char temp[32];
    unsigned char temp2[64];
    unsigned char char2[128];
    secp256k1_scalar_get_b32(temp, &data.m);
    bin2hex(temp,temp2,sizeof(temp));
    cJSON_AddStringToObject(cjson,"m",temp2);
    /* 第0层DLCV值 */
    // secp256k1_scalar_get_b32(temp, &data.DLCV_0);
    // bin2hex(temp,temp2,sizeof(temp));
    // cJSON_AddStringToObject(cjson,"dlcv_0",temp2);
    /* gama值 */
    cJSON *gammaList = cJSON_CreateArray();
    for (int i = 0; i < 2; i++)
    {
        secp256k1_ge_to_char(temp2, &data.gama_list[i]);
        bin2hex(temp2, char2, sizeof(temp2));
        cJSON_AddStringToObject(gammaList, "", char2);
    }
    cJSON_AddItemToObject(cjson,"gammaList",gammaList);

    // secp256k1_ge_to_char(temp2,&data.gama_n);
    // bin2hex(temp2,char2,sizeof(temp2));
    // cJSON_AddStringToObject(cjson,"gama_n",char2);
    /* 签名值数据 */
    secp256k1_scalar_get_b32(temp,&data.sigd);
    bin2hex(temp,temp2,sizeof(temp));
    cJSON_AddStringToObject(cjson,"sigd",temp2);
    secp256k1_scalar_get_b32(temp,&data.sigz);
    bin2hex(temp,temp2,sizeof(temp));
    cJSON_AddStringToObject(cjson,"sigz",temp2);
    /* 第n层公钥 */
    secp256k1_ge_to_char(temp2,&data.pubn);
    bin2hex(temp2,char2,sizeof(temp2));
    cJSON_AddStringToObject(cjson,"pubn",char2);
    /* 第0层证书 */
    cert_to_Json(cjson,node_ID);
}
/* 解析json数据成报告结构体 通过测试*/
void Json_to_Report_structure(cJSON *cjson,Equipment_Certification_Report *data,int deviceID){
    /* 设备信息 */
    unsigned char tmp1[32];
    unsigned char tmp2[64];
    int overflow = 0;
    char *temp0 = cJSON_GetObjectItem(cjson,"m")->valuestring;
    hex2bin(tmp1,temp0,64);
    secp256k1_scalar_set_b32(&data->m,tmp1,&overflow);
    VERIFY_CHECK(overflow == 0);
    /* 第0层DLCV值 */
    // char *temp1 = cJSON_GetObjectItem(cjson,"dlcv_0")->valuestring;
    // hex2bin(tmp1,temp1,64);
    // secp256k1_scalar_set_b32(&data->DLCV_0,tmp1,&overflow);
    // VERIFY_CHECK(overflow == 0);
    /* gama值 list*/
    secp256k1_fe x,y;
    cJSON *gammaList = cJSON_GetObjectItem(cjson,"gammaList");
    int size = cJSON_GetArraySize(gammaList);
    for(int i = 0;i<size;i++){
        char *temp = cJSON_GetArrayItem(gammaList ,i)->valuestring;
        hex2bin(tmp2,temp,128);
        secp256k1_fe_set_b32(&x,tmp2);
        secp256k1_fe_set_b32(&y, tmp2+32);
        secp256k1_ge_set_xy(&data->gama_list[i], &x, &y);
    }
    
    // char *temp2 = cJSON_GetObjectItem(cjson,"dlcv_n")->valuestring;
    // hex2bin(tmp2,temp2,128);
    // secp256k1_fe_set_b32(&x,tmp2);
    // secp256k1_fe_set_b32(&y, tmp2+32);
    // secp256k1_ge_set_xy(&data->gama_n, &x, &y);
    /* 签名值 */
    char *temp3 = cJSON_GetObjectItem(cjson,"sigd")->valuestring;
    hex2bin(tmp1,temp3,64);
    secp256k1_scalar_set_b32(&data->sigd,tmp1,&overflow);
    VERIFY_CHECK(overflow == 0);
    char *temp4 = cJSON_GetObjectItem(cjson,"sigz")->valuestring;
    hex2bin(tmp1,temp4,64);
    secp256k1_scalar_set_b32(&data->sigz,tmp1,&overflow);
    VERIFY_CHECK(overflow == 0);
    /* 第n层公钥值 */
    char *temp5 = cJSON_GetObjectItem(cjson,"pubn")->valuestring;
    hex2bin(tmp2,temp5,128);
    secp256k1_fe_set_b32(&x,tmp2);
    secp256k1_fe_set_b32(&y, tmp2+32);
    secp256k1_ge_set_xy(&data->pubn, &x, &y);
     /* 将证书链上 加上会导致通信量太大 所以先不加*/
    // char certname[100];
    // sprintf(certname,"%dcert",deviceID);
    // char *temp6 = cJSON_GetObjectItem(cjson,certname)->valuestring;
    // cJSON_AddStringToObject(certArray,certname,temp6);
}
/*  聚合结果转为json数据 */
/**
 * @description: 
 * @param {cJSON *} cjson 转换的json对象
 * @param {secp256k1_ge} *outpub 聚合验证需要的公钥 长度是datalistnum 单设备报告数量(包含了设备本身) 加上Aggindex(收到的聚合报告的长度) 
 * @param {secp256k1_ge} *A 聚合得到的A 
 * @param {secp256k1_scalar} *outmsg 聚合验证需要的消息
 * @param {secp256k1_scalar } sumZ 聚合验证需要的z
 * @return {*}
 */
void Convert_aggregated_reports_to_JSON_data(cJSON * cjson,secp256k1_ge *outpub,secp256k1_ge *A,secp256k1_scalar *outmsg,secp256k1_scalar sumZ){
    /* 三个数组对象 */
    int len = datalistnum+Aggindex;
    cJSON *outpubArray = cJSON_CreateArray();
    unsigned char tmp1[32];
    unsigned char tmp2[64];
    unsigned char temp[128];
    for (int i = 0;i<len;i++){
        secp256k1_ge_to_char(tmp2,outpub+i);
        bin2hex(tmp2,temp,sizeof(tmp2));
        cJSON_AddStringToObject(outpubArray,"",temp);
    }
    cJSON_AddItemToObject(cjson,"outpub",outpubArray);
    cJSON *A_Array = cJSON_CreateArray();
    for (int i = 0;i<len;i++){
        secp256k1_ge_to_char(tmp2,A+i);
        bin2hex(tmp2,temp,sizeof(tmp2));
        cJSON_AddStringToObject(A_Array,"",temp);
    }
    cJSON_AddItemToObject(cjson,"A",A_Array);
    cJSON *outmsgArray = cJSON_CreateArray();
    for (int i = 0;i<len;i++){
        secp256k1_scalar_get_b32(tmp1,outmsg+i);
        bin2hex(tmp1,tmp2,sizeof(tmp1));
        cJSON_AddStringToObject(outmsgArray,"",tmp2);
    }
    cJSON_AddItemToObject(cjson,"outmsg",outmsgArray);
    secp256k1_scalar_get_b32(tmp1,&sumZ);
    bin2hex(tmp1,tmp2,sizeof(tmp1));
    cJSON_AddStringToObject(cjson,"sumZ",tmp2);

    /* 证书链 */
    // cJSON_AddStringToObject(cjson,"cert",cJSON_PrintUnformatted(certArray));
    

    
}
/* 从json数据中提取出聚合的结果 */
void JSON_data_to_Convert_aggregated_reports(cJSON * cjson,secp256k1_ge *outpub,secp256k1_ge *A,secp256k1_scalar *outmsg,secp256k1_scalar  *sumZ){
    unsigned char tmp1[32];
    unsigned char tmp2[64];
    int overflow = 0;
    /* 三个数组对象 */
    cJSON *outpubArray = cJSON_GetObjectItem(cjson,"outpub");
    int size = cJSON_GetArraySize(outpubArray);
    secp256k1_fe x,y;
    for(int i = 0;i<size;i++){
        char *temp = cJSON_GetArrayItem(outpubArray,i)->valuestring;
        hex2bin(tmp2,temp,128);
        secp256k1_fe_set_b32(&x,tmp2);
        secp256k1_fe_set_b32(&y, tmp2+32);
        secp256k1_ge_set_xy(outpub+Aggindex+i, &x, &y);
    }
    cJSON *A_Array = cJSON_GetObjectItem(cjson,"A");
    for(int i = 0;i<size;i++){
        char *temp = cJSON_GetArrayItem(A_Array,i)->valuestring;
        hex2bin(tmp2,temp,128);
        secp256k1_fe_set_b32(&x,tmp2);
        secp256k1_fe_set_b32(&y, tmp2+32);
        secp256k1_ge_set_xy(A+Aggindex+i, &x, &y);
    }
    cJSON *outmsgArray = cJSON_GetObjectItem(cjson,"outmsg");
    for(int i = 0;i<size;i++){
        char *temp = cJSON_GetArrayItem(outmsgArray,i)->valuestring;
        hex2bin(tmp1,temp,64);
        secp256k1_scalar_set_b32(outmsg+Aggindex+i,tmp1,&overflow);
        VERIFY_CHECK(overflow == 0);
    }
    char *sumzchar = cJSON_GetObjectItem(cjson,"sumZ")->valuestring;
    hex2bin(tmp1,sumzchar,64);
    secp256k1_scalar_set_b32(sumZ,tmp1,&overflow);
    VERIFY_CHECK(overflow == 0);
    /* 聚合报告的索引值需要加上size 以便聚合时使用 */
    Aggindex += size;

    /* 证书链 */
    // cJSON *certArray1 = cJSON_Duplicate(certArray,1);
    // char * tmp= cJSON_GetObjectItem(cjson,"cert")->valuestring;
    // char *jsontmp = mergeJSON(cJSON_PrintUnformatted(certArray1),tmp);
    // certArray = cJSON_Parse(jsontmp);
    // printf("合并前：%s\n%s\n",cJSON_PrintUnformatted(certArray1),tmp);
    // printf("合并后：%s\n",cJSON_PrintUnformatted(certArray));
}

/* 排序 */
void Sort_output_and_A(secp256k1_ge *outpub_2,  secp256k1_scalar *outmsg_2, secp256k1_ge *A_2){
    int pos1 = 0;
    int pos2 = 0;
    /*T集合*/
   tHatTreeNode *tHat = NULL;
   /*A集合*/
   geTreeNode *aHat = NULL;
    /*聚合过程*/
    for (int i = 0; i<Aggindex+datalistnum ; i++)
    {
        /*是否在T集合中*/
    	 int check1 =  tHatTree_Find ( outpub_2+i ,  outmsg_2+i ,tHat);
         /*是否在A集合中*/
    	int check2 =  geTree_Find ( A_2+i ,aHat) ;
        /*不在T集合和A集合中则*/
    	if ( check1 == 0&& check2 == 0  )
    	{
            /*插入T集合*/
    		tHat = tHatTree_Insertion(outpub_2+i ,  outmsg_2+i ,tHat);
            /*插入A集合*/
    		aHat = geTree_Insertion(A_2+i ,aHat);
    	}

    }

    /*将T集合和A集合赋值到参数中 */
    tHatTree_inorder(tHat, outpub ,outmsg,  &pos1);
    geTree_inorder(aHat, A,  &pos2);

    /*释放内存空间*/
    releasetHatTreeNode(tHat);
    releasegeTreeNode(aHat);

    if (pos1 != pos2)
    {
    	return 0;
    }

    return 1;

}

/* 聚合报告 */
/**
 * @description: 聚合函数 已通过测试
 * @param {int} type 是哪种聚合类型 1：第一次聚合 2：已经进行过聚合 区别在于A T z不同
 * @return {*}
 */
void AGG_Report(int type){
    printf("聚合的长度为：%d\n",datalistnum);
    /*聚合*/
    secp256k1_ge *pubn = (secp256k1_ge*) malloc (datalistnum*sizeof(secp256k1_ge));
    secp256k1_scalar *msg =  (secp256k1_scalar*) malloc (datalistnum*sizeof(secp256k1_scalar));
    secp256k1_scalar *sigd =  (secp256k1_scalar*) malloc (datalistnum*sizeof(secp256k1_scalar));
    secp256k1_scalar *sigz =  (secp256k1_scalar*) malloc (datalistnum*sizeof(secp256k1_scalar));    
    int recid;
    int getrec;
    int overflow=0;
    int outSize= 0;
    secp256k1_sha256 hasha;
    unsigned char dnum_char[32];
    unsigned char out[32];
    secp256k1_scalar message;
    secp256k1_scalar sumZ;
  
    //将数据组织成链表形式
    for(int i = 0;i<datalistnum;i++){
        *(msg+i)= datalist[i].m;
        *(sigd+i) = datalist[i].sigd;
        *(sigz+i) = datalist[i].sigz;
        *(pubn+i) = datalist[i].pubn;
    }

    secp256k1_ge *outpub_2 = (secp256k1_ge*)malloc((Aggindex+datalistnum)*sizeof(secp256k1_ge));
    secp256k1_ge *A_2 = (secp256k1_ge*)malloc((Aggindex+datalistnum)*sizeof(secp256k1_ge));
    secp256k1_scalar *outmsg_2 = (secp256k1_scalar*)malloc((Aggindex+datalistnum)*sizeof(secp256k1_scalar));
    /*聚合 得到 A sumz outpub outmsg*/
    switch (type)
    {
    case 1:
    /* 聚合做了什么？ 对sum是累加还是赋值 */
        secp256k1_gamma_Agg(pubn, msg, sigd, sigz, datalistnum, outpub, outmsg, A, &outSize  ,&SumZ);
        printf("聚合输出长度：%d\n",outSize);
        break;
    case 2:
    /* 第2种类型的聚合 需要更改A和T链表的指针位置 将结果链在后面 这里面会直接对sum赋值0 所以结束后要对SumZ做累加操作  */
        secp256k1_gamma_Agg(pubn, msg, sigd, sigz, datalistnum, outpub+Aggindex, outmsg+Aggindex, A+Aggindex, &outSize  ,&sumZ);
        secp256k1_scalar_add(&SumZ,&SumZ,&sumZ);
        /* 赋值操作 */
        for(int i = 0;i<Aggindex+datalistnum;i++){
            *(outpub_2+i) = *(outpub+i);
            *(outmsg_2+i) = *(outmsg+i);
            *(A_2+i) = *(A+i);
        }
        /* 对outpub和A进行排序 */
        Sort_output_and_A(outpub_2,outmsg_2,A_2);
        break;
    default:
        break;
    }
    free(pubn);
    free(msg);
    free(sigd);
    free(sigz);
    free(outpub_2);
    free(outmsg_2);
    free(A_2);
}

/* 定向发送数据 */
void Directed_sending_of_data(int rece_port,char *jsondata, pittacus_gossip_t *gossip,int type){
    char message[256];
    size_t message_with_ts_size = 0;
    char message_with_ts[486];
    time_t current_time = time(NULL);
    struct sockaddr_in seed_node_in2;
    seed_node_in2.sin_family = AF_INET;
    if(rece_port == 10000){
        seed_node_in2.sin_port = htons(45000);
    }else if(rece_port == 1){
        seed_node_in2.sin_port = htons(45001);
    }else{
        seed_node_in2.sin_port = start_port + rece_port;
    }
    inet_aton("127.0.0.1", &seed_node_in2.sin_addr);
    pittacus_addr_t seed_node_addr2 = {
        .addr = (const pt_sockaddr *)&seed_node_in2,
        .addr_len = sizeof(struct sockaddr_in)};
    pt_socklen_t updated_self_addr_size = sizeof(pt_sockaddr_in);
    int res = 0;
    switch (type)
    {
    case 1:
        sprintf(message, "message: [%d]: %s", node_ID, DATA_MESSAGE2);
        message_with_ts_size = sprintf(message_with_ts, "%s ts = %ld", message, current_time) + 1;
        res = pittacus_gossip_send_data_single(gossip, (const uint8_t *)message_with_ts, message_with_ts_size, &seed_node_addr2, updated_self_addr_size);
        if(res<0){
            printf("定向发送数据失败，类型为:%d\n",type);
        }
        return;
    case 2:
        sprintf(message, "message: [%d]: %s", node_ID, DATA_TYPE_1);
        break;
    case 3:
        sprintf(message, "message: [%d]: %s", node_ID, DATA_TYPE_2);
        break;
    default:
        break;
    }
    
    /* DLCV数据为空 sigd和sigz数据也为空 gama数据是乱码 前面的信息给60个字节 则 json数据每次传426个字节*/
    int len = strlen(jsondata);
    /* printf("json数据有多少：%d\n",len); */
    /* 一共需要分成datanum段 */
    int datanum = len%400==0?len/400:len/400+1;
    char temp[420]={'\0'};
    if(jsondata!=NULL && len>400){
        /* json数据太多 udp数据包装不下 有效负载不超过486字节  聚合签名越多 数据越多 如果每次发送都要分包 也太难了 */
        for(int i=0;i<datanum;i++){
            strncpy(temp,jsondata,400);
            /* 给数据包附上长度 */
            message_with_ts_size = sprintf(message_with_ts, "%s%d;datalength=%d (%s) ts = %ld", message,i,datanum,temp, current_time) + 1;
            
          /*   printf("message_with_ts:%s\n",message_with_ts);
            printf("message_with_ts_size:%d\n",message_with_ts_size); */
            res = pittacus_gossip_send_data_single(gossip, (const uint8_t *)message_with_ts, message_with_ts_size, &seed_node_addr2, updated_self_addr_size);

            if(res<0){
                printf("定向发送数据失败，类型为:%d 序号为:%d\n",type,i);
                return;
            }
            jsondata=jsondata+400;

        }   
    }else if(jsondata!=NULL&&len<400){
         /* 给数据包附上长度 */
        message_with_ts_size = sprintf(message_with_ts, "%s0;datalength=%d (%s)", message,datanum,jsondata) + 1;
        /* printf("message_with_ts:%s\n",message_with_ts);
        printf("message_with_ts_size:%d\n",message_with_ts_size); */
        res = pittacus_gossip_send_data_single(gossip, (const uint8_t *)message_with_ts, message_with_ts_size, &seed_node_addr2, updated_self_addr_size);
        if(res<0){
                printf("定向发送数据失败，类型为:%d\n",type);
                return;
            }
    }

    return;
}

bool Has_the_data_packet_been_received(int index){
    /* 数据包长度为 deviceDatanum[index]*/
    for(int i=0;i<deviceDatanum[index];i++){
        if(!data_packet_hasRece[index][i]){
            /* 说明有数据没接收到 继续接收 */
            return false;
        }
    }
    return true;
}

/* 判断聚合 */
void *Judgment_aggregation()
{
    int times = 10;
    int unreceNum=0;
    while (1)
    {
        // sleep(10);
        if (times < 5)
        {
            sleep(8);
        }
        else
        {
            unreceNum = childNum - rece_report_num;
            sleep(3 * unreceNum);
        }
        /* 所有子节点的报告均接收到 进行聚合 这里的判断条件不太严谨 有可能收到一个子节点的消息立马收到一个报告  这样也会聚合 可能也需要另起线程来判断 报告至少延迟5秒中 也许不会？*/
        /* 设定一个接收时间 例如30秒之后 不论子节点的报告是否接收完 直接聚合 当然起码要收到一份 否则就是没有子节点 发送自己的报告即可 */
        /* 这样设定会让父节点可能来不及接收子节点的聚合报告 */
        /* 改为每10秒判断一次   */
        // 最多判断五次接收报告和子节点报告是否相等
        //pthread_mutex_lock(&mutex);
        // 读取变量的代码 避免将if操作放在锁里 这里用一个临时值来保存变量
        //temp = rece_report_num;
        //pthread_mutex_unlock(&mutex);
        if ((rece_report_num == childNum && !hasAGG)||(times == 0 && !hasAGG))
        {
            printf("开始聚合: 接收报告%d 子节点数目%d times:第%d次\n",rece_report_num,childNum,times);
            /* 进行聚合 两种情况 第一次聚合 或者 已经进行过聚合*/
            clock_t start2 = clock();
            if (is_Agg)
            {
                /* 已经进行过聚合 */
                AGG_Report(2);
            }
            else
            {
                /* 第一次聚合*/
                AGG_Report(1);
            }
            hasAGG = true;
            /* 需要发送的是聚合签名的结果*/
            cJSON *cjson = cJSON_CreateObject();
            Convert_aggregated_reports_to_JSON_data(cjson, outpub, A, outmsg, SumZ);
            clock_t end2 = clock();
            aggtime = (double)(end2-start2)/CLOCKS_PER_SEC;
            // printf("####################################%d节点的聚合时间是：%f\n",node_ID,aggtime);
            /* 发送给父节点 */
            char *json_data = cJSON_PrintUnformatted(cjson); // JSON数据结构转换为JSON字符串
            // printf("发送给父节点的聚合报告为：%s\n",json_data);

            /* 将聚合结果发送给父节点 */
            int sendtimes = 1;
            if (cjson != NULL)
            {
                while (sendtimes != 0 && json_data != NULL)
                {
                    Directed_sending_of_data(1, json_data,gossip, 3);
                    sleep(3);
                    sendtimes--;
                }
                free(json_data);
                json_data = NULL;
                cJSON_Delete(cjson);
                cjson = NULL;
            }
            endTime = clock();
            double time = (double)(endTime - startTime) / CLOCKS_PER_SEC;
            runtime = suTime+time;
            /* 写入文件 */
            FILE *fp = NULL;
            FILE *fp2 = NULL;
            // 打开文件
            fp = fopen("./data/runtime_SN5.txt", "a");
            fp2 = fopen("temp.txt", "w");
            // 向文件中写入数据
            if(COUNT==5){
                fprintf(fp, "验证节点数：%d\t实际聚合：%d\t子叶子节点个数:%d\t\t启动时间：%f\t\t聚合时间:%f\n", COUNT,datalistnum+Aggindex,datalistnum-1,suTime, aggtime);
            }else if(COUNT==40){
                //存储量 加上每个节点的固件信息200 gama值256 证书591
                fprintf(fp, "验证节点数：%d\t实际聚合：%d\t子叶子节点个数:%d\t\t聚合时间:%f\t\t存储量:%ld\n", COUNT,datalistnum+Aggindex,datalistnum-1,aggtime,memory_capacity+(591+256+200-128)*Aggindex+200*datalistnum);
                // fprintf(fp, "验证节点数：%d\t实际聚合：%d\t处理数据时间:%f\t\t聚合时间:%f\t\t存储量:%ld\n", COUNT,datalistnum+Aggindex,dataProcessTime,aggtime,memory_capacity+(591+256+200-128)*Aggindex+200*datalistnum);
            }else{
                fprintf(fp, "验证节点数：%d\t实际聚合：%d\t子叶子节点个数:%d\t\t聚合时间:%f\n", COUNT,datalistnum+Aggindex,datalistnum-1,aggtime);
            }

            fprintf(fp2, "2");
            fclose(fp);
            fclose(fp2);

            /* 结束之后释放内存 */
            free(outpub);
            free(A);
            free(outmsg);
            exit(2);
        }else{
            /* 子节点报告未收齐 */
            //times--;
        }
    }
}
/* 数据接收器回调 */
void data_receiver(void *context, pittacus_gossip_t *gossip, const uint8_t *data, size_t data_size) {
    // printf("Data arrived: %s\n", data);
    char message[256];
    /* 一个足够大的字符数组来保存数据 由于UDP的限制 每次发送过来的数据只有400B 加上附加的一些东西 多给一些字节*/
    char data_char[600]={'\0'};
    sprintf(data_char,"%s",data);
    /* 哪个节点发送过来的 */
    int id = 0;
    sscanf(data_char,"%*[^[][%d[^]]",&id);
    if(!is_first && is_in(data_char,DATA_MESSAGE)==1){
        /* 不是第一次收到认证请求 直接return  */
        return;
    }
    /* 随后对数据进行判断 是认证请求 还是设备认证报告 还是不含签名值的设备认证报告&& !clusterJoin[id-start_port] */
    if(is_in(data_char,DATA_TYPE_3)==1 ){
        /* 有1节点已加入集群*/
        clusterNum++;
        //clusterJoin[id-start_port]=true;
        printf("%d节点已加入集群 \n",id);
    }
    if( is_in(data_char,DATA_MESSAGE)==1 && is_first){
        /* 说明是认证请求 且是第一次收到认证请求 改为false 之后收到的认证请求不予理会*/
        is_first = false;
        /* 种子节点父节点为远程验证者 端口号应该是固定的 */
       /*  father_ID = id;
        Directed_sending_of_data(father_ID,NULL,gossip,1); */

        /*  收到认证请求后 另启线程 设定接收数据的时间为30 30秒过后 无论子节点报告是否收齐 开始聚合*/
       
    }else if(is_in(data_char,DATA_MESSAGE2)==1){
        /* 是子节点发来的 将其放入子节点列表*/
        if(is_in_array(child_ID,childNum,id)==-1){
            child_ID[childNum] = id;
            childNum++;
        }
        if (!has_child)
        {
            has_child = true;
            pthread_t thrd2;
            int thread_sd = 1000;
             /* 设置子线程大小 */
            pthread_attr_t thread_attr;
            size_t stack_size = 64 * 1024 * 1024; // 64 MB
            pthread_attr_init(&thread_attr);
            pthread_attr_setstacksize(&thread_attr, stack_size);
            if (pthread_create(&thrd2, NULL, Judgment_aggregation, &thread_sd) != 0)
            {
                printf("thread2 error:%s \n", strerror(errno));
                return -1;
            }
            /* 设置成可分离 */
            pthread_detach(thrd2);
        }
    }else if( is_in(data_char,DATA_TYPE_1)==1 ){
        /* 说明是单设备认证报告 解析json数据 由于udp数据包的局限性 可能需要接收多个包才能接收完全数据*/
        /* 如果是多个单设备认证报告 如何保证持续接收  */
        int index = is_in_array(child_ID, childNum, id);
        if (index != -1 && !hasReceived[index])
        {
            if (deviceDatanum[index] == 0)
            {
                /* 需要读取数据包的长度 */
                sscanf(data_char, "%*[^=]=%d", &deviceDatanum[index]);
            }
            /* 该设备已经有数据包长度了 拼接数据 */
            char temp[420]={'\0'};
            int dataindex = -1;
            sscanf(data_char, "%*[^E]E%*[^0-9]%d%*[^(](%[^)]", &dataindex, temp);
            if (!data_packet_hasRece[index][dataindex])
            {
               
                /* 还没接收  */
                clock_t time1 = clock();
                strcpy(data_packet[index][dataindex], temp);
                data_packet_hasRece[index][dataindex] = true;
                /* 判断数据包是否接收完毕 */
                if (Has_the_data_packet_been_received(index))
                {
                    printf("%d节点数据接收完毕!\n",id);
                    hasReceived[index] = true;
                    /* 接收完毕 单个设备认证报告的数据包大概在2300字节*/
                    char json_char[4000]={'\0'};
                    for (int i = 0; i < deviceDatanum[index]; i++)
                    {
                        strcat(json_char, data_packet[index][i]);
                    }
                    /* printf("完整的数据为:%s\n",json_char); */
                    long jsonlen = strlen(json_char);
                    memory_capacity+=jsonlen;
                    cJSON *cjson = cJSON_Parse(json_char);
                    if (cjson != NULL)
                    {
                        Equipment_Certification_Report data;
                        Json_to_Report_structure(cjson, &data,id);
                        datalist[datalistnum] = data;
                        datalistID[datalistnum] = id;
                        datalistnum++;
                        //pthread_mutex_lock(&mutex);
                        rece_report_num++;
                        // 修改变量的代码
                        //pthread_mutex_unlock(&mutex);
                        cJSON_Delete(cjson);
                    }
                    else
                    {
                        printf("json数据解析失败!\n");
                    }
                    
                }
                clock_t time2 = clock();
                double T = (double)(time2 - time1) / CLOCKS_PER_SEC;
                dataProcessTime += T;
            }
        }
    }else if(is_in(data_char,DATA_TYPE_2)==1){
        /* 说明是不含签名值的聚合报告 如何保证报告只接收一次 目前发送方只发送一次看看效果*/
        
        int index = is_in_array(child_ID, childNum, id);
        if (index != -1 && !hasReceived[index])
        {   
            if (deviceDatanum[index] == 0)
            {
                /* 需要读取数据包的长度 */
                sscanf(data_char, "%*[^=]=%d", &deviceDatanum[index]);
            }
            /* 该设备已经有数据包长度了 拼接数据 */
            char temp[420]={'\0'};
            int dataindex = -1;
            sscanf(data_char, "%*[^A]A%*[^0-9]%d%*[^(](%[^)]", &dataindex, temp);
            if (!data_packet_hasRece[index][dataindex])
            {
                clock_t time1 = clock();
                strcpy(data_packet[index][dataindex], temp);
                data_packet_hasRece[index][dataindex] = true;
                /* 判断数据包是否接收完毕 */
                if (Has_the_data_packet_been_received(index))
                {
                    printf("%d节点数据接收完毕!\n",id);
                    hasReceived[index] = true;
                    /* 接收完毕可以聚合了 */
                    if (is_first_AGG)
                    {
                        /* 给sumz初始化  */
                        secp256k1_scalar_set_int(&SumZ, 0);
                        is_first_AGG = false;
                    }
                    /* 接收完毕 聚合报告长度随通信网络而定 可以采取动态分配*/
                    char *json_char = (char*)calloc(deviceDatanum[index]*420,sizeof(char));
                    for (int i = 0; i < deviceDatanum[index]; i++)
                    {
                        strcat(json_char, data_packet[index][i]);
                    }
                    long jsonlen = strlen(json_char);
                    memory_capacity+=jsonlen;
                    cJSON *cjson = cJSON_Parse(json_char);
                    if (cjson != NULL)
                    {
                        secp256k1_scalar sumz;
                        JSON_data_to_Convert_aggregated_reports(cjson, outpub, A, outmsg, &sumz);
                        secp256k1_scalar_add(&SumZ, &SumZ, &sumz);
                        /* 接收到的报告 */
                        //pthread_mutex_lock(&mutex);
                        rece_report_num++;
                        // 修改变量的代码
                        //pthread_mutex_unlock(&mutex);

                        is_Agg = true;
                        cJSON_Delete(cjson);
                    }
                    else
                    {
                        printf("json数据解析失败!\n");
                    }
                    if(json_char!=NULL){
                        free(json_char);
                        json_char=NULL;
                    }
                }
                clock_t time2 = clock();
                double T = (double)(time2 - time1) / CLOCKS_PER_SEC;
                dataProcessTime += T;
            }
        }
    }

    return ;
}

void deviceStart()
{
    /* 设备启动 */
    /* 本设备的认证报告 */
    Equipment_Certification_Report mydata;
    Single_device_startup_simulation2(node_ID, &mydata);
    cJSON * cjson = cJSON_CreateObject();
    Report_structure_to_JSON(cjson,mydata);
    char* jsondata = cJSON_PrintUnformatted(cjson);
    // printf("单设备报告:%s\n长度为:%d\n",jsondata,strlen(jsondata));
    memory_capacity+=strlen(jsondata);
    /*  把数据添加到聚合的报告列表里  */
    datalist[datalistnum] = mydata;
    datalistID[datalistnum] = node_ID;
    datalistnum++;

    /* 将证书链接上 */
    // cert_to_Json(certArray,node_ID);
}

void gossip_seed_node(){
    /* 实例化一个pittacus描述符 sockaddr表示当前节点的地址和数据接收器回调 */
    struct sockaddr_in self_in;
    self_in.sin_family = AF_INET;
    self_in.sin_port = htons(45000);
    inet_aton("127.0.0.1", &self_in.sin_addr);

    // Filling in the address of the current node.
    pittacus_addr_t self_addr = {
        .addr = (const pt_sockaddr *) &self_in,
        .addr_len = sizeof(struct sockaddr_in)
    };

    // Create a new Pittacus descriptor instance.
    gossip = pittacus_gossip_create(&self_addr, &data_receiver, NULL);
    if (gossip == NULL) {
        fprintf(stderr, "Gossip initialization failed: %s\n", strerror(errno));
        return -1;
    }else{
        printf("gossip%d号节点初始化结束成功！\n",node_ID);
    }

    // No seed nodes are provided. 没有种子结点
    /* 是时候加入集群了。有两种方法可以做到这一点:1)指定用作集群入口点的种子节点列表或2)如果此实例本身将成为种子节点，则不指定任何内容。 */
    int join_result = pittacus_gossip_join(gossip, NULL, 0);
    if (join_result < 0) {
        fprintf(stderr, "Gossip join failed: %d\n", join_result);
        pittacus_gossip_destroy(gossip);
        return -1;
    }
    else
    {
        printf("%d号节点为种子节点！\n", node_ID);
    }
    /* 生成本设备的认证报告 记录一下生成认证报告的时间*/
    deviceStart();
    clock_t end1 = clock();
    suTime = (double)(end1 - start1) / CLOCKS_PER_SEC;

    // Retrieve the socket descriptor.
    pt_socket_fd gossip_fd = pittacus_gossip_socket_fd(gossip);
    struct pollfd gossip_poll_fd = {
        .fd = gossip_fd,
        .events = POLLIN,
        .revents = 0
    };

    int poll_interval = GOSSIP_TICK_INTERVAL;
    int recv_result = 0;
    int send_result = 0;
    int poll_result = 0;
    int send_data_interval = 5; // send data every 5 seconds
    time_t previous_data_msg_ts = time(NULL);
    char message_with_ts[256];
    size_t message_with_ts_size = 0;
    char message[256];
    sprintf(message, "message: [%d]: %s", node_ID, DATA_MESSAGE);
    int send_times = 5;
    int isstart = 1;
    while (1) {
        gossip_poll_fd.revents = 0;
        poll_result = poll(&gossip_poll_fd, 1, poll_interval);
         if (poll_result == 0)
        {
            printf("poll超时！");
        }
        if (poll_result > 0) {
            if (gossip_poll_fd.revents & POLLERR) {
                fprintf(stderr, "Gossip socket failure: %s\n", strerror(errno));
                pittacus_gossip_destroy(gossip);
                return -1;
            } else if (gossip_poll_fd.revents & POLLIN) {
                // Tell Pittacus to read a message from the socket.
                /* 强制pittacus从网络读取消息 */
                recv_result = pittacus_gossip_process_receive(gossip);
                if (recv_result < 0) {
                    fprintf(stderr, "Gossip receive failed: %d\n", recv_result);
                    /* pittacus_gossip_destroy(gossip);
                    return -1; */
                }
            }
        } else if (poll_result < 0) {
            fprintf(stderr, "Poll failed: %s\n", strerror(errno));
            pittacus_gossip_destroy(gossip);
            return -1;
        }
        // Try to trigger the Gossip tick event and recalculate
        // the poll interval.
        /* 为了在pittacus中启用反熵 应该定期调用gossip tick函数 */
        /* poll_interval = pittacus_gossip_tick(gossip);
        if (poll_interval < 0) {
            fprintf(stderr, "Gossip tick failed: %d\n", poll_interval);
            return -1;
        } */

        // Send some data periodically.
        time_t current_time = time(NULL);
        /* 等待所有节点都进入集群*/
        if (send_times > 0 && previous_data_msg_ts + send_data_interval <= current_time && COUNT == clusterNum && !is_first)
        {
            if(isstart ==1){
                startTime = clock();
                isstart=0;
            }
            previous_data_msg_ts = current_time;
            message_with_ts_size = sprintf(message_with_ts, "%s (ts = %ld)", message, current_time) + 1;
            /* 在集群中传播数据 */
            printf("在集群中传送数据%s\n,",message);
            int res = pittacus_gossip_send_data(gossip, (const uint8_t *) message_with_ts, message_with_ts_size);
            if(res < 0){
                printf("在集群中传送数据出错\n");
            }else{
                send_times--;
            }
        }

        // Tell Pittacus to write existing messages to the socket.
        /* 将出站消息刷新到网络 */
        send_result = pittacus_gossip_process_send(gossip);/* Process terminating with default action of signal 1 (SIGHUP) */
        if (send_result < 0) {
            fprintf(stderr, "Gossip send failed: %d, %s\n", send_result, strerror(errno));
            pittacus_gossip_destroy(gossip);
            return -1;
        }

    }
    pittacus_gossip_destroy(gossip);
}



int main(int argc, char **argv) {
    unsigned char run32[32] = {0};
    /* Disable buffering for stdout to improve reliability of getting
     * diagnostic information. Happens right at the start of main because
     * setbuf must be used before any other operation on the stream. */
    setbuf(stdout, NULL);
    /* Also disable buffering for stderr because it's not guaranteed that it's
     * unbuffered on all systems. */
    setbuf(stderr, NULL);

    /* find iteration count */
    if (argc > 1) {
        COUNT = strtol(argv[1], NULL, 0);
    } else {
        const char* env = getenv("SECP256K1_TEST_ITERS");
        if (env && strlen(env) > 0) {
            COUNT = strtol(env, NULL, 0);
        }
    }
    if (COUNT <= 0) {
        fputs("An iteration count of 0 or less is not allowed.\n", stderr);
        return EXIT_FAILURE;
    }
    //printf("test count = %i\n", COUNT);

    /* find random seed */
    secp256k1_testrand_init(argc > 2 ? argv[2] : NULL);

    /*** Setup test environment ***/

    /* Create a global context available to all tests */
    /*CTX = secp256k1_context_create(SECP256K1_CONTEXT_NONE);*/
    CTX = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    /* Randomize the context only with probability 15/16
       to make sure we test without context randomization from time to time.
       TODO Reconsider this when recalibrating the tests. */
    if (secp256k1_testrand_bits(4)) {
        unsigned char rand32[32];
        secp256k1_testrand256(rand32);
        CHECK(secp256k1_context_randomize(CTX, rand32));
    }
    /* Make a writable copy of secp256k1_context_static in order to test the effect of API functions
       that write to the context. The API does not support cloning the static context, so we use
       memcpy instead. The user is not supposed to copy a context but we should still ensure that
       the API functions handle copies of the static context gracefully. */
    STATIC_CTX = malloc(sizeof(*secp256k1_context_static));
    CHECK(STATIC_CTX != NULL);
    memcpy(STATIC_CTX, secp256k1_context_static, sizeof(secp256k1_context));
    CHECK(!secp256k1_context_is_proper(STATIC_CTX));
    /*隐式证书部分 */
    //printf("隐式证书测试!!!!!!!!!!!!\n");
    /* test_Implicitertificate();  */
    /*Device_nlayer_startup_test(); */
    /* Device_Network_Aggregation_Validation_Simulation(); */

    /* 运行种子节点 该节点为种子节点 种子节点并不发送认证报告 只发送认证请求 接收认证报告*/
    // certArray = cJSON_CreateObject();
    outpub = (secp256k1_ge *)malloc(100 * sizeof(secp256k1_ge));
    A = (secp256k1_ge *)malloc(100 * sizeof(secp256k1_ge));
    outmsg = (secp256k1_scalar *)malloc(100 * sizeof(secp256k1_scalar));
    /* 集群节点数量 */
    printf("一共有%d个节点需要认证！\n",COUNT);
    gossip_seed_node();
   

    /* Extract_public_key_from_certificate(1); */
    /* shutdown */
    free(STATIC_CTX);
    secp256k1_context_destroy(CTX);
    printf("no problems found!\n");

    return 0;
}