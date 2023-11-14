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
static int COUNT = 64;
static secp256k1_context *CTX = NULL;
static secp256k1_context *STATIC_CTX = NULL;
static int fd = -1;
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

/* 执行命令行命令并获取返回值 */
void executeCMD(char *cmd, char *result)   
{   
    char buf_ps[1024];   
    char ps[1024]={0};   
    FILE *ptr;   
    strcpy(ps, cmd);   
    if((ptr=popen(ps, "r"))!=NULL)   
    {   
        while(fgets(buf_ps, 1024, ptr)!=NULL)   
        {   
           strcat(result, buf_ps);   
           if(strlen(result)>1024)   
               break;   
        }   
        pclose(ptr);   
        ptr = NULL;   
    }   
    else  
    {   
        printf("popen %s error", ps);   
    }   
}  

/* 删除换行符 */
void Remove_line_break(char *temp,int len){
    for(int i=0;i<len;i++){
        if(temp[i]=='\n'){
            temp[i]=" ";
        }
    }
    
}



/* openssl 生成显式证书 申请证书之前需要有证书请求文件 参数是设备第0层私钥和公钥 私钥用于签名 公钥要交给CA签发*/
/*证书请求文件包含用户信息 公钥 可选的一些属性 并使用私钥对其进行了签名
EC_GROUP:ECC算法中的组结构体 里面包含着曲线信息 
EC_POINT：ecc算法中的点结构体，里面有x，y，z三个值来确地曲线上的一个点
EC_KEY：ecc算法中的秘钥结构体，里面包含私钥、公钥、曲线信息
*/
int Generate_certificate_equest_file_and_Generate_X5092(int deviceID,int layer_n,secp256k1_scalar *priv0,secp256k1_ge *pub0){
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
		sprintf(buffer, "%s%dlayer%d", "device", deviceID,layer_n);
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
        sprintf(filename, "./pem2/certreq%dlayer%d.txt",deviceID,layer_n);
        b = BIO_new_file(filename, "w");
        PEM_write_bio_X509_REQ(b, req);
        BIO_free(b);
        OpenSSL_add_all_algorithms();
        ret=X509_REQ_verify(req,pkey);
        if(ret<0){
            printf("verify err.\n");
            return 0;
        }
        /* 将当前层私钥写入文件 为下一层签名做准备 */
        FILE *fp;
        char privName[50];
        sprintf(privName, "./pem2/device%dlayer%dpriv.key", deviceID, layer_n);
        fp = fopen(privName, "wb");
        //PEM_write_ECPKParameters(fp, EC_KEY_get0_group(key), 0);
        PEM_write_ECPrivateKey(fp, key, NULL, NULL, 0, NULL, NULL);
        fclose(fp);
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
        char cmd[400];
        if(layer_n ==0){
            sprintf(cmd, "openssl x509 -req -in ./pem2/certreq%dlayer%d.txt -extfile ./pem2/crt/extfile.txt -out ./pem2/crt/device%dlayer%d.crt  -CA ./pem2/crt/root.crt -CAkey ./pem2/crt/root.key -CAcreateserial", deviceID, 0,deviceID,0);
        }else{
            /* 不是第0层需要将私钥写入文件 */
            sprintf(cmd, "openssl x509 -req -in ./pem2/certreq%dlayer%d.txt -extfile ./pem2/crt/extfile.txt -out ./pem2/crt/device%dlayer%d.crt -CA ./pem2/crt/device%dlayer%d.crt -CAkey ./pem2/device%dlayer%dpriv.key -CAcreateserial", deviceID, layer_n,deviceID,layer_n,deviceID, (layer_n)-1,deviceID,(layer_n)-1);
        }
		
        int ret2 = -1; 
        while(ret2 !=0){
            ret2 = system(cmd);
        }
        /* 生成证书后删除证书请求文件 */
        sprintf(cmd,"rm %s",filename);
        system(cmd);
        /* 生成证书链 */
        if (layer_n == 2)
        {
            char cmd1[400];
             sprintf(cmd1, "cat  ./pem2/crt/device%dlayer1.crt ./pem2/crt/device%dlayer0.crt ./pem2/crt/root.crt >./pem2/crt/device%dchain.crt",deviceID, deviceID, deviceID);
            system(cmd1);
            /* 删除之前的证书 */
            sprintf(cmd1, "rm   ./pem2/crt/device%dlayer1.crt ./pem2/crt/device%dlayer0.crt", deviceID, deviceID);
            system(cmd1);
        }

        free(pub_char);
        pub_char = NULL;
        
        return 1;
}

void Verification_certificate(int deviceID){
    /* 验证证书：
    openssl verify -verbose -CAfile ./pem/root.crt ./pem/deviceXX.crt
    输出child.crt: OK */
    char cmd[200];
    /*  openssl verify -verbose -CAfile <(cat ./pem2/crt/device10001layer0.crt ./pem2/crt/root.crt) ./pem2/crt/device10001layer9.crt*/
    sprintf(cmd, "openssl verify -verbose -CAfile ./pem2/crt/device%dchain.crt ./pem2/crt/device%dlayer2.crt",deviceID,deviceID);
    
   system(cmd);
    /* printf("证书验证完毕\n"); */

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
    HardwareLayer_device_startup_process2(&CTX->ecmult_gen_ctx,&d,&C0,&DLCV0,&seckey0,&pub0);
    /* 向制造商申请显式证书 */
    Generate_certificate_equest_file_and_Generate_X5092(10001,0,&seckey0,&pub0);
    /* printf("设备初始化完毕！\n"); */
    
    /**
     * 假设设备是0-9层
    */
   secp256k1_scalar tempseckey = seckey0;
   secp256k1_scalar tempDLCV = DLCV0;
   secp256k1_ge pub_n;
    for(int i = 1;i<10;i++){
        printf("第%d层开始启动！\n",i);
         /* 下一层的度量值 C_n*/
        secp256k1_scalar C_i;
        random_scalar_order(&C_i);
        /*下一层的DLCV */
        secp256k1_scalar DLCV_i;
        /* 下一层私钥 */
        secp256k1_scalar seckeyi;
        Layer_n_device_startup_process2(&CTX->ecmult_gen_ctx,&tempseckey,&tempDLCV,&C_i,&DLCV_i,&seckeyi,&pub_n);
        /* 由上一层颁发证书 */
        Generate_certificate_equest_file_and_Generate_X5092(10001,i,&seckeyi,&pub_n);
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

    int res = secp256k1_gamma_sig_verify(&sigr, &sigs, &pub_n, &message);
    if(res !=1 ){
        printf("单个设备验证失败！\n");
        return ;
    }
    return;
}


/*模拟设备网络验证 此函数用于设备生成验证报告 需要参数来记录验证时所需要的信息*/
void Single_device_startup_simulation2(int deviceID,EC_Equipment_Certification_Report *data){
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
    /* 硬件启动 */
     HardwareLayer_device_startup_process2(&CTX->ecmult_gen_ctx,&d,&C0,&DLCV0,&seckey0,&pub0);
    /* 向制造商申请显式证书 */
    int ret = Generate_certificate_equest_file_and_Generate_X5092(deviceID,0,&seckey0,&pub0);
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
   secp256k1_scalar tempseckey = seckey0;
   secp256k1_scalar tempDLCV = DLCV0;
   secp256k1_ge pub_n;
    for(int i = 1;i<3;i++){
        /*printf("第%d层开始启动！\n",i);*/
         /* 下一层的度量值 C_n*/
        secp256k1_scalar C_i;
        random_scalar_order(&C_i);
        /*下一层的DLCV */
        secp256k1_scalar DLCV_i;
        /* 下一层私钥 */
        secp256k1_scalar seckeyi;
         Layer_n_device_startup_process2(&CTX->ecmult_gen_ctx,&tempseckey,&tempDLCV,&C_i,&DLCV_i,&seckeyi,&pub_n);
        /* 由上一层颁发证书 */
        Generate_certificate_equest_file_and_Generate_X5092(deviceID,i,&seckeyi,&pub_n);
        /* 更新temp值 */
        tempseckey = seckeyi;
        tempDLCV = DLCV_i;
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
    /* 保存公钥信息 */
    data->pubn = pub_n;
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



/* gossip协议 */
static int start_port = 11000;
static int node_ID = 10001;
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
int child_ID[20];
bool hasReceived[20]={false};
/* 子节点数目  */
int childNum = 0;
/* 聚合报告的位置索引 */
int Aggindex = 0;
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
EC_Equipment_Certification_Report datalist[20];
/* datalist的长度 聚合时需要使用 */
int datalistnum = 0;
/* datalist中对应的节点的ID */
int datalistID[20];
/* 设备数据包个数 */
int deviceDatanum[20]={0};
bool hasAGG = false;
/* 聚合需要的参数 */
static secp256k1_ge *outpub = NULL;
static secp256k1_ge *A = NULL;
static secp256k1_scalar *outmsg =  NULL;
static secp256k1_scalar  SumZ;
/* 本设备的认证报告 */
EC_Equipment_Certification_Report mydata;
/* 存储数据包 */
char data_packet[20][20][420]={'\0'};
bool data_packet_hasRece[20][20]={false};
/* 是否加入集群 */
int isjoin = 1;
/* 线程参数 */
typedef struct
{
	int time;
    pittacus_gossip_t *gossip;
}Pt_arg;
pittacus_gossip_t *gossip=NULL;
/* 将证书链转为Json数据 */
void Convert_the_certificate_chain_to_json_data(cJSON *chain,int deviceID){
    STACK_OF(X509_INFO)* certs = NULL;
    X509_INFO* cert_info = NULL;
    BIO* input = NULL;
    char* cert_text = NULL;

    // 读取证书链文件
    input = BIO_new(BIO_s_file());
    char filename[100];
    sprintf(filename,"./pem2/crt/device%dchain.crt",deviceID);
    BIO_read_filename(input, filename);
    // 解析证书链
    certs = PEM_X509_INFO_read_bio(input, NULL, NULL, NULL);
    // 将每个证书转换为字符形式
    for (int i = 0; i < sk_X509_INFO_num(certs); i++) {
        cert_info = sk_X509_INFO_value(certs, i);
        if (cert_info->x509 != NULL) {
            // 将证书转换为字符形式
            BIO* output = BIO_new(BIO_s_mem());
            PEM_write_bio_X509(output, cert_info->x509);
            BUF_MEM* buffer;
            BIO_get_mem_ptr(output, &buffer);
            cert_text = (char*)malloc(buffer->length + 1);
            memcpy(cert_text, buffer->data, buffer->length);
            cert_text[buffer->length] = '\0';
            cJSON_AddStringToObject(chain,"",cert_text);
            // 释放资源
            free(cert_text);
            BIO_free_all(output);
        }
    }

    // 释放资源
    sk_X509_INFO_pop_free(certs, X509_INFO_free);
    BIO_free_all(input);
}
/* 认证报告结构体转为json数据 */
/**
 * @description: 认证报告结构体转为json数据 通过测试
 * @param {CJSON} *cjson 转换的json对象
 * @param {Equipment_Certification_Report} data 需要转换的认证报告结构体
 * @return {*}
 */
void  Report_structure_to_JSON(cJSON *cjson,EC_Equipment_Certification_Report data){
    /* 将数据转为字符串形式存储 */
    unsigned char temp[32];
    unsigned char temp2[64];
    unsigned char char2[128];
    secp256k1_scalar_get_b32(temp, &data.m);
    bin2hex(temp,temp2,sizeof(temp));
    cJSON_AddStringToObject(cjson,"m",temp2);
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
    /* 证书链 */
    cJSON *chain = cJSON_CreateArray();
    Convert_the_certificate_chain_to_json_data(chain,node_ID);
    // printf("%s\n",cJSON_PrintUnformatted(chain));
    cJSON_AddItemToObject(cjson,"chain",chain);
}
/* 将json数据转为证书链 */
void Convert_json_data_into_a_certificate_chain(cJSON *chain,int deviceID){
    BIO* out = NULL;
    FILE* fp = NULL;
    X509* cert = NULL;
    char filename[100];
    sprintf(filename,"./data/crt/DEV%dchain.crt",deviceID);
    fp = fopen(filename, "w");

    for (int i = 0; i < 3; i++)
    {
        char *temp6 = cJSON_GetArrayItem(chain, i)->valuestring;
        // 从证书字符串创建X509结构体
        out = BIO_new_mem_buf(temp6, -1);
        cert = PEM_read_bio_X509(out, NULL, NULL, NULL);
        BIO_free(out);
        PEM_write_X509(fp, cert);
        free(cert);
        cert = NULL;
    }
    fclose(fp);
}
 /* 解析json数据成报告结构体 通过测试*/
void Json_to_Report_structure(cJSON *cjson,EC_Equipment_Certification_Report *data,int deviceID){
    /* 设备信息 */
    unsigned char tmp1[32];
    unsigned char tmp2[64];
    int overflow = 0;
    char *temp0 = cJSON_GetObjectItem(cjson,"m")->valuestring;
    hex2bin(tmp1,temp0,64);
    secp256k1_scalar_set_b32(&data->m,tmp1,&overflow);
    VERIFY_CHECK(overflow == 0);
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
    secp256k1_fe x,y;
    char *temp5 = cJSON_GetObjectItem(cjson,"pubn")->valuestring;
    hex2bin(tmp2,temp5,128);
    secp256k1_fe_set_b32(&x,tmp2);
    secp256k1_fe_set_b32(&y, tmp2+32);
    secp256k1_ge_set_xy(&data->pubn, &x, &y);
    /* 解析证书链 这里只是模拟证书链的解析存储 但实际验证并没有用新存储的 另外聚合报告里也不包含证书链 否则数据量太大 影响传输*/
    cJSON *chain = cJSON_GetObjectItem(cjson,"chain");
    Convert_json_data_into_a_certificate_chain(chain,deviceID);
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
}


/* 聚合报告 */
/**
 * @description: 聚合函数 已通过测试
 * @param {int} type 是哪种聚合类型 1：第一次聚合 2：已经进行过聚合 区别在于A T z不同
 * @return {*}
 */
void AGG_Report(int type){
    /*聚合*/
    secp256k1_ge *pubn = (secp256k1_ge*) malloc (datalistnum*sizeof(secp256k1_ge));
    secp256k1_scalar *msg =  (secp256k1_scalar*) malloc (datalistnum*sizeof(secp256k1_scalar));
    secp256k1_scalar *sigd =  (secp256k1_scalar*) malloc (datalistnum*sizeof(secp256k1_scalar));
    secp256k1_scalar *sigz =  (secp256k1_scalar*) malloc (datalistnum*sizeof(secp256k1_scalar));    
    int recid;
    int getrec;
    int overflow=0;
    int outSize= 0;
    secp256k1_scalar sumZ;
  
    //将数据组织成链表形式
    for(int i = 0;i<datalistnum;i++){
        *(msg+i)= datalist[i].m;
        *(sigd+i) = datalist[i].sigd;
        *(sigz+i) = datalist[i].sigz;
        *(pubn+i) = datalist[i].pubn;
    }

    /*聚合 得到 A sumz outpub outmsg*/
    switch (type)
    {
    case 1:
    /* 聚合做了什么？ 对sum是累加还是赋值 */
        secp256k1_gamma_Agg(pubn, msg, sigd, sigz, datalistnum, outpub, outmsg, A, &outSize  ,&SumZ);
        break;
    case 2:
    /* 第2种类型的聚合 需要更改A和T链表的指针位置 将结果链在后面 这里面会直接对sum赋值0 所以结束后要对SumZ做累加操作  */
        secp256k1_gamma_Agg(pubn, msg, sigd, sigz, datalistnum, outpub+Aggindex, outmsg+Aggindex, A+Aggindex, &outSize  ,&sumZ);
        secp256k1_scalar_add(&SumZ,&SumZ,&sumZ);
        break;
    default:
        break;
    }
    free(pubn);
    free(msg);
    free(sigd);
    free(sigz);
}


/* 定向发送数据 */
void Directed_sending_of_data(int rece_port,char *jsondata, int type){
    char message[256]={'\0'};
    size_t message_with_ts_size = 0;
    char message_with_ts[486]={'\0'};
    time_t current_time = time(NULL);
    struct sockaddr_in seed_node_in2;
    seed_node_in2.sin_family = AF_INET;
    if(rece_port == 10000){
        seed_node_in2.sin_port = htons(45000);
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
    case 4:
        sprintf(message, "message: [%d]: %s", node_ID, DATA_TYPE_3);
        message_with_ts_size = sprintf(message_with_ts, "%s ts = %ld", message, current_time) + 1;
        
        res = pittacus_gossip_send_data_single(gossip, (const uint8_t *)message_with_ts, message_with_ts_size, &seed_node_addr2, updated_self_addr_size);
        if(res<0){
            printf("定向发送数据失败，类型为:%d\n",type);
        }else{
            isjoin = 0;
        }
        return;
    default:
        break;
    }

    /* DLCV数据为空 sigd和sigz数据也为空 gama数据是乱码 前面的信息给60个字节 则 json数据每次传426个字节*/
    int len = strlen(jsondata);
   /*  printf("json数据有多少：%d\n",len);  */
    /* 一共需要分成datanum段 */
    int datanum = len%400==0?len/400:len/400+1;
    char temp[420]={'\0'};
    if(jsondata!=NULL && len>400){
        /* json数据太多 udp数据包装不下 有效负载不超过486字节  聚合签名越多 数据越多 如果每次发送都要分包 也太难了 */
        for(int i=0;i<datanum;i++){
            strncpy(temp,jsondata,400);
            /* 给数据包附上长度 */
            message_with_ts_size = sprintf(message_with_ts, "%s%d;datalength=%d (%s)", message,i,datanum,temp) + 1;
            
            /* printf("message_with_ts:%s\n",message_with_ts);
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
        res = pittacus_gossip_send_data_single(gossip, (const uint8_t *)message_with_ts, message_with_ts_size, &seed_node_addr2, updated_self_addr_size);
        if(res<0){
                printf("定向发送数据失败，类型为:%d\n",type);
                return;
            }
    }

    return;
}
int sleepTime(int n){
    int number;
    // 设置随机数种子
    srand(time(NULL));
    // 生成随机数
    number = rand() % n + 1;
    return number;
}
/* 判定为没有子节点 */
void *send_my_report(void *th){
    /* 先睡5秒  */
    sleep(5);
    /* 为了模拟发送6000多个字节的时间效果 多发几次让集群充满数据 */
   int sendtimes=3;
    /* 再判断是否有子节点 */
    if((!has_child) && (father_ID!=-1)){
        printf("%d准备发送报告给父节点\n",node_ID);
        /* 准备发送报告给父节点 */
            cJSON * report = cJSON_CreateObject();
            Report_structure_to_JSON(report,mydata);
            char *json_data = NULL;
            json_data = cJSON_PrintUnformatted(report); // JSON数据结构转换为JSON字符串
            /* 将设备认证报告发送给父节点 */
            if(report!=NULL){
                while(sendtimes!=0 && json_data!=NULL){
                    Directed_sending_of_data(father_ID,json_data,2);/* Invalid read of size 8 */
                    sleep(1);
                    sendtimes--;
                }
                /* 需要释放掉 */
                free(json_data);
                json_data = NULL;
                cJSON_Delete(report);
                report = NULL;
                exit(2);
            }
        }
    return;
}

/* 判断聚合 */
void *Judgment_aggregation(void *th)
{
    int times = 10;
   // int temp = 0;
    int unreceNum = 0;
    while (1)
    {
        /* 适应6800多字节证书的等待时间 */
            sleep(15);
            // if (times < 3)
            // {
            //     sleep(20);
            // }
            // else
            // {
            //     unreceNum = childNum - rece_report_num;
            //     sleep(5 * unreceNum);
            // }

            /* 所有子节点的报告均接收到 进行聚合 这里的判断条件不太严谨 有可能收到一个子节点的消息立马收到一个报告  这样也会聚合 可能也需要另起线程来判断 报告至少延迟5秒中 也许不会？*/
            /* 设定一个接收时间 例如20秒之后 不论子节点是否接收 直接聚合 */
            /* 因为是另起的线程 可能出现主线程在访问变量时分线程也在访问 所以安全起见需要对访问的变量上锁 这里就先不写了 太多啦 */
            /* 每10秒判断一次 */
            /* 在这里加锁是会造成死锁？ 当锁包括了if操作 */
            // pthread_mutex_lock(&mutex);
            //  读取变量的代码
            // temp = rece_report_num;
            // pthread_mutex_unlock(&mutex);
            printf("%d接收报告数：%d,子节点数：%d\n", node_ID, rece_report_num, childNum);
            if ((rece_report_num == childNum && !hasAGG) || (times == 0 && !hasAGG))
            {
                /* 只聚合一次 */
                printf("%d节点开始聚合\n", node_ID);
                /* 进行聚合 两种情况 第一次聚合 或者 已经进行过聚合*/
                if (is_Agg)
                {
                    /* 已经进行过聚合 */
                    AGG_Report(2);
                }
                else
                {
                    /* 第一次聚合 将自己的报告和子节点的报告聚合发送给父节点*/
                    AGG_Report(1);
                }
                hasAGG = true;
                /* 需要发送的是聚合签名的结果*/
                cJSON *cjson = cJSON_CreateObject();
                Convert_aggregated_reports_to_JSON_data(cjson, outpub, A, outmsg, SumZ);
                /* 发送给父节点 */
                char *json_data = cJSON_PrintUnformatted(cjson); // JSON数据结构转换为JSON字符串
                // printf("发送给父节点的聚合报告为：%s\n",json_data);

                /* 将聚合结果发送给父节点 */
                int sendtimes = 8;
                if (cjson != NULL)
                {
                    while (sendtimes != 0 && json_data != NULL)
                    {
                        Directed_sending_of_data(father_ID, json_data, 3);
                        sleep(1);
                        sendtimes--;
                    }
                    free(json_data);
                    json_data = NULL;
                    cJSON_Delete(cjson);
                    cjson = NULL;
                }

                /* 发送完报告释放内存 */
                free(outpub);
                free(A);
                free(outmsg);
                exit(2);
            }
            else
            {
                times--;
            }
    }
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
/* 数据接收器回调 每次接收到的数据会在下一次tick时在集群传播*/
void data_receiver(void *context, pittacus_gossip_t *gossip, const uint8_t *data, size_t data_size) {
    // printf("Data arrived: %s\n", data);
    char message[256];
    /* 一个足够大的字符数组来保存数据 */
    char data_char[600];
    sprintf(data_char,"%s",data);
    /* 哪个节点发送过来的 */
    int id = 0;
    sscanf(data_char,"%*[^[][%d[^]]",&id);
    if(!is_first && is_in(data_char,DATA_MESSAGE)==1){
        /* 不是第一次收到认证请求 直接return  */
        return;
    }
    /* 随后对数据进行判断 是认证请求 还是设备认证报告 还是不含签名值的设备认证报告*/
    if( is_in(data_char,DATA_MESSAGE)==1 && is_first){
        /* 说明是认证请求 且是第一次收到认证请求 改为false 之后收到的认证请求不予理会*/
        is_first = false;
        /* 给父节点发送一个消息  请父节点记住该节点为子节点 最多发两次*/
        father_ID = id;
        Directed_sending_of_data(father_ID,NULL,1);
          
        
        /* 没有子节点时构造json数据发送出去 发送的时机很重要 考虑另起一个线程来做 */
        pthread_t thrd;
        int thread_sd = 1000;
        /* 设置子线程大小 */
        pthread_attr_t thread_attr;
        size_t stack_size = 64 * 1024 * 1024; // 64 MB
        pthread_attr_init(&thread_attr);
        pthread_attr_setstacksize(&thread_attr, stack_size);
        if (pthread_create(&thrd, NULL, send_my_report, &thread_sd) != 0)
        {
            printf("thread error:%s \n", strerror(errno));
            return -1;
        }
        /* 设置成可分离 */
        pthread_detach(thrd);
    }else if(is_in(data_char,DATA_MESSAGE2)==1){
        /* 是子节点发来的 将其放入子节点列表*/
        if(is_in_array(child_ID,childNum,id)==-1){
            child_ID[childNum] = id;
            childNum++;
        }
        if (!has_child)
        {
            has_child = true;
            /*  收到认证请求后 另启线程 设定接收数据的时间为30 30秒过后 无论子节点报告是否收齐 开始聚合*/
            pthread_t thrd2;
            int thread_sd = 1000;
            /* 设置子线程大小 */
            pthread_attr_t thread_attr;
            size_t stack_size = 64 * 1024 * 1024; // 64 MB
            pthread_attr_init(&thread_attr);
            pthread_attr_setstacksize(&thread_attr, stack_size);
            if (pthread_create(&thrd2, NULL, Judgment_aggregation,&thread_sd ) != 0)
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
                strcpy(data_packet[index][dataindex], temp);
                data_packet_hasRece[index][dataindex] = true;
                /* 判断数据包是否接收完毕 */
                if (Has_the_data_packet_been_received(index))
                {
                    printf("%d子节点的数据接收完毕!\n",id);
                    hasReceived[index] = true;
                    /* 接收完毕 单个设备认证报告的数据包大概在6900字节*/
                    char json_char[8000]={'\0'};
                    for (int i = 0; i < deviceDatanum[index]; i++)
                    {
                        strcat(json_char, data_packet[index][i]);
                    }
                    //printf("完整的数据为:%s\n",json_char); 
                    cJSON *cjson = cJSON_Parse(json_char);
                    if (cjson != NULL)
                    {
                        EC_Equipment_Certification_Report data;
                        Json_to_Report_structure(cjson, &data,id);
                        datalist[datalistnum] = data;
                        datalistID[datalistnum] = id;
                        datalistnum++;
                        //pthread_mutex_lock(&mutex);
                        rece_report_num++;
                        // 修改变量的代码
                       // pthread_mutex_unlock(&mutex); 
                        cJSON_Delete(cjson);
                    }
                    else
                    {
                        printf("json数据解析失败!\n");
                    }
                }
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
                strcpy(data_packet[index][dataindex], temp);
                data_packet_hasRece[index][dataindex] = true;
                /* 判断数据包是否接收完毕 */
                if (Has_the_data_packet_been_received(index))
                {
                    printf("%d子节点的数据接收完毕!\n",id);
                    hasReceived[index] = true;
                    /* 接收完毕可以聚合了 */
                    if (is_first_AGG)
                    {
                        /* 给sumz初始化  */
                        secp256k1_scalar_set_int(&SumZ, 0);
                        is_first_AGG = false;
                    }
                    /* 接收完毕 聚合报告的数据包长度依据通信图而定 采取动态分配*/
                    char *json_char=(char*)calloc(deviceDatanum[index]*420,sizeof(char));
                    for (int i = 0; i < deviceDatanum[index]; i++)
                    {
                        strcat(json_char, data_packet[index][i]);
                    }
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
                        json_char = NULL;
                    }
                }
            }
        }
    }

    return ;
}

void deviceStart()
{
    /* 设备启动 */
    /* 本设备的认证报告 */
    Single_device_startup_simulation2(node_ID, &mydata);
    /*  把数据添加到聚合的报告列表里  */
    datalist[datalistnum] = mydata;
    datalistID[datalistnum] = node_ID;
    datalistnum++;
}

void gossip_node(){
    char message_with_ts[256];
    size_t message_with_ts_size = 0;
    char message[256];
    sprintf(message, "message: [%d]: %s", node_ID, DATA_MESSAGE);

    struct sockaddr_in self_in;
    self_in.sin_family = AF_INET;
    self_in.sin_port = start_port+node_ID; // pick up a random port.
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
        printf("gossip%d节点初始化结束成功！\n",node_ID);
    }

    // Connect to the active seed node.
    struct sockaddr_in seed_node_in;
    seed_node_in.sin_family = AF_INET;
    seed_node_in.sin_port = htons(45000);
    inet_aton("127.0.0.1", &seed_node_in.sin_addr);

    pittacus_addr_t seed_node_addr = {
        .addr = (const pt_sockaddr *) &seed_node_in,
        .addr_len = sizeof(struct sockaddr_in)
    };

    int join_result = pittacus_gossip_join(gossip, &seed_node_addr, 1);
    if (join_result < 0) {
        fprintf(stderr, "Gossip join failed: %d\n", join_result);
        pittacus_gossip_destroy(gossip);
        return -1;
    }else{
        printf("%d节点加入集群成功！\n",node_ID);
    }

    /* 启动设备 */
    deviceStart();

    // Force Pittacus to send a Hello message.
    if (pittacus_gossip_process_send(gossip) < 0) {
        fprintf(stderr, "Failed to send hello message to a cluster.\n");
        pittacus_gossip_destroy(gossip);
        return -1;
    }
   

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
    int send_times = 3;
    
    while (1) {
        gossip_poll_fd.revents = 0;
        poll_result = poll(&gossip_poll_fd, 1, poll_interval);
        
        if (poll_result > 0) {
            if (gossip_poll_fd.revents & POLLERR) {
                fprintf(stderr, "%d:Gossip socket failure: %s\n", node_ID,strerror(errno));
                pittacus_gossip_destroy(gossip);
                return -1;
            } else if (gossip_poll_fd.revents & POLLIN) {
                // Tell Pittacus to read a message from the socket.
                recv_result = pittacus_gossip_process_receive(gossip);
                if (recv_result < 0) {
                    fprintf(stderr, "%d:Gossip receive failed: %d\n", node_ID,recv_result);
                   /*  pittacus_gossip_destroy(gossip);
                    return -1; */
                }
            }
        } else if (poll_result < 0) {
            fprintf(stderr, "Poll failed: %s\n", strerror(errno));
            pittacus_gossip_destroy(gossip);
            return -1;
        }
        
        
        // Send some data periodically.
         /* 加入集群之后 向种子节点发一个消息 最多发两次*/
        int times = 2;
        while(isjoin == 1 && times >0){
            Directed_sending_of_data(10000,NULL,4);
            times--;
            if(isjoin){
                /* 发送一次之后还是1 说明发送失败 等一秒再发 */
                sleep(1);
            }
        }
        
        time_t current_time = time(NULL);
        if (send_times>0 && previous_data_msg_ts + send_data_interval <= current_time && !is_first) {
            previous_data_msg_ts = current_time;
            message_with_ts_size = sprintf(message_with_ts, "%s (ts = %ld)", message, current_time) + 1;
            /* 在集群中传播数据 */
            //printf("在集群中传送数据%s\n,",message);
            int res = pittacus_gossip_send_data(gossip, (const uint8_t *) message_with_ts, message_with_ts_size);
            if(res < 0){
                printf("在集群中传送数据出错\n");
            }else{
                /* 只在集群中传送send_times次 */
                send_times--;
            }
        }

        // Tell Pittacus to write existing messages to the socket. 告诉Pittacus将现有消息写入套接字。
        send_result = pittacus_gossip_process_send(gossip);
        if (send_result < 0) {
            fprintf(stderr, "%d:Gossip send failed: %d, %s\n",node_ID, send_result, strerror(errno));
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
        /* COUNT = strtol(argv[1], NULL, 0); */
        /* 在此处赋值node_ID */
        node_ID = strtol(argv[1], NULL, 0);
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

    /* 运行普通节点 普通节点 既要发送认证请求 又要发送认证报告 接收认证报告 */
    outpub = (secp256k1_ge *)malloc(100 * sizeof(secp256k1_ge));
    A = (secp256k1_ge *)malloc(100 * sizeof(secp256k1_ge));
    outmsg = (secp256k1_scalar *)malloc(100 * sizeof(secp256k1_scalar));
    gossip_node();
   /*  testAGGReportandVerify(); */
    /* test_receviceReport(); */
    /* testAGGReportandVerify(); */
    /* Single_device_startup_simulation(node_ID,&mydata); */
    

    /* Extract_public_key_from_certificate(1); */
    /* shutdown */
    free(STATIC_CTX);
    secp256k1_context_destroy(CTX);
    printf("no problems found!\n");

    return 0;
}