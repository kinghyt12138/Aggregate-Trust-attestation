/*
 * @Author: king
 * @Date: 2023-03-10 20:29:15
 * @LastEditors: WHU黄琰婷 huangyantingwhu@whu.edu.cn
 * @LastEditTime: 2023-11-09 10:42:48
 * @FilePath: /secp256k1-master/src/gammaAggregate_impl.h
 * @Description: 聚合签名实现文件
 * 
 * Copyright (c) 2023 by ${git_name_email}, All Rights Reserved. 
 */


#ifndef GAMMAAGGREGATE_IMPL_H_
#define GAMMAAGGREGATE_IMPL_H_



#include "field.h"
#include "group.h"
#include "ecmult.h"
#include "ecmult_gen.h"
#include "gammaAggregate.h"
#include "scalar.h"
#include "scalar_impl.h"

  void printChar(const unsigned char *r,int size)
{
    /*单位为字节*/
	 printf("size（单位为字节） = %d \n",  size);
	int i = 0;
   for ( i = 0;i< size; i++){
        printf(" %2.2x",r[i]);
        if((i+1)%16==0){
            printf(" \n" );
        }
   }
   printf(" \n" );
   
}

 void printScalar(const secp256k1_scalar *r,int size)
{
	printf("size（以32字节数为单位） = %d \n",  size);
	int i = 0;
   for ( i = 0;i< size; i++)
   { unsigned char message_char[32];
   secp256k1_scalar_get_b32(message_char, r+i);
   printChar(message_char, 32);

   }


   printf(" \n" );
}
void printGe(const secp256k1_ge *r,  int size)
{
	 printf("size = %d \n",  size);
	int i = 0;
  for ( i = 0;i< size; i++)
  {
	   unsigned char tmp[64];

      secp256k1_ge_to_char(tmp,  r+i);
      printChar(tmp, 64);
  }


  printf("end \n" );
}

 void printGej(const secp256k1_gej *r,  int size)
{
	 printf("size = %d \n",  size);
	int i = 0;

	secp256k1_ge  ge;
   for ( i = 0;i< size; i++)
   {
	   unsigned char tmp[64];

	   secp256k1_ge_set_gej(&ge,r+i);
        /*新版没有char函数*/
       secp256k1_ge_to_char(tmp,  &ge);
       printChar(tmp, 64);
   }


   printf("end \n" );
}
/**
 * @description: 
 * @param {secp256k1_ecmult_gen_context} *ctx 加速aG计算所需要的上下文
 * @param {secp256k1_scalar} *sigd  签名值的组成部分d
 * @param {secp256k1_scalar} *sigz  签名值的组成部分z  d和z共同组成签名值
 * @param {secp256k1_scalar} *seckey  私钥
 * @param {secp256k1_scalar} *message  签名消息
 * @param {secp256k1_scalar} *nonce   随机数
 * @param {int} *recid
 * @return {*}
 */
static int secp256k1_gamma_sig_sign(const secp256k1_ecmult_gen_context *ctx, secp256k1_scalar *sigd,
		secp256k1_scalar *sigz, const secp256k1_scalar *seckey, const secp256k1_scalar *message, const secp256k1_scalar *nonce, int *recid) {
    unsigned char b[32];
    /*计算结果A 雅克比坐标*/
    secp256k1_gej rp;
    /*椭圆曲线点坐标 仿射坐标*/
    secp256k1_ge r;
    secp256k1_scalar n;

    unsigned char message_char[32];
    secp256k1_sha256 hasher;
    unsigned char output_hash[32];

    unsigned char tmp[64];
    /*公钥*/
    secp256k1_gej pubkey;


    int overflow = 0;
    /*点乘计算 A=rP*/
    secp256k1_ecmult_gen(ctx, &rp, nonce);      /* A = rp = nonce * P  */
    /*仿射坐标和雅克比坐标变换*/
    secp256k1_ge_set_gej(&r, &rp);
    /*将椭圆曲线点A转换为字符存入tmp*/
    secp256k1_ge_to_char(tmp, &r);

/*
    printf("签名时：A =  " );
    printChar(tmp, sizeof(tmp)); */
    /*计算Hash（A）*/
    secp256k1_sha256_initialize(&hasher);
    secp256k1_sha256_write(&hasher, tmp, sizeof(tmp));
    secp256k1_sha256_finalize(&hasher,output_hash);

    /*d=Hash(A)*/
    secp256k1_scalar_set_b32(sigd, output_hash, &overflow);
    /*
    printf("签名d为：");
    printScalar(sigd,1);
    printf("私钥key为：");
    printScalar(seckey,1);
    printf("消息msg为：");
    printScalar(message,1);*/

    VERIFY_CHECK(overflow == 0);

    if (recid) {
        /* The overflow condition is cryptographically unreachable as hitting it requires finding the discrete log
         * of some P where P.x >= order, and only 1 in about 2^127 points meet this criteria.
         */
        /*溢出条件在密码学上是不可达到的 因为命中它需要找到某个p的离散对数，其中P.x>=阶，大约2的127次方中只有一点满足此条件
        */
        *recid = (overflow ? 2 : 0) | (secp256k1_fe_is_odd(&r.y) ? 1 : 0);
    }

    /*计算公钥*/
    secp256k1_ecmult_gen(ctx, &pubkey, seckey);


    /*仿射坐标和雅克比坐标变换*/
    secp256k1_ge_set_gej(&r, &pubkey);                    /*gej to ge */
    secp256k1_ge_to_char(tmp, &r);
    secp256k1_scalar_get_b32(message_char, message);

    /*计算hash（X，m）*/
    secp256k1_sha256_initialize(&hasher);
    secp256k1_sha256_write(&hasher, tmp, sizeof(tmp));
    secp256k1_sha256_write(&hasher, message_char, sizeof(message_char));
    secp256k1_sha256_finalize(&hasher,output_hash);


    /*e=Hash（X，m）*/
    secp256k1_scalar_set_b32(sigz, output_hash, &overflow);
    VERIFY_CHECK(overflow == 0);
    /*
    printf("签名时e为");
    printScalar(sigz,1);
    */
    /**
     * 这里开始计算z=rd-ex mod q
    */
    /*计算ex*/
    secp256k1_scalar_mul( sigz, sigz, seckey);
    /*变成-ex*/
    secp256k1_scalar_negate(sigz, sigz);
    /*计算rd*/
    secp256k1_scalar_mul(nonce, nonce, sigd);
    /*计算z=rd-ex*/
    secp256k1_scalar_add(sigz, sigz, nonce);
/*
    printf("签名时z为：");
    printScalar(sigz,1);*/
    
    secp256k1_scalar_clear(&n);
    secp256k1_gej_clear(&rp);
    secp256k1_gej_clear(&pubkey);
    secp256k1_ge_clear(&r);

    return 1;
}



/**
 * @description: 伽马签名的验证 需要的参数是公钥 消息 签名值
 * @param {secp256k1_ecmult_context} *ctx 加速点乘计算的上下文
 * @param {secp256k1_scalar} *sigd 签名值之一d
 * @param {secp256k1_scalar} *sigz 签名值之一z
 * @param {secp256k1_ge} *pubkey 公钥
 * @param {secp256k1_scalar} *message 消息本身
 * @return {*}
 */
static int secp256k1_gamma_sig_verify(const secp256k1_scalar *sigd, const secp256k1_scalar *sigz,
		const secp256k1_ge *pubkey, const secp256k1_scalar *message) {
	unsigned char message_char[32];
	secp256k1_sha256 hasher;
	unsigned char output_hash[32];
    secp256k1_scalar e, dn,zn;
    unsigned char pub_char[64];

    secp256k1_gej pubkeyj;
    secp256k1_gej pr;

    secp256k1_gej A;
    secp256k1_ge Ae;

    secp256k1_scalar hasha;

    int overflow = 0;
    
    secp256k1_ge_to_char(pub_char, pubkey);
    secp256k1_scalar_get_b32(message_char, message);
    /*计算Hash（X，m）*/
    secp256k1_sha256_initialize(&hasher);
    secp256k1_sha256_write(&hasher, pub_char, sizeof(pub_char));
    secp256k1_sha256_write(&hasher, message_char, sizeof(message_char));
    secp256k1_sha256_finalize(&hasher,output_hash);
    /*e=Hash（X，m）*/
    secp256k1_scalar_set_b32(&e, output_hash, &overflow);

    VERIFY_CHECK(overflow == 0);
    /*仿射坐标和雅克比坐标变换*/
    secp256k1_gej_set_ge(&pubkeyj, pubkey);
    /*计算d的逆元 d^-1*/
    secp256k1_scalar_inverse_var(&dn, sigd);  /* dn = sigd^(-1) */
    /*计算ed^-1*/
    secp256k1_scalar_mul(&e, &e, &dn);
    /*计算zd^-1*/
    secp256k1_scalar_mul(&zn, sigz, &dn);
    /*计算A=zd^-1P+ed^-1X*/
    secp256k1_ecmult(&A, &pubkeyj, &e, &zn);    /* A = pubkeyj*e + zn*G  */

    /*坐标变换*/
    secp256k1_ge_set_gej(&Ae, &A);
    /*转换成字符*/
    secp256k1_ge_to_char(pub_char, &Ae);

    /*计算hash（A）*/
    secp256k1_sha256_initialize(&hasher);
    secp256k1_sha256_write(&hasher, pub_char, sizeof(pub_char));
    secp256k1_sha256_finalize(&hasher,output_hash);

    secp256k1_scalar_set_b32(&hasha, output_hash, &overflow);

    VERIFY_CHECK(overflow == 0);
    /*判断hash（A）与d是否相等*/
    if(secp256k1_scalar_eq(&hasha, sigd) == 1)
    {
        /*相等则验证成功*/
        // printf("单次签名验证成功！\n");
    	return 1;
    }
    printf("单次签名验证失败！\n");
    /*否则验证失败*/
    return 0;

}

/*gama聚合签名验证foragg*/
static int secp256k1_gamma_sig_verify_forAGG(const secp256k1_scalar *sigd, const secp256k1_scalar *sigz,
		const secp256k1_ge *pubkey, const secp256k1_scalar *message,  secp256k1_ge *Ae) {
	unsigned char message_char[32];
	secp256k1_sha256 hasher;
	unsigned char output_hash[32];
    secp256k1_scalar e, dn,zn;
    unsigned char pub_char[64];

    secp256k1_gej pubkeyj;
    secp256k1_gej pr;

    secp256k1_gej A;
    /*secp256k1_ge Ae;*/

    secp256k1_scalar hasha;

    int overflow = 0;

    secp256k1_ge_to_char(pub_char, pubkey);
    secp256k1_scalar_get_b32(message_char, message);

   

    secp256k1_sha256_initialize(&hasher);
    secp256k1_sha256_write(&hasher, pub_char, sizeof(pub_char));
    secp256k1_sha256_write(&hasher, message_char, sizeof(message_char));
    secp256k1_sha256_finalize(&hasher,output_hash);


    secp256k1_scalar_set_b32(&e, output_hash, &overflow);
    VERIFY_CHECK(overflow == 0);

    secp256k1_gej_set_ge(&pubkeyj, pubkey);
    secp256k1_scalar_inverse_var(&dn, sigd);  /* dn = sigd^(-1) */
    secp256k1_scalar_mul(&e, &e, &dn);
    secp256k1_scalar_mul(&zn, sigz, &dn);
    secp256k1_ecmult(&A, &pubkeyj, &e, &zn);    /* A = pubkeyj*e + zn*G  */

    secp256k1_ge_set_gej( Ae, &A);
    secp256k1_ge_to_char(pub_char, Ae);


    secp256k1_sha256_initialize(&hasher);
    secp256k1_sha256_write(&hasher, pub_char, sizeof(pub_char));
    secp256k1_sha256_finalize(&hasher,output_hash);
    secp256k1_scalar_set_b32(&hasha, output_hash, &overflow);
    VERIFY_CHECK(overflow == 0);
    /* printf("random run \n"); */

    if(secp256k1_scalar_eq(&hasha, sigd) == 1)
    {
        //printf("聚合签名单个签名验证成功！\n");
    	return 1;
    }
    printf("聚合签名单个签名验证失败！\n");
    return 0;



}



/**
 * @description: 
 * @param {secp256k1_ge} *pubkey 公钥
 * @param {secp256k1_scalar} *message 签名消息
 * @param {secp256k1_scalar} *d 签名值之一d
 * @param {secp256k1_scalar} *z 签名值之一z
 * @param {int} size 聚合的签名的个数
 * @param {secp256k1_ge} *outpubkey 聚合的公钥 算是链表？
 * @param {secp256k1_scalar} *outmessage 聚合的消息 算链表?
 * @param {secp256k1_ge} *A
 * @param {int} *outsize 指到链表的哪个位置
 * @param {secp256k1_scalar} *sumZ 总和z 聚合签名值之一
 * @return {*}
 */
static int secp256k1_gamma_Agg(const secp256k1_ge *pubkey, const secp256k1_scalar *message,  const secp256k1_scalar *d,
		const secp256k1_scalar *z, const int size,
		 secp256k1_ge *outpubkey,  secp256k1_scalar *outmessage, secp256k1_ge *A, int *outsize, secp256k1_scalar *sumZ)
{
    int i;
    int pos1 = 0;
    int pos2 = 0;
    /*初始化a*/
    secp256k1_ge  *tempA = (secp256k1_ge*) malloc (size*sizeof(secp256k1_ge));


    /*初始化z 直接初始化成0了*/
   secp256k1_scalar_set_int(sumZ, 0);

    /*T集合*/
   tHatTreeNode *tHat = NULL;
   /*A集合*/
   geTreeNode *aHat = NULL;
    /*聚合过程*/
    for (i = 0; i<size ; i++)
    {
        /*挨个验证*/
    	int check =  secp256k1_gamma_sig_verify_forAGG(d+i,  z+i, pubkey+i, message+i,tempA+i);
        /*是否在T集合中*/
    	 int check1 =  tHatTree_Find ( pubkey+i ,  message+i ,tHat)   ;
         /*是否在A集合中*/
    	int check2 =  geTree_Find ( tempA+i ,aHat) ;
        /*验证成功且不在T集合和A集合中则*/
    	if ( check == 1   &&
    			( check1 == 0) && (check2 == 0 ) )
    	{
            /*插入T集合*/
    		tHat = tHatTree_Insertion(pubkey+i, message+i, tHat);
            /*插入A集合*/
    		aHat = geTree_Insertion(tempA+i, aHat);
            /*给z做累加 z=z+zi mod q*/
    		secp256k1_scalar_add(sumZ, sumZ, z+i);
    	}

    }

    /*将T集合和A集合赋值到参数中 以便验证*/
    tHatTree_inorder(tHat, outpubkey ,outmessage,  &pos1);
    geTree_inorder(aHat, A,  &pos2);

    free(tempA);
    /*释放内存空间*/
    releasetHatTreeNode(tHat);
    releasegeTreeNode(aHat);

    if (pos1 != pos2)
    {
    	return 0;
    }
    else
    {
    	*outsize = pos1;
    }

    return 1;
}


 int secp256k1_ecmult_pippenger_batch_agg(const secp256k1_callback* error_callback,secp256k1_scratch *scratch,  secp256k1_gej *r, const int n_points, const secp256k1_ge  *oldpoints, const secp256k1_scalar *oldscalars, const secp256k1_scalar *inp_g_sc)
 {
    const size_t scratch_checkpoint = secp256k1_scratch_checkpoint(error_callback, scratch);
    /* Use 2(n+1) with the endomorphism, when calculating batch
	    /* Use 2(n+1) with the endomorphism, n+1 without, when calculating batch
	     * sizes. The reason for +1 is that we add the G scalar to the list of
	     * other scalars. */

	size_t entries = 2*n_points + 2;
    secp256k1_ge *points;
    secp256k1_scalar *scalars;
    secp256k1_gej *buckets;
    struct secp256k1_pippenger_state *state_space;
    size_t idx = 0;
    size_t point_idx = 0;
    int i, j;
    int bucket_window;

    secp256k1_gej_set_infinity(r);
    if (inp_g_sc == NULL && n_points == 0) {
        return 1;
    }
    bucket_window = secp256k1_pippenger_bucket_window(n_points);

    /* We allocate PIPPENGER_SCRATCH_OBJECTS objects on the scratch space. If
     * these allocations change, make sure to update the
     * PIPPENGER_SCRATCH_OBJECTS constant and pippenger_scratch_size
     * accordingly. */
    points = (secp256k1_ge *) secp256k1_scratch_alloc(error_callback, scratch, entries * sizeof(*points));
    scalars = (secp256k1_scalar *) secp256k1_scratch_alloc(error_callback, scratch, entries * sizeof(*scalars));
    state_space = (struct secp256k1_pippenger_state *) secp256k1_scratch_alloc(error_callback, scratch, sizeof(*state_space));
    if (points == NULL || scalars == NULL || state_space == NULL) {
        secp256k1_scratch_apply_checkpoint(error_callback, scratch, scratch_checkpoint);
        return 0;
    }
    state_space->ps = (struct secp256k1_pippenger_point_state *) secp256k1_scratch_alloc(error_callback, scratch, entries * sizeof(*state_space->ps));
    state_space->wnaf_na = (int *) secp256k1_scratch_alloc(error_callback, scratch, entries*(WNAF_SIZE(bucket_window+1)) * sizeof(int));
    buckets = (secp256k1_gej *) secp256k1_scratch_alloc(error_callback, scratch, (1<<bucket_window) * sizeof(*buckets));
    if (state_space->ps == NULL || state_space->wnaf_na == NULL || buckets == NULL) {
        secp256k1_scratch_apply_checkpoint(error_callback, scratch, scratch_checkpoint);
        return 0;
    }

    if (inp_g_sc != NULL) {
        scalars[0] = *inp_g_sc;
        points[0] = secp256k1_ge_const_g;
        idx++;
        secp256k1_ecmult_endo_split(&scalars[0], &scalars[1], &points[0], &points[1]);
        idx++;
    }

    while (point_idx < n_points) {
      /*   if (!cb(&scalars[idx], &points[idx], point_idx + cb_offset, cbdata)) {
            secp256k1_scratch_apply_checkpoint(error_callback, scratch, scratch_checkpoint);
            return 0;
        } */
        memcpy(scalars+idx, oldscalars+point_idx, sizeof(secp256k1_scalar));
	    memcpy(points+idx, oldpoints+point_idx, sizeof(secp256k1_ge));
        idx++;
        secp256k1_ecmult_endo_split(&scalars[idx - 1], &scalars[idx], &points[idx - 1], &points[idx]);
        idx++;
        point_idx++;
    }

    secp256k1_ecmult_pippenger_wnaf(buckets, bucket_window, state_space, r, scalars, points, idx);

    /* Clear data */
    for(i = 0; (size_t)i < idx; i++) {
        secp256k1_scalar_clear(&scalars[i]);
        state_space->ps[i].skew_na = 0;
        for(j = 0; j < WNAF_SIZE(bucket_window+1); j++) {
            state_space->wnaf_na[i * WNAF_SIZE(bucket_window+1) + j] = 0;
        }
    }
    for(i = 0; i < 1<<bucket_window; i++) {
        secp256k1_gej_clear(&buckets[i]);
    }
    secp256k1_scratch_apply_checkpoint(error_callback, scratch, scratch_checkpoint);
    return 1;

 }




 int secp256k1_ecmult_strauss_batch_agg(const secp256k1_callback *error_callback,secp256k1_scratch *scratch,
		  secp256k1_gej *result, int num, const secp256k1_gej *points, const secp256k1_scalar *index, const secp256k1_scalar *sumZ)

 {
    struct secp256k1_strauss_state state;
    const size_t scratch_checkpoint = secp256k1_scratch_checkpoint(error_callback, scratch);

     secp256k1_gej_set_infinity(result);
	if (sumZ == NULL && num == 0) {
	    return 1;
	}

    /* We allocate STRAUSS_SCRATCH_OBJECTS objects on the scratch space. If these
     * allocations change, make sure to update the STRAUSS_SCRATCH_OBJECTS
     * constant and strauss_scratch_size accordingly. */
    state.aux = (secp256k1_fe*)secp256k1_scratch_alloc(error_callback, scratch, num * ECMULT_TABLE_SIZE(WINDOW_A) * sizeof(secp256k1_fe));
    state.pre_a = (secp256k1_ge*)secp256k1_scratch_alloc(error_callback, scratch, num * ECMULT_TABLE_SIZE(WINDOW_A) * sizeof(secp256k1_ge));
    state.ps = (struct secp256k1_strauss_point_state*)secp256k1_scratch_alloc(error_callback, scratch, num * sizeof(struct secp256k1_strauss_point_state));

    if (state.aux == NULL || state.pre_a == NULL || state.ps == NULL) {
        secp256k1_scratch_apply_checkpoint(error_callback, scratch, scratch_checkpoint);
        return 0;
    }

    secp256k1_ecmult_strauss_wnaf(&state, result, num, points, index, sumZ);
    secp256k1_scratch_apply_checkpoint(error_callback, scratch, scratch_checkpoint);
    return 1;
 }

 


/**
 * @description: 使用同步点乘完成公钥重构
 * @param {secp256k1_context} *ctx 
 * @param {secp256k1_callback*} error_callback
 * @param {secp256k1_ge} *pub0 第0层公钥
 * @param {secp256k1_scalar} *TCIList TCI值
 * @param {secp256k1_ge} *gamaList 对应的gamma值
 * @param {secp256k1_ge} *pubn 重构出来的公钥 按照聚合顺序排列 这要求TCI和gamma就是按照聚合顺序排列的
 * @return {*}
 */
static void Reconstructing_Public_Key_Synchronization_multiplication(const secp256k1_context *ctx,const secp256k1_callback* error_callback,
const secp256k1_ge *pub0,const secp256k1_scalar *TCIList,const secp256k1_ge *gamaList, secp256k1_gej *pubn)
{
     int totalSize = 2;
//存放的是w和d
     secp256k1_scalar *index =  (secp256k1_scalar*) malloc (totalSize*sizeof(secp256k1_scalar));
     secp256k1_gej *points = (secp256k1_gej *)malloc(totalSize * sizeof(secp256k1_gej));
     //  secp256k1_gej  *result = (secp256k1_gej*) malloc ( sizeof(secp256k1_gej));
     secp256k1_ge *gepoints = (secp256k1_ge *)malloc(totalSize * sizeof(secp256k1_ge));
     //先把0赋值进去
     secp256k1_gej_set_ge(pubn,pub0);

     secp256k1_scratch *scratch = secp256k1_scratch_space_create(ctx, 450000 + 256 * (2 * 1024 + 2));

     int i;
     /*开始重构公钥*/
     secp256k1_sha256 hasher;
     unsigned char output_hash[32];
     unsigned char message_char[32];
     unsigned char tmp[64];
     // 把两个gamma值先放到points里面
     secp256k1_gej_set_ge(points , &gamaList[0]);
     secp256k1_gej_set_ge(points +1, &gamaList[1]);

     memcpy(gepoints + 0,  &gamaList[0], sizeof(secp256k1_ge));
     memcpy(gepoints + 0, &gamaList[1], sizeof(secp256k1_ge));

     int overflow = 0;
     { /* e2=H(gama2||TCI2) */
         secp256k1_ge_to_char(tmp, &gamaList[1]);
         secp256k1_scalar_get_b32(message_char, &TCIList[1]);
         secp256k1_sha256_initialize(&hasher);
         secp256k1_sha256_write(&hasher, tmp, sizeof(tmp));
         secp256k1_sha256_write(&hasher, message_char, sizeof(message_char));
         secp256k1_sha256_finalize(&hasher, output_hash);
         secp256k1_scalar_set_b32(index+1, output_hash, &overflow);
         VERIFY_CHECK(overflow == 0);
     }

     { /* e1=H(gama1||TCI1) */
         secp256k1_ge_to_char(tmp, &gamaList[0]);
         secp256k1_scalar_get_b32(message_char, &TCIList[0]);
         secp256k1_sha256_initialize(&hasher);
         secp256k1_sha256_write(&hasher, tmp, sizeof(tmp));
         secp256k1_sha256_write(&hasher, message_char, sizeof(message_char));
         secp256k1_sha256_finalize(&hasher, output_hash);
         secp256k1_scalar_set_b32(index , output_hash, &overflow);
         VERIFY_CHECK(overflow == 0);
     }

     {       /*compute ecumulate*/

       int straussFunction = 0;
       int max_points = secp256k1_pippenger_max_points(error_callback,scratch);
       if (max_points == 0) {
           printf("max_points等于0\n");
           return;
       } else if (max_points > ECMULT_MAX_POINTS_PER_BATCH) {
           max_points = ECMULT_MAX_POINTS_PER_BATCH;
       }
       int  n_batches = (totalSize+max_points-1)/max_points;
       int  n_batch_points = (totalSize+n_batches-1)/n_batches;

       if (n_batch_points >= ECMULT_PIPPENGER_THRESHOLD) {
    	   straussFunction = 0;
       } else {
    	   straussFunction = 1;
           max_points = secp256k1_strauss_max_points(error_callback,scratch);
           if (max_points == 0) {
               printf("max_points等于0\n");
               return;
           }
           n_batches = (totalSize+max_points-1)/max_points;
           n_batch_points = (totalSize+n_batches-1)/n_batches;
       }

      if (straussFunction == 1)
      {
      //走的这个分支
          for(i = 0; i < n_batches; i++) {
              int nbp = totalSize < n_batch_points ? totalSize : n_batch_points;
              int offset = n_batch_points*i;
              secp256k1_gej tmp;
              if (!secp256k1_ecmult_strauss_batch_agg(error_callback, scratch, &tmp, nbp , points+offset, index+offset, NULL)) {
                  printf("secp256k1_ecmult_strauss_batch_agg failed\n");
                  return;
              }
              secp256k1_gej_add_var(pubn, pubn, &tmp, NULL);
              totalSize -= nbp;
          }
      }else
      {
          for(i = 0; i < n_batches; i++) {
              int nbp = 0;

              if (totalSize < n_batch_points)
              {
            	  nbp = totalSize;
              }else
              {
            	  nbp = n_batch_points;
              }
              int offset = n_batch_points*i;
              secp256k1_gej tmp;
              int ret = secp256k1_ecmult_pippenger_batch_agg(error_callback, scratch,  &tmp, nbp , gepoints+offset, index+offset, NULL  );
              if(ret == 0){
                printf("secp256k1_ecmult_pippenger_batch_agg return 0\n");
              }
              secp256k1_gej_add_var(pubn, pubn, &tmp, NULL);
              totalSize -= nbp;
          }
      }

       /*printf( "%d, %d, %d",max_points, n_batches, n_batch_points );*/

       /*secp256k1_ecmult_strauss_wnaf(ctxecmult, &state, result, totalSize , points, index, sumZ);
       secp256k1_scratch_deallocate_frame(scratch);  */

     }
        /*判断计算结果是否为无穷远 是无穷远则验证成功 否则验证失败*/
    //    free(result);
       free(index);
       free(points);
       free(gepoints);

       secp256k1_scratch_destroy(error_callback,scratch);
    //   return (re);
}

/**
 * @description: 聚合验证 参数为T链表A链表和z总和
 * @param {secp256k1_context} *ctx 保存上下文信息的不透明数据结构
 * @param {secp256k1_ecmult_context} *ctxecmult 计算点乘计算的上下文
 * @param {secp256k1_ge} *pubkey 公钥链表
 * @param {secp256k1_scalar} *message 消息链表
 * @param {secp256k1_ge} *A A链表
 * @param {int} size 需要的验证的个数
 * @param {secp256k1_scalar} *sumZ 总和z
 * @return {*}
 */
static int secp256k1_gamma_Agg_verify2(const secp256k1_context *ctx,const secp256k1_callback* error_callback, const secp256k1_ge *pubkey, const secp256k1_scalar *message,
		const secp256k1_ge *A, const int size,  const secp256k1_scalar *sumZ,secp256k1_gej * result2)
{
    /*检查公钥和信息是否有重复元素且顺序是否正确*/
     if (checkTSet(pubkey, message, size)== 0)
     {
        printf("公钥和信息有重复元素或者长度不对\n");
    	 return 0;
     }
    /*A链表是否有重复元素且顺序是否正确*/
     if (checkASet(A, size) == 0)
     {
        printf("A链表有重复元素或长度与size不相等\n");
    	return 0;
     }
     /*printf("verifySize =  %d ",   size);*/

     int totalSize = 2*size;
//存放的是w和d
     secp256k1_scalar *index =  (secp256k1_scalar*) malloc (totalSize*sizeof(secp256k1_scalar));
     secp256k1_gej  *points = (secp256k1_gej*) malloc (totalSize*sizeof(secp256k1_gej));
     secp256k1_gej  *result = (secp256k1_gej*) malloc ( sizeof(secp256k1_gej));
     secp256k1_ge   *gepoints = (secp256k1_ge *) malloc (totalSize*sizeof(secp256k1_ge ));
     
     secp256k1_gej_set_infinity(result);

     secp256k1_scratch *scratch = secp256k1_scratch_space_create(ctx, 450000 + 256 * (2 * 1024 + 2));
     /*  secp256k1_scratch *scratch = secp256k1_scratch_space_create(ctx, 10*(450000 + 256 * (2 * 1024 + 2))); */

     int i;
     /*开始聚合验证*/
     for (i = 0; i<size ; i++)
        {
    	    secp256k1_sha256 hasher;
    	    unsigned char output_hash[32];
    	    unsigned char message_char[32];
    	    unsigned char tmp[64];

    	    secp256k1_gej_set_ge(points+i, pubkey+i);
    	    secp256k1_gej_set_ge(points+size + i, A+i);

    	    memcpy(gepoints+i, pubkey+i, sizeof(secp256k1_ge));
    	    memcpy(gepoints+size + i, A+i, sizeof(secp256k1_ge));

    	    int overflow = 0;
    	    {  /* d_i = H(A_i) */
    	    secp256k1_ge_to_char(tmp, A+i);
     	    secp256k1_sha256_initialize(&hasher);
    	    secp256k1_sha256_write(&hasher, tmp, sizeof(tmp));
    	    secp256k1_sha256_finalize(&hasher,output_hash);
    	    secp256k1_scalar_set_b32(index + size + i, output_hash, &overflow);

    	    secp256k1_scalar_negate(index + size + i, index+ size +i);

    	    VERIFY_CHECK(overflow == 0);
    	    }

    	    {    /* e_i = H(X_i, m_i) */
    	    secp256k1_ge_to_char(tmp, pubkey+i);
    	    secp256k1_scalar_get_b32(message_char, message+i);
    	    secp256k1_sha256_initialize(&hasher);
    	    secp256k1_sha256_write(&hasher, tmp, sizeof(tmp));
    	    secp256k1_sha256_write(&hasher, message_char, sizeof(message_char));
    	    secp256k1_sha256_finalize(&hasher,output_hash);
    	    secp256k1_scalar_set_b32(index  + i, output_hash, &overflow);
    	    VERIFY_CHECK(overflow == 0);
    	    }
        }

     {       /*compute ecumulate*/

       if (sumZ == NULL || size == 0) {
           printf("sumz = 0或者size=0\n");
           return 0;
       }
       int straussFunction = 0;
       int max_points = secp256k1_pippenger_max_points(error_callback,scratch);
       if (max_points == 0) {
           printf("max_points等于0\n");
           return 0;
       } else if (max_points > ECMULT_MAX_POINTS_PER_BATCH) {
           max_points = ECMULT_MAX_POINTS_PER_BATCH;
       }
       int  n_batches = (totalSize+max_points-1)/max_points;
       int  n_batch_points = (totalSize+n_batches-1)/n_batches;
    //    printf("max_points等于%d\n",max_points);
    //    printf("n_batches等于%d\n",n_batches);
    //    printf("n_batch_points等于%d\n",n_batch_points);

       if (n_batch_points >= ECMULT_PIPPENGER_THRESHOLD) {
    	   straussFunction = 0;
       } else {
    	   straussFunction = 1;
           max_points = secp256k1_strauss_max_points(error_callback,scratch);
           if (max_points == 0) {
               printf("max_points等于0\n");
               return 0;
           }
           n_batches = (totalSize+max_points-1)/max_points;
           n_batch_points = (totalSize+n_batches-1)/n_batches;
       }

      if (straussFunction == 1)
      {
          for(i = 0; i < n_batches; i++) {
              int nbp = totalSize < n_batch_points ? totalSize : n_batch_points;
              int offset = n_batch_points*i;
              secp256k1_gej tmp;
              if (!secp256k1_ecmult_strauss_batch_agg(error_callback, scratch, &tmp, nbp , points+offset, index+offset, i == 0 ? sumZ : NULL  )) {
                  printf("secp256k1_ecmult_strauss_batch_agg failed\n");
                  return 0;
              }
              secp256k1_gej_add_var(result, result, &tmp, NULL);
              totalSize -= nbp;
          }
      }else
      {
          for(i = 0; i < n_batches; i++) {
              int nbp = 0;

              if (totalSize < n_batch_points)
              {
            	  nbp = totalSize;
              }else
              {
            	  nbp = n_batch_points;
              }
              int offset = n_batch_points*i;
              secp256k1_gej tmp;
              int ret = secp256k1_ecmult_pippenger_batch_agg(error_callback, scratch,  &tmp, nbp , gepoints+offset, index+offset, i == 0 ? sumZ : NULL  );
              if(ret == 0){
                printf("secp256k1_ecmult_pippenger_batch_agg return 0\n");
              }
              secp256k1_gej_add_var(result, result, &tmp, NULL);
              totalSize -= nbp;
          }
      }

       /*printf( "%d, %d, %d",max_points, n_batches, n_batch_points );*/

       /*secp256k1_ecmult_strauss_wnaf(ctxecmult, &state, result, totalSize , points, index, sumZ);
       secp256k1_scratch_deallocate_frame(scratch);  */

     }
        /*判断计算结果是否为无穷远 是无穷远则验证成功 否则验证失败*/
       int re = secp256k1_gej_is_infinity(result);
       result2 = result;
       free(result);
       free(index);
       free(points);
       free(gepoints);
        if(re == 0){
            printf("返回值为0，聚合验证失败\n");
       }else{
            // printf("返回值不为0，聚合验证成功\n");
       }

       secp256k1_scratch_destroy(error_callback,scratch);
      return (re);
}


/**
 * @description: 聚合验证 参数为T链表A链表和z总和
 * @param {secp256k1_context} *ctx 保存上下文信息的不透明数据结构
 * @param {secp256k1_ecmult_context} *ctxecmult 计算点乘计算的上下文
 * @param {secp256k1_ge} *pubkey 公钥链表
 * @param {secp256k1_scalar} *message 消息链表
 * @param {secp256k1_ge} *A A链表
 * @param {int} size 需要的验证的个数
 * @param {secp256k1_scalar} *sumZ 总和z
 * @return {*}
 */
static int secp256k1_gamma_Agg_verify(const secp256k1_context *ctx,const secp256k1_callback* error_callback, const secp256k1_ge *pubkey, const secp256k1_scalar *message,
		const secp256k1_ge *A, const int size,  const secp256k1_scalar *sumZ)
{
    /*检查公钥和信息是否有重复元素且顺序是否正确*/
     if (checkTSet(pubkey, message, size)== 0)
     {
        printf("公钥和信息有重复元素或者长度不对\n");
    	 return 0;
     }
    /*A链表是否有重复元素且顺序是否正确*/
     if (checkASet(A, size) == 0)
     {
        printf("A链表有重复元素或长度与size不相等\n");
    	return 0;
     }
     /*printf("verifySize =  %d ",   size);*/

     int totalSize = 2*size;
//存放的是w和d
     secp256k1_scalar *index =  (secp256k1_scalar*) malloc (totalSize*sizeof(secp256k1_scalar));
     secp256k1_gej  *points = (secp256k1_gej*) malloc (totalSize*sizeof(secp256k1_gej));
     secp256k1_gej  *result = (secp256k1_gej*) malloc ( sizeof(secp256k1_gej));
     secp256k1_ge   *gepoints = (secp256k1_ge *) malloc (totalSize*sizeof(secp256k1_ge ));
     
     secp256k1_gej_set_infinity(result);

     secp256k1_scratch *scratch = secp256k1_scratch_space_create(ctx, 450000 + 256 * (2 * 1024 + 2));
     /*  secp256k1_scratch *scratch = secp256k1_scratch_space_create(ctx, 10*(450000 + 256 * (2 * 1024 + 2))); */

     int i;
     /*开始聚合验证*/
     for (i = 0; i<size ; i++)
        {
    	    secp256k1_sha256 hasher;
    	    unsigned char output_hash[32];
    	    unsigned char message_char[32];
    	    unsigned char tmp[64];

    	    secp256k1_gej_set_ge(points+i, pubkey+i);
    	    secp256k1_gej_set_ge(points+size + i, A+i);

    	    memcpy(gepoints+i, pubkey+i, sizeof(secp256k1_ge));
    	    memcpy(gepoints+size + i, A+i, sizeof(secp256k1_ge));

    	    int overflow = 0;
    	    {  /* d_i = H(A_i) */
    	    secp256k1_ge_to_char(tmp, A+i);
     	    secp256k1_sha256_initialize(&hasher);
    	    secp256k1_sha256_write(&hasher, tmp, sizeof(tmp));
    	    secp256k1_sha256_finalize(&hasher,output_hash);
    	    secp256k1_scalar_set_b32(index + size + i, output_hash, &overflow);

    	    secp256k1_scalar_negate(index + size + i, index+ size +i);

    	    VERIFY_CHECK(overflow == 0);
    	    }

    	    {    /* e_i = H(X_i, m_i) */
    	    secp256k1_ge_to_char(tmp, pubkey+i);
    	    secp256k1_scalar_get_b32(message_char, message+i);
    	    secp256k1_sha256_initialize(&hasher);
    	    secp256k1_sha256_write(&hasher, tmp, sizeof(tmp));
    	    secp256k1_sha256_write(&hasher, message_char, sizeof(message_char));
    	    secp256k1_sha256_finalize(&hasher,output_hash);
    	    secp256k1_scalar_set_b32(index  + i, output_hash, &overflow);
    	    VERIFY_CHECK(overflow == 0);
    	    }
        }

     {       /*compute ecumulate*/

       if (sumZ == NULL || size == 0) {
           printf("sumz = 0或者size=0\n");
           return 0;
       }
       int straussFunction = 0;
       int max_points = secp256k1_pippenger_max_points(error_callback,scratch);
       if (max_points == 0) {
           printf("max_points等于0\n");
           return 0;
       } else if (max_points > ECMULT_MAX_POINTS_PER_BATCH) {
           max_points = ECMULT_MAX_POINTS_PER_BATCH;
       }
       int  n_batches = (totalSize+max_points-1)/max_points;
       int  n_batch_points = (totalSize+n_batches-1)/n_batches;
    //    printf("max_points等于%d\n",max_points);
    //    printf("n_batches等于%d\n",n_batches);
    //    printf("n_batch_points等于%d\n",n_batch_points);

       if (n_batch_points >= ECMULT_PIPPENGER_THRESHOLD) {
    	   straussFunction = 0;
       } else {
    	   straussFunction = 1;
           max_points = secp256k1_strauss_max_points(error_callback,scratch);
           if (max_points == 0) {
               printf("max_points等于0\n");
               return 0;
           }
           n_batches = (totalSize+max_points-1)/max_points;
           n_batch_points = (totalSize+n_batches-1)/n_batches;
       }
        // printf("straussFunction等于%d\n",straussFunction);
      if (straussFunction == 1)
      {
          for(i = 0; i < n_batches; i++) {
              int nbp = totalSize < n_batch_points ? totalSize : n_batch_points;
              int offset = n_batch_points*i;
              secp256k1_gej tmp;
              if (!secp256k1_ecmult_strauss_batch_agg(error_callback, scratch, &tmp, nbp , points+offset, index+offset, i == 0 ? sumZ : NULL  )) {
                  printf("secp256k1_ecmult_strauss_batch_agg failed\n");
                  return 0;
              }
              secp256k1_gej_add_var(result, result, &tmp, NULL);
              totalSize -= nbp;
          }
      }else
      {
          for(i = 0; i < n_batches; i++) {
              int nbp = 0;

              if (totalSize < n_batch_points)
              {
            	  nbp = totalSize;
              }else
              {
            	  nbp = n_batch_points;
              }
              int offset = n_batch_points*i;
              secp256k1_gej tmp;
              int ret = secp256k1_ecmult_pippenger_batch_agg(error_callback, scratch,  &tmp, nbp , gepoints+offset, index+offset, i == 0 ? sumZ : NULL  );
              if(ret == 0){
                printf("secp256k1_ecmult_pippenger_batch_agg return 0\n");
              }
              secp256k1_gej_add_var(result, result, &tmp, NULL);
              totalSize -= nbp;
          }
      }

       /*printf( "%d, %d, %d",max_points, n_batches, n_batch_points );*/

       /*secp256k1_ecmult_strauss_wnaf(ctxecmult, &state, result, totalSize , points, index, sumZ);
       secp256k1_scratch_deallocate_frame(scratch);  */

     }
        /*判断计算结果是否为无穷远 是无穷远则验证成功 否则验证失败*/
       int re = secp256k1_gej_is_infinity(result);
       free(result);
       free(index);
       free(points);
       free(gepoints);
        if(re == 0){
            printf("返回值为0，聚合验证失败\n");
       }else{
            // printf("返回值不为0，聚合验证成功\n");
       }

       secp256k1_scratch_destroy(error_callback,scratch);
      return (re);
}



/* check if every item of set is in the right order and distinct */
/* 检查集合中的每个项目是否顺序正确且不同 */
int checkTSet(  const secp256k1_ge *pubkey, const secp256k1_scalar *message,  const int size )
{
	int i;
	for (i = 0; i< (size-1) ; i++)
	{
        /* 如果相等 或者 pubkey+i比pubkey+i+1更大 则返回0 及要求outpub从小到大排列 */
		if (secp256k1_ge_compare2( (pubkey+i), message+i,   (pubkey+i+1), message+i+1) >=0 )
		{
			return 0;
		}
	}
   return 1;

}


int checkASet(  const secp256k1_ge *A,  const int size )
{
	int i;
		for (i = 0; i< (size-1) ; i++)
		{/* 要求A从小到大排列 */
			if (secp256k1_ge_compare(A+i,    A+i+1 ) >=0 )
			{
				return 0;
			}
		}
		return 1;
}


 /*tree functions */

 geTreeNode * rotateright(geTreeNode *x)
 {
 	geTreeNode *y;
     y=x->Left;
     x->Left=y->Right;
     y->Right=x;
     x->Height=height(x);
     y->Height=height(y);
     return(y);
 }

 geTreeNode * rotateleft(geTreeNode *x)
 {
 	geTreeNode *y;
     y=x->Right;
     x->Right=y->Left;
     y->Left=x;
     x->Height = height(x);
     y->Height = height(y);

     return(y);
 }

 geTreeNode * RR(geTreeNode *T)
 {
     T=rotateleft(T);
     return(T);
 }

 geTreeNode * LL(geTreeNode *T)
 {
     T=rotateright(T);
     return(T);
 }

 geTreeNode * LR(geTreeNode *T)
 {
     T->Left=rotateleft(T->Left);
     T=rotateright(T);

     return(T);
 }

 geTreeNode * RL(geTreeNode *T)
 {
     T->Right=rotateright(T->Right);
     T=rotateleft(T);
     return(T);
 }


 int BF(geTreeNode *T)
 {
     int lh,rh;
     if(T==NULL)
         return(0);

     if(T->Left== NULL)
         lh=0;
     else
         lh=1+ T->Left->Height;

     if(T->Right==NULL)
         rh=0;
     else
         rh=1+ T->Right->Height;

     return(lh-rh);
 }

 int height(geTreeNode *T)
 {
     int lh,rh;
     if(T==NULL)
         return(0);

     if(T->Left==NULL)
         lh=0;
     else
         lh=1+T->Left->Height;

     if(T->Right==NULL)
         rh=0;
     else
         rh=1+T->Right->Height;

     if(lh>rh)
         return(lh);

     return(rh);
 }


 /* functions for tHatTree */


   tHatTreeNode * tHatrotateright(tHatTreeNode *x)
 {
 	tHatTreeNode *y;
     y=x->Left;
     x->Left=y->Right;
     y->Right=x;
     x->Height=tHatheight(x);
     y->Height=tHatheight(y);
     return(y);
 }

 tHatTreeNode * tHatrotateleft(tHatTreeNode *x)
 {
 	tHatTreeNode *y;
     y=x->Right;
     x->Right=y->Left;
     y->Left=x;
     x->Height = tHatheight(x);
     y->Height = tHatheight(y);

     return(y);
 }

 tHatTreeNode * tHatRR(tHatTreeNode *T)
 {
     T=tHatrotateleft(T);
     return(T);
 }

 tHatTreeNode * tHatLL(tHatTreeNode *T)
 {
     T=tHatrotateright(T);
     return(T);
 }

 tHatTreeNode * tHatLR(tHatTreeNode *T)
 {
     T->Left=tHatrotateleft(T->Left);
     T=tHatrotateright(T);

     return(T);
 }

 tHatTreeNode * tHatRL(tHatTreeNode *T)
 {
     T->Right=tHatrotateright(T->Right);
     T=tHatrotateleft(T);
     return(T);
 }


 int tHatBF(tHatTreeNode *T)
 {
     int lh,rh;
     if(T==NULL)
         return(0);

     if(T->Left==NULL)
         lh=0;
     else
         lh= 1 + (T->Left)-> Height;

     if(T->Right==NULL)
         rh=0;
     else
         rh=1+ T->Right->Height;

     return(lh-rh);
 }

 int tHatheight(tHatTreeNode *T)
 {
     int lh,rh;
     if(T==NULL)
         return(0);

     if(T->Left==NULL)
         lh=0;
     else
         lh=1+T->Left->Height;

     if(T->Right==NULL)
         rh=0;
     else
         rh=1+T->Right->Height;

     if(lh>rh)
         return(lh);

     return(rh);
 }



 /*static functions */






 static int geTree_Find(const secp256k1_ge *X, const  geTreeNode *T)
 {
 	 if( T == NULL ){
 		     return 0;
 		}
 	 else if(secp256k1_ge_compare(X,  T->Data) < 0   )       /*X < T->Data */
 	   {
 		 return geTree_Find( X,  T->Left);
 	   }
 	 else if(secp256k1_ge_compare(X,  T->Data) > 0)
 	 {
 		 return geTree_Find( X,  T->Right);
 	 }

	/* printGe( X, 1);
 	 printGe(T->Data, 1);
 	 int test = secp256k1_ge_compare( X,   T->Data ) ;*/

 	 return 1;
 }

void  releasegeTreeNode( geTreeNode *T)
{
    if (T !=  NULL)
    {
    	releasegeTreeNode(T->Left);
    	releasegeTreeNode(T->Right);

    	free(T);
    }

}

void  releasetHatTreeNode( tHatTreeNode *T)
{
    if (T !=  NULL)
    {
    	releasetHatTreeNode(T->Left);
    	releasetHatTreeNode(T->Right);

    	free(T);
    }

}



 static geTreeNode *geTree_Insertion(const secp256k1_ge *X, geTreeNode *T)
 {
 	  if( T == NULL ){
 	        T = (geTreeNode*) malloc(sizeof(geTreeNode));
 	       /* T->Data = (secp256k1_ge*) malloc(sizeof(secp256k1_ge));*/
 	       T->Data = X;
 	        /*   memcpy(T->Data, X , sizeof(secp256k1_ge));*/
 	       /*T->Height = 0;*/
 	        T->Left   = NULL;
 	       T->Right = NULL;
 	    }
 	    else if(secp256k1_ge_compare(X,  T->Data) < 0   )       /*X < T->Data */
 	    {
 	        T->Left = geTree_Insertion(X, T->Left);    /*递归比较并插入，将插入后的左子树更新给T-Left*/
 	        if(BF(T) == 2)
 	            {if(secp256k1_ge_compare(X,  T->Left->Data) < 0 )
 	                 T =  LL(T);  /*左单旋*/
 	            else
 	            	T =  LR(T); /*左-右双旋*/}
 	    }
 	    else if(secp256k1_ge_compare(X,  T->Data) > 0){
 	        T->Right = geTree_Insertion(X, T->Right);  /*递归比较并插入，将插入后的右子树更新给T->Right*/
 	        if(BF(T) == -2)
 	            {if(secp256k1_ge_compare(X,  T->Right->Data) > 0)
 	                T = RR(T);  /*右单旋*/
 	            else
 	                T = RL(T); /*右-左双旋*/}
 	    }

 	    /*else X == T->Data, 无需插入*/
 	    T->Height = height(T);/*树高等于子树高度加一*/

 	    return T;   /*返回插入并调整后的树*/
 }



 static void geTree_inorder(geTreeNode *T, secp256k1_ge *out , int * post)
 {
     if(T != NULL)
     {
     	geTree_inorder(T->Left, out , post);
     	 memcpy(out+(*post), T->Data, sizeof(secp256k1_ge));
     	 (*post)++;
     	 geTree_inorder(T->Right, out , post);
     }
 }

/* 平衡二叉排序树的插入  */
 static tHatTreeNode *tHatTree_Insertion(const secp256k1_ge *X, const  secp256k1_scalar *m, tHatTreeNode *T)
 {
 	  if( T == NULL ){
 	        T = (tHatTreeNode*)malloc(sizeof(tHatTreeNode));
 	        T->Data = X;
 	        T->message = m;

 	       /*  T->Data = (secp256k1_ge*)malloc(sizeof(secp256k1_ge));
 	      T->message = (secp256k1_scalar*)malloc(sizeof(secp256k1_scalar));

 	       memcpy(T->Data, X , sizeof(secp256k1_ge));
 	      memcpy(T->message, m , sizeof(secp256k1_scalar));*/

 	     /*T->Height = 0;*/
 	        T->Left   = NULL;
 	       T->Right = NULL;
 	    }
 	    else if(secp256k1_ge_compare2( X, m,   T->Data , T->message) < 0   )       /*X < T->Data */
 	    {
 	        T->Left = tHatTree_Insertion(X, m, T->Left);    /*递归比较并插入，将插入后的左子树更新给T-Left*/
 	        if(tHatBF(T) == 2)
 	            {if(secp256k1_ge_compare2( X,  m,  T->Left->Data , T->Left->message) < 0 )
 	                 T =  tHatLL(T);  /*左单旋*/
 	            else
 	            	T =  tHatLR(T); /*左-右双旋*/}
 	    }
 	    else if(secp256k1_ge_compare2(X, m, T->Data, T->message) > 0){
 	        T->Right = tHatTree_Insertion(X, m, T->Right);  /*递归比较并插入，将插入后的右子树更新给T->Right*/
 	        if(tHatBF(T) == -2)
 	            {if(secp256k1_ge_compare2( X,  m,  T->Right->Data , T->Right->message ) > 0)
 	                T = tHatRR(T);  /*右单旋*/
 	            else
 	                T = tHatRL(T); /*右-左双旋*/}
 	    }

 	    /*else X == T->Data, 无需插入*/
 	    T->Height = tHatheight(T);/*树高等于子树高度加一*/

 	    return T;   /*返回插入并调整后的树*/

 }

 static void tHatTree_inorder(tHatTreeNode *T, secp256k1_ge *out ,secp256k1_scalar *m, int *post)
 {
     if(T != NULL)
     {
     	tHatTree_inorder(T->Left, out ,m, post);
     	  memcpy ( out  + ( *post ) , T->Data,  sizeof(secp256k1_ge)  );      /*(out  + ( *post )) = T->Data;  (m  + ( *post )) = T->message;*/
     	  memcpy ( m + ( *post ) , T->message,  sizeof(secp256k1_scalar)  );

     	(*post) ++;
     	tHatTree_inorder(T->Right, out ,m, post);
     }
 }
 static   int tHatTree_Find(const secp256k1_ge  *X,    const secp256k1_scalar  *m,   const  tHatTreeNode *T)
 {
 	 if( T == NULL ){
 		     return 0;
 		}
 	 else if(secp256k1_ge_compare2( X,  m,  T->Data , T->message) < 0   )       /*X < T->Data */
 	   {
 		 return tHatTree_Find(  X,   m,  T->Left);
 	   }
 	 else if(secp256k1_ge_compare2( X,  m,  T->Data , T->message) > 0)
 	 {
 		 return tHatTree_Find(  X,   m,   T->Right);
 	 }
     /*
 	 printGe( X, 1);
 	 printGe(T->Data, 1);*/
 	 int test = secp256k1_ge_compare2( X,  m,  T->Data , T->message) ;

 	 return 1;
 }


   /**
    * @description: 
    * @param {secp256k1_ge } *ge1
    * @param {secp256k1_ge } *ge2
    * @return {*} 比较两个ge 
    * 如果双方都为无穷点 则返回0 如果ge1为无穷远点而ge2不是 则返回-1 如果ge1不是无穷远点而ge2是 则返回1
    * ge1和ge2相等时返回0
    * ge1的x更大 则返回1
    * ge2的x更大 则返回2
    * 这个大可能不是通常理解的大
    */
   int secp256k1_ge_compare(const secp256k1_ge  *ge1, const secp256k1_ge  *ge2) {

     if ( ge1->infinity == 1 &&  ge2->infinity == 1 )
     	return 0;
     if ( ge1->infinity == 1 &&  ge2->infinity == 0)
         return -1;
     if ( ge1->infinity == 0 &&  ge2->infinity == 1)
         return 1;

     int r = secp256k1_fe_cmp_var(&(ge1->x), &(ge2->x));

     if ( r != 0 )
     {
     	return r;
     }else
     {
        return secp256k1_fe_cmp_var(&(ge1->y), &(ge2->y));
     }
 }


   /**
    * @description: 
    * @param {secp256k1_ge} *ge1
    * @param {secp256k1_scalar} *m1
    * @param {secp256k1_ge} *ge2
    * @param {secp256k1_scalar} *m2
    * @return {*} 比较（X1,m1）和（X2,m2）
    * 公钥和消息都相同时 返回0
    * ge1更大返回1 ge2更大返回-1
    */
   int secp256k1_ge_compare2(const secp256k1_ge *ge1, const secp256k1_scalar *m1,
		   const secp256k1_ge *ge2, const secp256k1_scalar *m2) {


     int r = secp256k1_ge_compare( ge1,  ge2);

     if ( r != 0 )
     {
     	return r;
     }else
     {
     return secp256k1_scalar_cmp(m1, m2);
     }
 }



   int secp256k1_scalar_cmp(  const secp256k1_scalar *m1,    const secp256k1_scalar *m2)
   {
 	  unsigned char message_char1[32];
 	  unsigned char message_char2[32];

 	 secp256k1_scalar_get_b32(message_char1, m1);
 	 secp256k1_scalar_get_b32(message_char2, m2);



 	 return (stringCompare(message_char1, message_char1, 32));



   }





/* 相等则返回0 ch1大则返回1 否则返回-1 */
   int stringCompare(const unsigned char *ch1,  const unsigned char *ch2,  const int size)
 {

 	int i = 0;
    for ( i = 0;i< size; i++)
    {
    	if(*(ch1+i) != *(ch2+i))
    	{
    		return ( (*(ch1+i) > *(ch2+i)) ? 1:-1    );
    	}

    }

    return 0;

 }










































#endif /* GAMMAAGGREGATE_IMPL_H_ */
