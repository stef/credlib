/* -*- Mode: C; c-file-style: "stroustrup" -*- */

/* Brandsian Credentials */

#if !defined( _brands_h )
#define _brands_h

#if defined( __cplusplus )
extern "C" {
#endif

#include "credlib.h"
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/dsa.h>

#define CREDLIB_BRANDS_DEFAULT_KEY_SIZE 1024

typedef enum brands_e {
    brands_undef, brands_init, brands_key,
/* user states */
    brands_req_pre, brands_req, 
    brands_resp_pre, brands_resp, brands_cred, 
    brands_chal,		/* issuer state */
    brands_show			/* verifier state */
} brands_t;

typedef struct brands_s {
    brands_t state;
    bool_t issuer;		/* we own memory of g */
    DSA* params;
    BIGNUM** g;			/* issuer public */
    BIGNUM** y;			/* issuer private key */
    BIGNUM** x;			/* user attribs, x_0 is user private key */
    int num_attribs;		/* excluding private key alpha */
    bool_t* show;		/* remember what we showed/verified */
    BIGNUM* k;
    BIGNUM* alpha2;
    BIGNUM* alpha3;
    BIGNUM* h;
    BIGNUM* hp;
    BIGNUM* beta;
    BIGNUM* s;
    BIGNUM* t;
    BIGNUM* gamma;
    BIGNUM* u;
    BIGNUM* up;
    BIGNUM* v;
    BIGNUM* vp;
    BIGNUM* inv_alpha;
    BIGNUM** w;
    BIGNUM* a;
    BIGNUM* c;
    BIGNUM** r;
    BIGNUM* e;
    BIGNUM* M;
    BN_CTX* ctx;
} BRANDS;

BRANDS* BRANDS_new( void );
int BRANDS_free( BRANDS* b );

/* key setup calls */

int BRANDS_key_set( BRANDS* b, BRANDS* issuer );
int BRANDS_key_generate( BRANDS* b, DSA* params, int key_size, 
			 int num_attribs );

/* user calls */

int BRANDS_user_attrib_set( BRANDS* b, uint_t i, void* attr, int attr_len );

int BRANDS_user_request( BRANDS* b, byte** out, int* out_len );

int BRANDS_user_response( BRANDS* b, byte* in, int in_len, 
			  byte** out, int* out_len );

int BRANDS_user_recv_cert( BRANDS *b, byte* in, int int_len );

int BRANDS_user_attrib_show( BRANDS* b, uint_t attrib );
int BRANDS_user_attrib_show_array( BRANDS* b, bool_t* show, uint_t show_num );
int BRANDS_user_send_show( BRANDS* b, bool_t* show, uint_t show_num,
			   byte** out, int* out_len );

/* issuer calls */

int BRANDS_issuer_challenge( BRANDS* b, byte* in, int in_len, 
			     byte** out, int* out_len );

int BRANDS_issuer_send_cert( BRANDS* b, byte* in, int in_len,
			     byte** out, int* out_len );

/* verifier calls */

int BRANDS_verifier_recv_show( BRANDS* b, byte* in, int in_len );

/* generic calls */

int BRANDS_precompute( BRANDS* b );
int BRANDS_verify( BRANDS* b );
#define BRANDS_state( b ) ( (b) ? (b)->state : CREDLIB_NULL_PTR )

/* self-test function */

int BRANDS_test( int key_size, int attribs, bool_t precompute );

#if defined( __cplusplus )
}
#endif

#endif
