/* -*- Mode: C; c-file-style: "stroustrup" -*- */

/* Chaumian Credentials */

#if !defined( _chaum_h )
#define _chaum_h

#if defined( __cplusplus )
extern "C" {
#endif

#include "credlib.h"
#include <openssl/sha.h>
#include <openssl/rsa.h>

#define CHAUM_SERIAL_LEN (SHA_DIGEST_LENGTH)
#define CHAUM_PADDING_MIN 2
#define CHAUM_MIN_KEY_SIZE( serial_len ) \
	BYTES2BITS(CHAUM_PADDING_MIN + serial_len + SHA_DIGEST_LENGTH)+2

typedef enum chaum_e {
    chaum_undef, chaum_init, chaum_req, chaum_cred
} chaum_t;

typedef struct chaum_s {
    chaum_t state;
    RSA* value;
    BIGNUM* cred;
    BIGNUM* unblind;
    byte* serial;
    int serial_len;
    BN_CTX* ctx;
} CHAUM;

int CHAUM_new( CHAUM** c, RSA* value );
int CHAUM_free( CHAUM* c );
int CHAUM_save( CHAUM* c, byte** out, int* out_len );
int CHAUM_load( CHAUM* c, const byte* in, int in_len );
int CHAUM_umsg_max( CHAUM* c );
int CHAUM_request( CHAUM* c, const byte* umsg, int umsg_len,
		   byte** request, int* request_len );
int CHAUM_certify( CHAUM* c, const byte* request, int request_len,
		   byte** response, int* response_len );
int CHAUM_unblind( CHAUM* c, const byte* response, int response_len );
int CHAUM_show( CHAUM* c, byte** cred, int* cred_len );
int CHAUM_verify( CHAUM* c, const byte* cred, int cred_len );
int CHAUM_test( int key_size );

/* lower level set/access */

#define CHAUM_set_field( c, n, field ) \
	( ((c)->field) ? BN_copy( (c)->field, (n) ) : \
		(c)->field = BN_dup( (n) ) )

#define CHAUM_get_cred( c ) ((c)->cred)
#define CHAUM_set_cred( c, n ) CHAUM_set_field( c, n, cred )

#define CHAUM_get_unblind( c ) ((c)->unblind)
#define CHAUM_set_unblind( c, n ) CHAUM_set_field( c, n, unblind )

#define CHAUM_get_value( c ) ((c)->value)
#define CHAUM_set_value( c, value ) ((c)->value = (value))

#define CHAUM_get_serial( c ) ((c)->serial)
#define CHAUM_get_serial_len( c ) ((c)->serial_len)
#define CHAUM_set_serial( c, s, sl ) \
	( ((c)->serial = (s)), ((c)->serial_len = (sl)) )

#if defined( __cplusplus )
}
#endif

#endif


/* int chaum_coin_init( CHAUM& c, byte* ca, int clen ); */

/*
typedef struct chaum_ca_st CHAUM_CA;

typedef struct {
    word32 encoding;
    char* semantics;
    BIGNUM* sig;
    RSA* key;
    CHAUM_CA* ca;
} CHAUM_ATTRIB;

struct chaum_ca_st {
    RSA* master;
    char* issuer;
    BIGNUM* selfsig;
    int num_attribs;
    CHAUM_ATTRIB* attribs;
};

typedef struct {
    RSA rsa;
    BN_ctx* bn_ctx;
} CHAUM;

typedef struct {
    BIGNUM* blind;
} CHAUM_BLIND;

*/
