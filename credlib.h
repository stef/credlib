/* -*- Mode: C; c-file-style: "stroustrup" -*- */

/* common error codes and types */

#if !defined( _credlib_h )
#define _credlib_h

#if defined( __cplusplus )
extern "C" {
#endif

#if defined( WIN32 )
#include <winsock2.h>
#else
#include <netinet/in.h>
#endif
#include <openssl/crypto.h>
#include <openssl/bn.h>
#include "cexception.h"
#include "types.h"

/* 0 = normal fail, 1 = ok, -ve codes are exceptions */

#define CREDLIB_OK 1
#define CREDLIB_FAIL 0
#define CREDLIB_UNKNOWN_ERROR -1
#define CREDLIB_OUT_OF_MEMORY -2
#define CREDLIB_UNIMPLEMENTED -3
#define CREDLIB_RND_NOT_SEEDED -4
#define CREDLIB_MATH_LIB_ERROR -5
#define CREDLIB_NULL_PTR -6
#define CREDLIB_ARG_TOO_SMALL -7
#define CREDLIB_ARG_TOO_LARGE -8
#define CREDLIB_KEY_TOO_SMALL -9
#define CREDLIB_MSG_INCONSISTENT -10
#define CREDLIB_BAD_PADDING -11
#define CREDLIB_CALL_SEQUENCE -12
#define CREDLIB_NULL_SAVE -13
#define CREDLIB_LOAD_CORRUPT -14
#define CREDLIB_IO_INCONSISTENCY -15
#define CREDLIB_CHAUM_SERIAL_TOO_SMALL -16
#define CREDLIB_CHAUM_SERIAL_MISMATCH -17
#define CREDLIB_BRANDS_ATTRIB_INDEX_OUT_OF_RANGE -18
#define CREDLIB_BRANDS_ATTRIB_TOO_LARGE -19
#define CREDLIB_BRANDS_TOO_MANY_ATTRIBS -20

#define TRYM( x ) DO( if (!(x)) { THROW(CREDLIB_OUT_OF_MEMORY); } )
#define TRYL( x ) DO( if (!(x)) { THROW(CREDLIB_MATH_LIB_ERROR); } )

extern int verbose_flag;

#define _( x ) (x), strlen( x )

#define TRACE( x ) if ( verbose_flag ) { x; }
#define PRINT( d, x ) \
	DO( printf( "%s", d ); BN_print_fp( stdout, (x) ); printf( "\n" ); )
#define REPORT( x ) (x==CREDLIB_OK) ? "ok" : "fail"
#if defined( WIN32 )
#define EXIT( x ) exit( ( fflush(stdout),\
	( ((x)==CREDLIB_OK) ? EXIT_SUCCESS : EXIT_FAILURE ) ) )
#else
#define EXIT( x ) exit( ((x)==CREDLIB_OK) ? EXIT_SUCCESS : EXIT_FAILURE )
#endif

#define BITS2BYTES( b ) ((b)+7)/8
#define BYTES2BITS( b ) ((b)<<3)

#if defined( DEBUG_MALLOC )
extern void* _m;
#define CREDLIB_malloc( x ) ((_m=(void*)OPENSSL_malloc( x )),\
	fprintf(stderr,"malloc=0x%08x,%d\n",_m,(x)),_m)
#define CREDLIB_free( x ) DO( fprintf(stderr,"free=0x%08x\n",x); \
	OPENSSL_free( x ); (x) = NULL; )
#else
#define CREDLIB_malloc( x ) (void*)OPENSSL_malloc( x )
#define CREDLIB_free( x ) DO( OPENSSL_free( x ); (x) = NULL; )
#endif

#define CREDLIB_BN_free( x ) DO( BN_free( x ); (x) = NULL; )

int CREDLIB_out( byte** msg, int** msg_len, 
		 int* alt_len, int required_len );

#define CREDLIB_calc(l) (l)
    int CREDLIB_write( void* d, void* s, size_t n );
#define CREDLIB_read( p, m, l ) CREDLIB_write( (m), (p), (l) )

#define CREDLIB_calc_byte() sizeof(byte)
#define CREDLIB_write_byte( p, b ) ( ( *(p) = b ),CREDLIB_calc_byte() )
#define CREDLIB_read_byte( p, b ) ( ( (b) = *p ),CREDLIB_calc_byte() )
 
#define CREDLIB_calc_uint16() sizeof(uint16_t)
#define CREDLIB_write_uint16(p,s) \
	( ( *(uint16_t*)(p) = htons(s) ), CREDLIB_calc_uint16() )
#define CREDLIB_read_uint16(p,s) \
	( ( (s) = ntohs(*(uint16_t*)(p)) ), CREDLIB_calc_uint16() )
 
#define CREDLIB_calc_uint32() sizeof(uint32_t)
#define CREDLIB_write_uint32(p,s) \
	( ( *(uint32_t*)(p) = htonl(s) ), CREDLIB_calc_uint32() )
#define CREDLIB_read_uint32(p,l) \
	( ( (l) = ntohl(*(uint32_t*)(p)) ), CREDLIB_calc_uint32() )

#define CREDLIB_calc_bn( bn ) \
	( CREDLIB_calc_uint16() + ( (bn) ? BN_num_bytes( bn ) : 0 ) )
int CREDLIB_write_bn( byte* p, BIGNUM* bn );
int CREDLIB_read_bn( const byte* p, BIGNUM** bn );

int CREDLIB_calc_bn_array( BIGNUM** bna, int bna_len, int off );
int CREDLIB_write_bn_array( byte* p, BIGNUM** bna, int bna_len, int off );
int CREDLIB_read_bn_array( const byte* p, BIGNUM*** bn, int* bna_len, 
			   int off );

#define CREDLIB_calc_mem( len ) ( CREDLIB_calc_uint32()+(len) )
int CREDLIB_write_mem( byte* p, const byte* mem, int len );
int CREDLIB_read_mem( const byte* p, byte** mem, int* len );

#define CREDLIB_calc_bool_array_small( len, off ) \
	( CREDLIB_calc_uint16()+BITS2BYTES(len-off) )
int CREDLIB_write_bool_array_small( byte* p, const bool_t* ba, int len,
				    int off );
int CREDLIB_read_bool_array_small( const byte* p, bool_t** ba, int* len, 
				   int off );

int CREDLIB_rand_range( BIGNUM* rnd, int Zps, BIGNUM* p );

int CREDLIB_mod_hash( BIGNUM* r, BIGNUM* n, BIGNUM* n2,
                      byte* out, int out_len, BIGNUM* m, BN_CTX* ctx );

BIGNUM** CREDLIB_BN_array_malloc( int size );
int CREDLIB_BN_array_free_fn( BIGNUM** bn, int size );
#define CREDLIB_BN_array_free( bn, sz ) \
	DO( CREDLIB_BN_array_free_fn( (bn), (sz) ); (bn) = NULL; )

#if defined( __cplusplus )
}
#endif

#endif
