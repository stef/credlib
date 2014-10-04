/* -*- Mode: C; c-file-style: "stroustrup" -*- */

#include <string.h>
#include <openssl/sha.h>
#include "credlib.h"

int verbose_flag = 0;

#if defined( DEBUG_MALLOC )
void* _m = NULL;
#endif

const char* cexcept_err_string[] = {
    "unknown_error",
    "out of memory",
    "unimplemented",
    "RNG not seeded",
    "math lib error",
    "null pointer",
    "argument too small",
    "argument too large",
    "key too small",
    "message inconsistent",
    "bad padding",
    "illegal call sequence",
    "nothing to save",
    "loaded data corrupt",
    "IO inconsistency",
    "chaum credential serial number too small",
    "chaum credential serial number mismatch",
    "brands attribute index out of range",
    "brands attribute too large",
    "brands too many attributes",
};

int CREDLIB_out( byte** msg, int** msg_len, 
		 int* alt_len, int required_len ) {
    EXCEPTION;
    
    if ( !msg || !msg_len || !alt_len ) { THROW( CREDLIB_NULL_PTR ); }
    if ( !*msg_len ) { *msg_len = alt_len; **msg_len = required_len; }
    if ( *msg ) {
	if ( **msg_len < required_len ) {
	    THROW( CREDLIB_ARG_TOO_SMALL );
	}
    } else {
	TRYM( *msg = CREDLIB_malloc( required_len ) );
	**msg_len = required_len;
    }
 cleanup:
    return ret;
}

int CREDLIB_write( void* d, void* s, size_t n ) {
    if ( !d || !s ) { return 0; }
    memcpy( d, s, n );
    return n;
}

int CREDLIB_write_bn( byte* p, BIGNUM* bn ) {
    EXCEPTION;
    int bn_len, check_len;
    if ( !p ) { THROW( CREDLIB_NULL_PTR ); }
    TRYIO_start( p );
    bn_len = bn ? BN_num_bytes( bn ) : 0;
    TRYIO( CREDLIB_write_uint16( ptr, bn_len ) );
    /* BN_bn2bin coincidentally has right API */
    if ( bn ) { 
	TRYIO( check_len = BN_bn2bin( bn, ptr ) ); 
	if ( check_len != bn_len ) { THROW( CREDLIB_IO_INCONSISTENCY ); }
    }
    RETURN( TRYIO_len( p ) );
 cleanup:
    return ret;
}

int CREDLIB_read_bn( const byte* p, BIGNUM** bn ) {
    EXCEPTION;
    int bn_len;

    if ( !p || !bn ) { THROW( CREDLIB_NULL_PTR ); } 
    TRYIO_start( p );
    TRYIO( CREDLIB_read_uint16( ptr, bn_len ) );
    *bn = BN_bin2bn( ptr, bn_len, *bn ); ptr += bn_len;
    if ( !*bn ) { THROW( CREDLIB_MATH_LIB_ERROR ); }
    RETURN( TRYIO_len( p ) );
 cleanup:
    return ret;
}

int CREDLIB_calc_bn_array( BIGNUM** bna, int bna_len, int off ) {
    int i, req_len = 0;

    req_len = CREDLIB_calc_uint16();
    for ( i = off; i < bna_len; i++ ) {
	req_len += CREDLIB_calc_bn( bna[i] );
    }
    return req_len;
}

int CREDLIB_write_bn_array( byte* out, BIGNUM** bna, int bna_len, int off ) {
    EXCEPTION;
    int i;

    if ( !out || (bna_len > 0 && !bna) ) { THROW( CREDLIB_NULL_PTR ); }

    TRYIO_start( out );
    TRYIO( CREDLIB_write_uint16( ptr, bna_len-off ) );
    for ( i = off; i < bna_len; i++ ) {
	TRYIO( CREDLIB_write_bn( ptr, bna[i] ) );
    }
    RETURN( TRYIO_len( out ) );
	
 cleanup:
    return ret;
}

int CREDLIB_read_bn_array( const byte* in, BIGNUM*** bnap, int* bna_len,
			   int off ) {
    EXCEPTION;
    int alt_len, req_len, i;
    BIGNUM** bna = NULL;

    if ( !in || !bnap || !bna_len ) { THROW( CREDLIB_NULL_PTR ); }

    TRYIO_start( in );
    TRYIO( CREDLIB_read_uint16( ptr, req_len ) );
    if ( !bna_len ) { bna_len = &alt_len; alt_len = req_len; }
    if ( !*bnap ) { 
	TRYM( *bnap = CREDLIB_BN_array_malloc( req_len+off ) ); 
	*bna_len = req_len+off;
    }
    bna = *bnap;
    for ( i = off; i < *bna_len; i++ ) {
	TRYIO( CREDLIB_read_bn( ptr, &(bna[i]) ) );
    }
    RETURN( TRYIO_len( in ) );
 cleanup:
    return ret;
}

int CREDLIB_write_mem( byte* p, const byte* mem, int len ) {
    EXCEPTION;
    
    if ( !p || !mem ) { THROW( CREDLIB_NULL_PTR ); }
    TRYIO_start( p );
    TRYIO( CREDLIB_write_uint32( ptr, len ) );
    memcpy( ptr, mem, len ); ptr += len;
    RETURN( TRYIO_len( p ) );
 cleanup:
    return ret;
}

int CREDLIB_read_mem( const byte* p, byte** mem, int* len ) {
    EXCEPTION;
    int alt_len;
    uint32_t req_len;

    if ( !p || !mem ) { THROW( CREDLIB_NULL_PTR ); }
    TRYIO_start( p );
    TRYIO( CREDLIB_read_uint32( ptr, req_len ) );
    TRY( CREDLIB_out( mem, &len, &alt_len, req_len ) );
    memcpy( *mem, ptr, req_len ); ptr += req_len;
    RETURN( TRYIO_len( p ) );
 cleanup:
    return ret;
}

int CREDLIB_write_bool_array_small( byte* p, const bool_t* ba, int len, 
				    int off ) {
    EXCEPTION;
    int i, j, bytes, b, c;

    if ( !p || !ba ) { THROW( CREDLIB_NULL_PTR ); }
    TRYIO_start( p );
    TRYIO( CREDLIB_write_uint16( ptr, len-off ) );
    bytes = BITS2BYTES(len-off);
    for ( i = 0, c = 8; i < bytes; i++ ) {
	if ( i == bytes-1 ) { c = (len-off) % 8; }
	for ( j = 0, b = 0; j < c; j++ ) {
	    b <<= 1;
	    b |= ba[ off+i*8+j ] ? 1 : 0;
	}
	if ( c < 8 ) { b <<= 8-c; }
	TRYIO( CREDLIB_write_byte( ptr, b ) );
    }
    RETURN( TRYIO_len( p ) );
 cleanup:
    return ret;
}

int CREDLIB_read_bool_array_small( const byte* p, bool_t** bap, int* len,
				   int off) {
    EXCEPTION;
    int i, j, bytes, b, c, req_len, alt_len;
    bool_t* ba = NULL;

    if ( !p || !bap ) { THROW( CREDLIB_NULL_PTR ); }
    
    TRYIO_start( p );
    TRYIO( CREDLIB_read_uint16( ptr, req_len ) );
    TRY( CREDLIB_out( (byte**)bap, &len, &alt_len, req_len+off ) );
    ba = *bap;
    bytes = BITS2BYTES( req_len );
    for ( i = 0, c = 8; i < bytes; i++ ) {
	if ( i == bytes-1 ) { c = req_len % 8; }
	TRYIO( CREDLIB_read_byte( ptr, b ) );
	for ( j = 0; j < c; j++ ) {
	    ba[i*8+j+off] = ( b & 0x80 ) ? 1 : 0;
	    b <<= 1;
	}
    }
    RETURN( TRYIO_len( p ) );
 cleanup:
    return ret;
}

int CREDLIB_rand_range( BIGNUM* rnd, int Zps, BIGNUM* p ) {
    EXCEPTION;

    if ( !p || !rnd ) { THROW( CREDLIB_NULL_PTR ); }
 again:
    if ( !BN_rand_range( rnd, p ) ) { THROW( CREDLIB_RND_NOT_SEEDED ); }
    if ( Zps && BN_is_zero( rnd ) ) { goto again; } /* Zp* */
    /* Zp* means must not be 0 */
    
 cleanup:
    return ret;
}

int CREDLIB_mod_hash( BIGNUM* r, BIGNUM* n, BIGNUM* n2,
                      byte* out, int out_len, BIGNUM* m, BN_CTX* ctx ) {
    EXCEPTION;
    SHA_CTX sha1;
    byte hash[ SHA_DIGEST_LENGTH ];
    byte* dat = NULL;
    int dat_len_s, req_len, alt_len;
    int* dat_len=&dat_len_s;
 
    if ( !m || !r || !ctx ) { THROW( CREDLIB_NULL_PTR ); }
    if ( !n && !n2 && !out ) { THROW( CREDLIB_NULL_PTR ); } /* no input! */
 
    SHA1_Init( &sha1 );
 
    req_len = ( n ? CREDLIB_calc_bn( n ) : 0 )
        + ( n2 ? CREDLIB_calc_bn( n2 ) : 0 );
 
    if ( req_len > 0 ) {
        TRY( CREDLIB_out( &dat, &dat_len, &alt_len, req_len ) );
        TRYIO_start( dat );
        /* use serialization system to n||n2 to prevent ambiguity */
        if ( n ) { TRYIO( CREDLIB_write_bn( ptr, n ) ); }
        if ( n2 ) { TRYIO( CREDLIB_write_bn( ptr, n2 ) ); }
 
        SHA1_Update( &sha1, dat, TRYIO_len( dat ) );
    }
    if ( out ) { SHA1_Update( &sha1, out, out_len ); }
    SHA1_Final( hash, &sha1 );
     
    CREDLIB_free( dat );
    TRYM( BN_bin2bn( hash, SHA_DIGEST_LENGTH, r ) );
    TRYM( BN_mod( r, r, m, ctx ) );
     
 cleanup:
    return ret;
}
 
BIGNUM** CREDLIB_BN_array_malloc( int size ) {
    EXCEPTION;
    BIGNUM** bna = NULL;
    int i;

    TRYM( bna = CREDLIB_malloc( sizeof(BIGNUM*) * size ) );
    memset( bna, 0, sizeof(BIGNUM*) * size );
    for ( i = 0; i < size; i++ ) {
	TRYM( bna[i] = BN_new() );
    }
    
 cleanup:
    FINALLY( CREDLIB_OUT_OF_MEMORY ) {
	CREDLIB_BN_array_free( bna, size );
	return NULL;
    }
    return bna;
}

int CREDLIB_BN_array_free_fn( BIGNUM** bna, int size ) {
    int i;
    
    if ( bna ) {
	for ( i = 0; i < size; i++ ) {
	    if ( bna[i] ) { BN_free( bna[i] ); bna[i] = NULL; }
	}
	CREDLIB_free( bna );
    }
    return CREDLIB_OK;
}
