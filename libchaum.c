/* -*- Mode: C; c-file-style: "stroustrup" -*- */

#include <string.h>
#include <openssl/rand.h>
#include "chaum.h"

int CHAUM_new( CHAUM** cp, RSA* value ) {
    EXCEPTION;
    CHAUM* c = NULL;
    
    if ( !cp ) { THROW( CREDLIB_NULL_PTR ); }

    TRYM( c = *cp = (CHAUM*)CREDLIB_malloc( sizeof( CHAUM ) ) );
    c->state = chaum_undef;
    c->value = value;
    c->cred = NULL;
    c->unblind = NULL;
    c->serial = NULL;
    TRYM( c->ctx = BN_CTX_new() );
    c->state = chaum_init;
 cleanup:
    FINALLY( CREDLIB_OUT_OF_MEMORY ) {
	if ( c ) { 
	    c->state = chaum_undef; 
	    CHAUM_free( c );
	}
    }
    return ret;
}

int CHAUM_free( CHAUM* c ) {
    if ( c ) {
	if ( c->cred ) { BN_free( c->cred ); }
	if ( c->unblind ) { BN_free( c->unblind ); }
	if ( c->ctx ) { BN_CTX_free( c->ctx ); }
	c->state = chaum_undef;
	CREDLIB_free( c );
    }
    return CREDLIB_OK;
}

int CHAUM_save( CHAUM* c, byte** out, int* out_len ) {
    EXCEPTION;
    int req_len, alt_len;

    if ( !c || !out ) { THROW( CREDLIB_NULL_PTR ); }


    switch ( c->state ) {
    case chaum_req:
	req_len = CREDLIB_calc_byte() +
	    CREDLIB_calc_bn( c->cred ) +
	    CREDLIB_calc_bn( c->unblind ) +
	    CREDLIB_calc_mem( c->serial_len );
	TRY( CREDLIB_out( out, &out_len, &alt_len, req_len ) );
	TRYIO_start( *out );
	TRYIO( CREDLIB_write_byte( ptr, (byte)c->state ) );
	TRYIO( CREDLIB_write_bn( ptr, c->cred ) );
	TRYIO( CREDLIB_write_bn( ptr, c->unblind ) );
	TRYIO( CREDLIB_write_mem( ptr, c->serial, c->serial_len ) );
	break;
    case chaum_cred:
	req_len = CREDLIB_calc_byte() +
	    CREDLIB_calc_bn( c->cred ) +
	    CREDLIB_calc_byte() +
	    (c->serial ? CREDLIB_calc_mem( c->serial_len ) : 0);
	TRY( CREDLIB_out( out, &out_len, &alt_len, req_len ) );
	TRYIO_start( *out );
	TRYIO( CREDLIB_write_byte( ptr, (byte)c->state ) );
	TRYIO( CREDLIB_write_bn( ptr, c->cred ) );
	TRYIO( CREDLIB_write_byte( ptr, c->serial ? 1 : 0 ) );
	if ( c->serial ) {
	    TRYIO( CREDLIB_write_mem( ptr, c->serial, c->serial_len ) );
	}
	break;

    case chaum_init:
    case chaum_undef:
    default:
	THROW( CREDLIB_NULL_SAVE );
	break;
    }
    RETURN( TRYIO_len( *out ) );
 cleanup:
    return ret;
}

int CHAUM_load( CHAUM* c, const byte* in, int in_len ) {
    EXCEPTION;
    TRYIO_start( in );
    c->state = (chaum_t)*ptr++;
    switch ( c->state ) {
    case chaum_req:
	TRYIO( CREDLIB_read_bn( ptr, &(c->cred) ) );
	TRYIO( CREDLIB_read_bn( ptr, &(c->unblind) ) );
	TRYIO( CREDLIB_read_mem( ptr, &(c->serial), &(c->serial_len) ) );
	break;
    case chaum_cred:
	TRYIO( CREDLIB_read_bn( ptr, &(c->cred) ) );
	if ( *ptr++ ) {
	    TRYIO( CREDLIB_read_mem( ptr, &(c->serial), &(c->serial_len) ) );
	}
	break;
    case chaum_init:
    case chaum_undef:
    default:
	THROW( CREDLIB_LOAD_CORRUPT );
	break;
    }
    RETURN( TRYIO_len( in ) ); 
 cleanup:
    return ret;
}

int CHAUM_umsg_max( CHAUM* c ) {
    return BN_num_bytes(c->value->n) - SHA_DIGEST_LENGTH - CHAUM_PADDING_MIN;
}

int CHAUM_request( CHAUM* c, const byte* umsg, int umsg_len,
		   byte** request, int* request_len ) {
    EXCEPTION;
    BIGNUM* be = NULL;
    BIGNUM* blind = NULL;
    BIGNUM* m = NULL;
    byte* msg = NULL;
    byte* serialp = NULL;
    int msg_len, padding_len;
    SHA_CTX sha1;
    uint16_t request_bytes;
    int alt_len = 0;

    if ( !c || !c->value || !c->ctx ) { THROW( CREDLIB_NULL_PTR ); }

    if ( c->state != chaum_init ) { THROW( CREDLIB_CALL_SEQUENCE ); }

    if ( umsg ) {
	if ( umsg_len > CHAUM_umsg_max( c ) ) {
	    THROW( CREDLIB_ARG_TOO_LARGE );
	}
	TRYM( c->serial = (byte*)CREDLIB_malloc( umsg_len ) );
	c->serial_len = umsg_len;
	memcpy( c->serial, umsg, umsg_len );
    } else {
	if ( CHAUM_SERIAL_LEN > CHAUM_umsg_max( c ) ) {
	    THROW( CREDLIB_KEY_TOO_SMALL );
	}
	TRYM( c->serial = (byte*)CREDLIB_malloc( CHAUM_SERIAL_LEN ) );
	c->serial_len = CHAUM_SERIAL_LEN;
	if ( !RAND_bytes( c->serial, c->serial_len ) ) { 
	    THROW( CREDLIB_RND_NOT_SEEDED );
	}
    }

    /* msg = pad || serial || h(serial) */

    TRYM( m = BN_new() );

    msg_len = BN_num_bytes( c->value->n );
    TRYM( msg = CREDLIB_malloc( msg_len ) );

    padding_len = msg_len - c->serial_len - SHA_DIGEST_LENGTH;
    msg[0] = 0x1;
    memset( msg+1, 0xFF, padding_len - 2 );
    msg[padding_len-1] = 0x0;

    serialp = msg+padding_len;
    memcpy( serialp, c->serial, c->serial_len );

    SHA1_Init( &sha1 );
    SHA1_Update( &sha1, c->serial, c->serial_len );
    SHA1_Final( serialp+c->serial_len, &sha1 );

    /* represent msg as a bignum in serial */
    TRYM( BN_bin2bn( msg, msg_len, m ) );

    TRACE( printf( "# s = msg = pad || serial || h(serial)\n" ) );
    TRACE( PRINT( "s = ", m ) );

    TRYM( blind = BN_new() );

    /* random blinding factor b */
    if ( !BN_rand( blind, BN_num_bits( c->value->n ), 1, 0 ) ) {
	THROW( CREDLIB_RND_NOT_SEEDED );
    }
    
    TRACE( PRINT( "b = ", blind ) );

    TRYM( be = BN_new() );
    if ( !BN_mod_exp( be, blind, c->value->e, c->value->n, c->ctx ) ) {
	THROW( CREDLIB_MATH_LIB_ERROR );
    }

    TRACE( printf( "# c = b^e\n" ) );
    TRACE( PRINT( "c = ", be ) );

    /* proto-cred = b^e.msg = b^e.[pad || serial || h(serial)] */

    if ( !c->cred ) { TRYM( c->cred = BN_new() ); }
    if ( !BN_mod_mul( c->cred, m, be, c->value->n, c->ctx ) ) {
	THROW( CREDLIB_MATH_LIB_ERROR );
    }

    TRACE( 
	printf( "# p = c.s = b^e.msg = b^e.[pad||serial||h(serial)]\n" ) );
    TRACE( PRINT( "p = ", c->cred ) );
    if ( !c->unblind ) { TRYM( c->unblind = BN_new() ); }

    if ( request ) {
	request_bytes = CREDLIB_calc_bn( c->cred );
	TRY( CREDLIB_out( request, &request_len, &alt_len, request_bytes ) );
	TRY( CREDLIB_write_bn( *request, c->cred ) );
    }

    if ( !BN_mod_inverse( c->unblind, blind, c->value->n, c->ctx ) ) {
	THROW( CREDLIB_MATH_LIB_ERROR );
    }

    TRACE( printf( "# u = 1/b; u.b = 1\n" ) );
    TRACE( PRINT( "u = ", c->unblind ) );

    c->state = chaum_req;

 cleanup:
    if ( be ) { BN_free( be ); }
    if ( blind ) { BN_free( blind ); }
    if ( m ) { BN_free( m ); }
    if ( msg ) { CREDLIB_free( msg ); }
    
    return ret;
}

int CHAUM_certify( CHAUM* c, const byte* request, int request_len,
		   byte** response, int* response_len ) {
    EXCEPTION;
    int alt_len;
    uint16_t response_bytes;

    if ( !c ) { THROW( CREDLIB_NULL_PTR ); }

    if ( c->state != chaum_init ) { THROW( CREDLIB_CALL_SEQUENCE ); }
    
    if ( request ) {
	if ( request_len < sizeof(uint16_t) ) {
	    THROW( CREDLIB_ARG_TOO_SMALL ); 
	}
	TRY( CREDLIB_read_bn( request, &c->cred ) );
    } else {
	if ( !c->cred ) { THROW( CREDLIB_NULL_PTR ); }
    }

    if ( !BN_mod_exp( c->cred, c->cred, c->value->d, c->value->n, c->ctx) ) {
	THROW( CREDLIB_MATH_LIB_ERROR );
    }

    if ( response ) {
	response_bytes = CREDLIB_calc_bn( c->cred );
	TRY( CREDLIB_out( response,&response_len,&alt_len,response_bytes ) );
	TRY( CREDLIB_write_bn( *response, c->cred ) );
    }

    TRACE( 
	printf( "# a = p^d = b.q^d = b.msg^d = b.[serial||h(serial)]^d\n" ) );
    TRACE( PRINT( "a = ", c->cred ) );

    /* otherwise ok */
 cleanup:
    return ret;
}

int CHAUM_unblind( CHAUM* c, const byte* response, int response_len ) {
    EXCEPTION;

    if ( !c || !c->cred || !c->unblind ) { THROW( CREDLIB_NULL_PTR ); }

    if ( c->state != chaum_req ) { THROW( CREDLIB_CALL_SEQUENCE ); }

    if ( response ) {
	if ( response_len < sizeof(uint16_t) ) {
	    THROW( CREDLIB_ARG_TOO_SMALL ); 
	}
	TRY( CREDLIB_read_bn( response, &c->cred ) );
    }

    if ( !BN_mod_mul( c->cred, c->cred, c->unblind, c->value->n, c->ctx ) ) {
	THROW( CREDLIB_MATH_LIB_ERROR );
    }
    TRACE( printf( "# t = b.q^d/b = a*u = serial^d = [x||h(x)]^d\n" ) );
    TRACE( PRINT( "t = ", c->cred ) );
    c->state = chaum_cred;
 cleanup:
    /* burn the unblinding factor */
    if ( c->unblind ) { BN_free( c->unblind ); c->unblind = NULL; }
    return ret;
}

int CHAUM_show( CHAUM* c, byte** cred, int* cred_len ) {
    EXCEPTION;
    int req_len, alt_len;

    if ( !cred ) { RETURN( CREDLIB_OK ); }
    if ( !c->cred ) { THROW( CREDLIB_NULL_PTR ); }
    if ( c->state != chaum_cred ) { THROW( CREDLIB_CALL_SEQUENCE ); }
    req_len = CREDLIB_calc_bn( c->cred );
    TRY( CREDLIB_out( cred, &cred_len, &alt_len, req_len ) );
    TRYIO_start( *cred );
    TRYIO( CREDLIB_write_bn( ptr, c->cred ) );
 cleanup:
    return ret;
}

int CHAUM_verify( CHAUM* c, const byte* cred, int cred_len ) {
    EXCEPTION;
    SHA_CTX sha1;
    byte* msg = NULL;	   /* msg' = pad||serial||x; x ?= h(serial) */
    byte* serialp = NULL;
    int msg_len, padding_len, serial_len;
    byte hash[SHA_DIGEST_LENGTH];
    BIGNUM* res = NULL;

    if ( !c ) { THROW( CREDLIB_NULL_PTR ); }
    if ( c->state != chaum_cred && /* self check */
	 c->state != chaum_init ) { /* 3rd party check */
	THROW( CREDLIB_CALL_SEQUENCE ); 
    }

    if ( cred ) {
	if ( cred_len < sizeof(uint16_t) ) {
	    THROW( CREDLIB_ARG_TOO_SMALL ); 
	}
	TRY( CREDLIB_read_bn( cred, &c->cred ) );
    }

    if ( !c->cred ) { THROW( CREDLIB_NULL_PTR ); }

    TRYM( res = BN_new() );
    /* res = cred^e = x||h(x) */

    if ( !BN_mod_exp( res, c->cred, c->value->e, c->value->n, c->ctx ) ) {
	THROW( CREDLIB_MATH_LIB_ERROR );
    }

    TRACE( printf( "# s' ?= q = t^e = (q^d)^e = q = pad || x || h(x)\n" ) );
    TRACE( PRINT( "q = ", res ) );

    /* decode res to bytes into msg */
    msg_len = BN_num_bytes( res );
    if ( msg_len != BN_num_bytes( c->value->n ) ) {	
	THROW( CREDLIB_BAD_PADDING ); 
    }
    TRYM( msg = CREDLIB_malloc( msg_len ) );
    if ( !BN_bn2bin( res, msg ) ) { THROW( CREDLIB_MATH_LIB_ERROR ); }

    /* verify padding */

    if ( msg[0] != 0x1 ) { THROW( CREDLIB_BAD_PADDING ); }

    for ( padding_len = 1; 
	  msg[padding_len] == 0xFF && padding_len < msg_len; 
	  padding_len++ ) {}

    if ( msg_len == padding_len || msg[padding_len++] != 0x0 ) {
	THROW( CREDLIB_BAD_PADDING );
    }

    serial_len = msg_len - padding_len - SHA_DIGEST_LENGTH;
    if ( serial_len < CHAUM_SERIAL_LEN ) { /* min serial ?? */
	THROW( CREDLIB_CHAUM_SERIAL_TOO_SMALL );
    }

    serialp = msg+padding_len;

    /* check from serial = x||y that y = h(x) */
    SHA1_Init( &sha1 );
    SHA1_Update( &sha1, serialp, serial_len );
    SHA1_Final( hash, &sha1 );

    if ( memcmp( hash, serialp+serial_len, SHA_DIGEST_LENGTH ) != 0 ) {
	RETURN( CREDLIB_FAIL );
    }

    if ( c->serial ) {		/* if user kept serial number */
	if ( serial_len != c->serial_len ||
	     memcmp( serialp, c->serial, serial_len ) != 0 ) {
	    THROW( CREDLIB_CHAUM_SERIAL_MISMATCH );
	}
    } else {
	c->serial = CREDLIB_malloc( serial_len );
	c->serial_len = serial_len;
	memcpy( c->serial, msg+padding_len, serial_len );
    }

    /* otherwise ok */
 cleanup:
    if ( res ) { BN_free( res ); }
    if ( msg ) { CREDLIB_free( msg ); }
    return ret;
}

int CHAUM_test( int key_size ) {
    EXCEPTION;
    RSA* value = NULL;
    CHAUM* cred = NULL;
    CHAUM* cred_load = NULL;
    CHAUM* cred_show = NULL;
    CHAUM* issuer = NULL;
    byte* serial = NULL;
    int serial_len;
    byte* request = NULL;
    int request_len = 0;
    byte* response = NULL;
    int response_len = 0;
    byte* show = NULL;
    int show_len = 0;
    byte* save_req = NULL;
    int save_req_len;
    byte* save_cred = NULL;
    int save_cred_len;
    
    /* generate an RSA key for the VALUE */

    if ( key_size < CHAUM_MIN_KEY_SIZE( CHAUM_SERIAL_LEN ) ) {
	TRACE( printf( "key size %d too small, must be >= %d\n",
		       key_size, CHAUM_MIN_KEY_SIZE( CHAUM_SERIAL_LEN ) ) );
	THROW( CREDLIB_FAIL );
    }

    value = RSA_generate_key( key_size, 65537L, NULL, NULL );
    if ( value == NULL ) { THROW( CREDLIB_MATH_LIB_ERROR ); }

    TRY( CHAUM_new( &issuer, value ) );
    TRY( CHAUM_new( &cred, value ) );

    TRACE( PRINT( "e = ", value->e ) );
    TRACE( PRINT( "d = ", value->d ) );
    TRACE( PRINT( "n = ", value->n ) );

    /* USER: create a blind proto cred */
    TRY( CHAUM_request( cred, NULL, 0, &request, &request_len ) );

    /* USER: save blind proto cred */
    TRY( CHAUM_save( cred, &save_req, &save_req_len ) );

    serial = CHAUM_get_serial( cred );
    serial_len = CHAUM_get_serial_len( cred );

    /* ISSUER: have issuer certify it */
    TRY( CHAUM_certify( issuer, request, request_len, 
			&response, &response_len  ) );

    /* USER: load blind proto cred */
    TRY( CHAUM_new( &cred_load, value ) );
    TRY( CHAUM_load( cred_load, save_req, save_req_len ) );

    /* USER: unblind and verify it */
    TRY( CHAUM_unblind( cred_load, response, response_len ) );
    TRY( CHAUM_verify( cred_load, NULL, 0 ) );

    /* USER: save cred for later use */

    TRY( CHAUM_save( cred_load, &save_cred, &save_cred_len ) );

    /* USER: load cred again */
    TRY( CHAUM_new( &cred_show, value ) );
    TRY( CHAUM_load( cred_show, save_cred, save_cred_len ) );
    TRY( CHAUM_verify( cred_show, NULL, 0 ) );

    /* USER: show it */
    TRY( CHAUM_show( cred_show, &show, &show_len ) );

    /* ISSUER/VERIFIER/AUDITOR: verify the shown credential */
    TRY( CHAUM_verify( issuer, show, show_len ) );    

 cleanup:
    if ( cred ) { CHAUM_free( cred ); }
    if ( cred_load ) { CHAUM_free( cred_load ); }
    if ( cred_show ) { CHAUM_free( cred_show ); }
    if ( save_cred ) { CREDLIB_free( save_cred ); }
    if ( save_req ) { CREDLIB_free( save_req ); }
    if ( value ) { RSA_free( value ); }
    if ( request ) { CREDLIB_free( request ); }
    if ( response ) { CREDLIB_free( response ); }
    if ( show ) { CREDLIB_free( show ); }
    if ( serial ) { CREDLIB_free( serial ); }
    return ret;
}
