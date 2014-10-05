/* -*- Mode: C; c-file-style: "stroustrup" -*- */

#include <string.h>
#include "brands.h"

BRANDS* BRANDS_new( void ) {
    EXCEPTION;
    BRANDS* b = NULL;

    TRYM( b = (BRANDS*)CREDLIB_malloc( sizeof( BRANDS ) ) );
    b->state = brands_undef;
    b->issuer = false;
    b->params = NULL;
    b->g = NULL;
    b->x = NULL;
    b->y = NULL;
    b->num_attribs = 0;
    b->show = NULL;
    b->k = NULL;
    b->alpha2 = NULL;
    b->alpha3 = NULL;
    b->h = NULL;
    b->hp = NULL;
    b->beta = NULL;
    b->s = NULL;
    b->t = NULL;
    b->gamma = NULL;
    b->u = NULL;
    b->up = NULL;
    b->v = NULL;
    b->vp = NULL;
    b->inv_alpha = NULL;
    b->w = NULL;
    b->a = NULL;
    b->c = NULL;
    b->r = NULL;
    b->e = NULL;
    b->M = NULL;

    TRYM( b->ctx = BN_CTX_new() );
    b->state = brands_init;
 cleanup:
    FINALLY( CREDLIB_OUT_OF_MEMORY ) {
	if ( b ) {
	    b->state = brands_undef;
	    BRANDS_free( b );
	    return NULL;
	}
    }
    return b;
}

int BRANDS_free( BRANDS* b ) {
    if ( b ) {
	b->state = brands_undef;
	b->params = NULL;	/* forget params, someone else owns */
	if ( b->issuer ) {	/* we own g */
	    if ( b->g ) { CREDLIB_BN_array_free( b->g, b->num_attribs ); }
	} else {
	    b->g = NULL;	/* forget g, someone else owns */
	}
	if ( b->x ) { CREDLIB_BN_array_free( b->x, b->num_attribs ); }
	if ( b->y ) { CREDLIB_BN_array_free( b->y, b->num_attribs ); }
	if ( b->show ) { CREDLIB_free( b->show ); }
	if ( b->k ) { CREDLIB_BN_free( b->k ); }
	if ( b->alpha2 ) { CREDLIB_BN_free( b->alpha2 ); }
	if ( b->alpha3 ) { CREDLIB_BN_free( b->alpha3 ); }
	if ( b->h ) { CREDLIB_BN_free( b->h ); }
	if ( b->hp ) { CREDLIB_BN_free( b->hp ); }
	if ( b->beta ) { CREDLIB_BN_free( b->beta ); }
	if ( b->s ) { CREDLIB_BN_free( b->s ); }
	if ( b->t ) { CREDLIB_BN_free( b->t ); }
	if ( b->gamma ) { CREDLIB_BN_free( b->gamma ); }
	if ( b->u ) { CREDLIB_BN_free( b->u ); }
	if ( b->up ) { CREDLIB_BN_free( b->up ); }
	if ( b->v ) { CREDLIB_BN_free( b->v ); }
	if ( b->vp ) { CREDLIB_BN_free( b->vp ); }
	if ( b->inv_alpha ) { CREDLIB_BN_free( b->inv_alpha ); }
	if ( b->w ) { CREDLIB_BN_array_free( b->w, b->num_attribs ); }
	if ( b->a ) { CREDLIB_BN_free( b->a ); }
	if ( b->c ) { CREDLIB_BN_free( b->c ); }
	if ( b->r ) { CREDLIB_BN_array_free( b->r, b->num_attribs ); }
	if ( b->e ) { CREDLIB_BN_free( b->e ); }
	if ( b->M ) { CREDLIB_BN_free( b->M ); }
	if ( b->ctx ) { BN_CTX_free( b->ctx ); }

	CREDLIB_free( b );
    }
    return CREDLIB_OK;
}

int BRANDS_key_set( BRANDS* b, BRANDS* issuer ) {
    EXCEPTION;
    if ( !b || !issuer || !issuer->params || !issuer->g ) {
	THROW( CREDLIB_NULL_PTR );
    }
    b->issuer = false;
    b->params = issuer->params;
    b->g = issuer->g;
    b->num_attribs = issuer->num_attribs;
    TRYM( b->x = CREDLIB_BN_array_malloc( b->num_attribs ) );
    b->state = brands_key;

 cleanup:
    return ret;
}

int BRANDS_key_generate( BRANDS* b, DSA* params, int key_size,
			 int num_attribs ) {
    EXCEPTION;
    int i;

    if ( !b ) { THROW( CREDLIB_NULL_PTR ); }
    if ( b->state != brands_init ) { THROW( CREDLIB_CALL_SEQUENCE ); }
    if ( !params ) {
	if ( key_size == 0 ) { key_size = CREDLIB_BRANDS_DEFAULT_KEY_SIZE; }

   params = DSA_new();
   if (!params) { THROW( CREDLIB_OUT_OF_MEMORY ); }
   if (!DSA_generate_parameters_ex(params, key_size,NULL,0,NULL,
            NULL,NULL)) { THROW( CREDLIB_MATH_LIB_ERROR ); }
    }
    b->issuer = true;
    b->params = params;
    TRACE( printf( "# DSA params g, p, q\n" ) );
    TRACE( PRINT( "g = ", b->params->g ) );
    TRACE( PRINT( "p = ", b->params->p ) );
    TRACE( PRINT( "q = ", b->params->q ) );
    b->num_attribs = ++num_attribs; /* need extra 1 for user private key */
    TRYM( b->y = CREDLIB_BN_array_malloc( num_attribs ) );
    TRYM( b->g = CREDLIB_BN_array_malloc( num_attribs ) );

    for ( i = 0; i < num_attribs; i++ ) {
	TRY( CREDLIB_rand_range( b->y[i], 1, b->params->q ) );
	TRACE( printf( "y[%d] = ", i ); PRINT( "", b->y[i] ) );
	/* g_i = g^y_i mod p */
	TRYL( BN_mod_exp( b->g[i], b->params->g, b->y[i],
			  b->params->p, b->ctx ) );
	TRACE( printf( "g[%d] = ", i ); PRINT( "", b->g[i] ) );
    }
    b->state = brands_key;

 cleanup:
    FINALLY( CREDLIB_OUT_OF_MEMORY ) { /* free just what we alloced */
	if ( b->g ) { CREDLIB_BN_array_free( b->g, num_attribs ); }
	if ( b->y ) { CREDLIB_BN_array_free( b->y, num_attribs ); }
	b->state = brands_init;	/* roll back to init state */
    }
    FINALLY( CREDLIB_CALL_SEQUENCE ) { RESET(); }
    return ret;
}

int BRANDS_user_attrib_set( BRANDS* b, uint_t i, void* attr, int attr_len ) {
    EXCEPTION;
    int q_len;

    if ( !b || !b->x || !b->params->q ) { THROW( CREDLIB_NULL_PTR ); }

    if ( b->state != brands_key || b->issuer ) {
	THROW( CREDLIB_CALL_SEQUENCE );
    }

    if ( i > b->num_attribs-1 ) {
	THROW( CREDLIB_BRANDS_ATTRIB_INDEX_OUT_OF_RANGE );
    }
    if ( !attr ) { BN_set_word( b->x[i+1], 0 ); }
    q_len = BN_num_bytes( b->params->q );
    if ( attr_len > q_len-1 ) { THROW( CREDLIB_BRANDS_ATTRIB_TOO_LARGE ); }
    if ( !BN_bin2bn( attr, attr_len, b->x[i+1] ) ) {
	THROW( CREDLIB_MATH_LIB_ERROR );
    }
    TRACE( printf( "# set attrib %d\n", i+1 ) );
    TRACE( printf( "x[%d] = ",i+1 ); PRINT( "",b->x[i+1] ) );
 cleanup:
    FINALLY( CREDLIB_CALL_SEQUENCE ) { RESET(); }
    return ret;
}

static
int brands_user_request_precompute( BRANDS* b ) {
    EXCEPTION;

    if ( !b ) { THROW( CREDLIB_NULL_PTR ); }
    if ( b->state != brands_key || b->issuer ) {
	THROW( CREDLIB_CALL_SEQUENCE );
    }

    /* not much can be done as don't know x_1 .. x_n yet */

    /* alpha = x_0 = rand Z_q* */
    TRY( CREDLIB_rand_range( b->x[0], 1, b->params->q ) ); /* alpha */
    TRACE( PRINT( "x[0] = ", b->x[0] ) );
    TRYM( b->alpha2 = BN_new() );
    TRYM( b->alpha3 = BN_new() );
    /* alpha2 = rand Z_q; alpha3 = rand Z_q */
    TRY( CREDLIB_rand_range( b->alpha2, 0, b->params->q ) );
    TRACE( PRINT( "alpha2 = ", b->alpha2 ) );
    TRY( CREDLIB_rand_range( b->alpha3, 0, b->params->q ) );
    TRACE( PRINT( "alpha3 = ", b->alpha3 ) );

    b->state = brands_req_pre;
 cleanup:
    FINALLY( CREDLIB_CALL_SEQUENCE ) { RESET(); }
    return ret;
}

int BRANDS_user_request( BRANDS* b, byte** out, int* out_len ) {
    EXCEPTION;
    int i, req_len, alt_len;

    if ( !b || !b->x ) { THROW( CREDLIB_NULL_PTR ); }

    if ( ( b->state != brands_key && b->state != brands_req_pre ) ||
	 b->issuer ) {
	THROW( CREDLIB_CALL_SEQUENCE );
    }

    if ( b->state != brands_req_pre ) {
	TRY( brands_user_request_precompute( b ) );
    }

    /* send x_1 ... x_n array (ie excluding x_0 = alpha) */

    TRACE( for ( i = 1; i < b->num_attribs; i++ ) {
	printf("ox[%d] = ",i); PRINT( "", b->x[i] );
    } );

    req_len = CREDLIB_calc_bn_array( b->x, b->num_attribs, 1 );
    TRY( CREDLIB_out( out, &out_len, &alt_len, req_len ) );
    TRYIO_start( *out );
    TRYIO( CREDLIB_write_bn_array( ptr, b->x, b->num_attribs, 1 ) );
    if ( TRYIO_len( *out ) != req_len ) { THROW( CREDLIB_IO_INCONSISTENCY ); }
    *out_len = req_len;
    b->state = brands_req;

 cleanup:
    FINALLY( CREDLIB_CALL_SEQUENCE ) { RESET(); }
    return ret;
}

int BRANDS_issuer_challenge( BRANDS* b, byte* in, int in_len,
			     byte** out, int* out_len ) {
    EXCEPTION;
    BIGNUM* tmp = NULL;
    int i, num_attribs, req_len, alt_len;

    if ( !b || !in || !out || !out_len ) { THROW( CREDLIB_NULL_PTR ); }
    if ( b->state != brands_key || !b->issuer ) {
	THROW( CREDLIB_CALL_SEQUENCE );
    }

    /* skip x[0] not sent (offset 1) */
    TRYIO_start( in );
    if ( b->x ) { num_attribs = b->num_attribs; }
    TRYIO( CREDLIB_read_bn_array( ptr, &b->x, &num_attribs, 1 ) );
    if ( num_attribs != b->num_attribs ) {
	THROW( CREDLIB_IO_INCONSISTENCY );
    }

    TRACE( for ( i = 1; i < b->num_attribs; i++ ) {
	printf("ix[%d] = ",i); PRINT( "", b->x[i] );
    } );

    TRYM( b->k = BN_new() );
    TRYM( b->s = BN_new() );
    /* k = rand Z_q */
    TRY( CREDLIB_rand_range( b->k, 0, b->params->q ) );
    TRACE( PRINT( "k = ", b->k ) );
    /* s = g^k */
    TRYL( BN_mod_exp( b->s, b->params->g, b->k, b->params->p, b->ctx ) );
    TRACE( PRINT( "s = ", b->s ) );

    TRYM( b->t = BN_new() );
    /* t = (y_0 + x_1.y_1 + ... + x_n.y_n)^-1 */
    TRYM( tmp = BN_new() );
    TRYL( BN_copy( b->t, b->y[0] ) ); /* t = y_0 */
    for ( i = 1; i < b->num_attribs; i++ ) {
	/* tmp = x_i.y_i */
	TRYL( BN_mod_mul( tmp, b->x[i], b->y[i], b->params->q, b->ctx ) );
	/* t += tmp */
	TRYL( BN_mod_add( b->t, b->t, tmp, b->params->q, b->ctx ) );
    }
    /* t = t^-1 */
    TRYL( BN_mod_inverse( b->t, b->t, b->params->q, b->ctx ) );
    TRACE( PRINT( "t = ", b->t ) );

    req_len = CREDLIB_calc_bn( b->s );
    TRY( CREDLIB_out( out, &out_len, &alt_len, req_len ) );
    TRYIO_start( *out );
    TRYIO( CREDLIB_write_bn( ptr, b->s ) );
    if ( TRYIO_len( *out ) != req_len ) { THROW( CREDLIB_IO_INCONSISTENCY ); }
    TRACE( PRINT( "os = ", b->s ) );
    b->state = brands_chal;

 cleanup:
    FINALLY( CREDLIB_CALL_SEQUENCE ) { RESET(); }
    if ( tmp ) { BN_free( tmp ); }
    return ret;
}

static
int brands_user_response_precompute( BRANDS* b ) {
    EXCEPTION;
    BIGNUM* tmp = NULL;
    int i;

    if ( !b ) { THROW( CREDLIB_NULL_PTR ); }
    if ( b->state != brands_req || b->issuer ) {
	THROW( CREDLIB_CALL_SEQUENCE );
    }

    /* now we know know x_1 .. x_n */

    TRYM( b->h = BN_new() );
    BN_one( b->h );
    TRYM( tmp = BN_new() );
    /* h = g_1^x_1 ... g_n^x_n  where n = num_attribs */
    for ( i = 1; i < b->num_attribs; i++ ) {
	if ( !BN_is_zero( b->x[i] ) ) {	/* if x_i == 0 => g_i^x_i = 1 so NOP */
	    /* tmp = g_i^x_i */
	    TRYL( BN_mod_exp( tmp, b->g[i], b->x[i], b->params->p, b->ctx ) );
	    /* h *= tmp */
	    TRYL( BN_mod_mul( b->h, b->h, tmp, b->params->p, b->ctx ) );
	}
    }
    TRACE( PRINT( "h = ", b->h ) );
    TRYM( b->hp = BN_new() );
    /* h' = (h_0.h)^alpha where h_0 = g[0], alpha = x[0] */
    /* tmp = h_0.h */
    TRYL( BN_mod_mul( tmp, b->g[0], b->h, b->params->p, b->ctx ) );

    /* DELETE h */
    BN_free( b->h ); b->h = NULL;

    /* h' = tmp^alpha */
    TRYL( BN_mod_exp( b->hp, tmp, b->x[0], b->params->p, b->ctx ) );
    TRACE( PRINT( "hp = ", b->hp ) );

    TRYM( b->inv_alpha = BN_new() );
    /* ialpha = alpha^-1 */
    TRYL( BN_mod_inverse( b->inv_alpha, b->x[0], b->params->q, b->ctx ) );
    TRACE( PRINT( "ialpha = ", b->inv_alpha ) );
    /* DELETE alpha */
    BN_free( b->x[0] ); b->x[0] = NULL;

    TRYM( b->beta = BN_new() );
    /* beta = g^alpha2.(h_0.h)^alpha3 */
    /* tmp still holds h_0.h after above calc */
    /* tmp = tmp^alpha3 */
    TRYL( BN_mod_exp( tmp, tmp, b->alpha3, b->params->p, b->ctx ) );
    /* beta = g^alpha2 */
    TRYL( BN_mod_exp( b->beta, b->params->g, b->alpha2, b->params->p,b->ctx) );
    /* beta *= tmp */
    TRYL( BN_mod_mul( b->beta, b->beta, tmp, b->params->p, b->ctx ) );
    TRACE( PRINT( "beta = ", b->beta ) );

    b->state = brands_resp_pre;
 cleanup:
    FINALLY( CREDLIB_CALL_SEQUENCE ) { RESET(); }
    if ( tmp ) { BN_free( tmp ); }
    return ret;
}

int BRANDS_user_response( BRANDS* b, byte* in, int in_len,
			  byte** out, int* out_len ) {
    EXCEPTION;
    int req_len, alt_len;

    if ( !b || !in || !out ) { THROW( CREDLIB_NULL_PTR ); }
    if ( ( b->state != brands_req && b->state != brands_resp_pre )
	 || b->issuer ) {
	THROW( CREDLIB_CALL_SEQUENCE );
    }

    if ( b->state != brands_resp_pre ) {
	TRY( brands_user_response_precompute( b ) );
    }

    TRYIO_start( in );
    TRYIO( CREDLIB_read_bn( ptr, &b->s ) );
    TRACE( PRINT( "is = ", b->s ) );

    TRYM( b->gamma = BN_new() );
    /* gamma = beta.s */
    TRYL( BN_mod_mul( b->gamma, b->beta, b->s, b->params->p, b->ctx ) ) ;
    TRACE( PRINT( "gamma = ", b->gamma ) );

    /* DELETE beta */
    BN_free( b->beta ); b->beta = NULL;

    /* u' = SHA1(h'||gamma) mod q */
    TRYM( b->up = BN_new() );
    TRY( CREDLIB_mod_hash( b->up, b->hp, b->gamma, NULL, 0,
			   b->params->q, b->ctx ) );
    TRACE( PRINT( "up = ", b->up ) );

    /* DELETE gamma */
    BN_free( b->gamma ); b->gamma = NULL;

    /* u = u' - alpha2 */
    TRYM( b->u = BN_new() );
    TRYL( BN_mod_sub( b->u, b->up, b->alpha2, b->params->q, b->ctx ) );
    TRACE( PRINT( "u = ", b->u ) );

    /* DELETE alpha2 */
    BN_free( b->alpha2 ); b->alpha2 = NULL;

    req_len = CREDLIB_calc_bn( b->u );
    TRY( CREDLIB_out( out, &out_len, &alt_len, req_len ) );
    TRYIO_start( *out );
    TRYIO( CREDLIB_write_bn( ptr, b->u ) );
    if ( TRYIO_len( *out ) != req_len ) { THROW( CREDLIB_IO_INCONSISTENCY ); }
    TRACE( PRINT( "ou = ", b->u ) );
    b->state = brands_resp;

 cleanup:
    FINALLY( CREDLIB_CALL_SEQUENCE ) { RESET(); }
    return ret;
}

int BRANDS_issuer_send_cert( BRANDS* b, byte* in, int in_len,
			     byte** out, int* out_len ) {
    EXCEPTION;
    int req_len, alt_len;

    if ( !b || !in || !out ) { THROW( CREDLIB_NULL_PTR ); }
    if ( b->state != brands_chal || !b->issuer ) {
	THROW( CREDLIB_CALL_SEQUENCE );
    }

    TRYIO_start( in );
    TRYIO( CREDLIB_read_bn( ptr, &b->u ) );
    TRACE( PRINT( "iu = ", b->u ) );

    /* v = (k-u)t */
    TRYM( b->v = BN_new() );
    /* v = k-u */
    TRYL( BN_mod_sub( b->v, b->k, b->u, b->params->q, b->ctx ) );

    /* DELETE k */
    BN_free( b->k ); b->k = NULL;

    /* v *= t */
    TRYL( BN_mod_mul( b->v, b->v, b->t, b->params->q, b->ctx ) );
    TRACE( PRINT( "v = ", b->v ) );

    /* DELETE t */
    BN_free( b->t ); b->t = NULL;

    req_len = CREDLIB_calc_bn( b->v );
    TRY( CREDLIB_out( out, &out_len, &alt_len, req_len ) );
    TRYIO_start( *out );
    TRYIO( CREDLIB_write_bn( ptr, b->v ) );
    if ( TRYIO_len( *out ) != req_len ) { THROW( CREDLIB_IO_INCONSISTENCY ); }
    TRACE( PRINT( "ov = ", b->v ) );
    b->state = brands_key;	/* back to start */

 cleanup:
    FINALLY( CREDLIB_CALL_SEQUENCE ) { RESET(); }
    return ret;
}

int BRANDS_user_recv_cert( BRANDS *b, byte* in, int in_len ) {
    EXCEPTION;

    if ( !b || !in ) { THROW( CREDLIB_NULL_PTR ); }
    if ( b->state != brands_resp || b->issuer ) {
	THROW( CREDLIB_CALL_SEQUENCE );
    }

    TRYIO_start( in );
    TRYIO( CREDLIB_read_bn( ptr, &b->v ) );
    TRACE( PRINT( "iv = ", b->v ) );

    /* v' = (v+alpha3).alpha^-1 where alpha = x[0] */
    TRYM( b->vp = BN_new() );
    /* v' = v+alpha3 */
    TRYL( BN_mod_add( b->vp, b->v, b->alpha3, b->params->q, b->ctx ) );

    /* DELETE alpha3 */
    BN_free( b->alpha3 ); b->alpha3 = NULL;

    /* v' *= tmp */
    TRYL( BN_mod_mul( b->vp, b->vp, b->inv_alpha, b->params->q, b->ctx ) );
    TRACE( PRINT( "vp = ", b->vp ) );
    b->state = brands_cred;

 cleanup:
    FINALLY( CREDLIB_CALL_SEQUENCE ) { RESET(); }
    return ret;
}

static
int brands_user_verify( BRANDS* b ) {
    EXCEPTION;
    BIGNUM* tmp = NULL;
    BIGNUM* tmp2 = NULL;

    if ( !b ) { THROW( CREDLIB_NULL_PTR ); }

    /* u' =? SHA1( h' || g^u'.h'^v' ) mod q */

    /* tmp = g^u'.h'^v' */
    TRYM( tmp = BN_new() );
    TRYM( tmp2 = BN_new() );
    /* tmp = h'^v' */
    TRYL( BN_mod_exp( tmp, b->hp, b->vp, b->params->p, b->ctx ) );
    /* tmp2 = g^u' */
    TRYL( BN_mod_exp( tmp2, b->params->g, b->up, b->params->p, b->ctx ) );
    /* tmp *= tmp2 */
    TRYL( BN_mod_mul( tmp, tmp, tmp2, b->params->p, b->ctx ) );
    TRACE( PRINT( "gammat = ", tmp ) );
    /* tmp = SHA1( h' || tmp ) mod q */
    TRY( CREDLIB_mod_hash( tmp, b->hp, tmp, NULL, 0, b->params->q, b->ctx ) );

    if ( BN_cmp( b->up, tmp ) != 0 ) { RETURN( CREDLIB_FAIL ); }

 cleanup:
    if ( tmp ) { BN_free( tmp ); }
    if ( tmp2 ) { BN_free( tmp2 ); }
    return ret;
}

int BRANDS_user_attrib_show( BRANDS* b, uint_t attrib ) {
    EXCEPTION;
    int i;

    if ( !b ) { THROW( CREDLIB_NULL_PTR ); }
    if ( b->state != brands_cred || b->issuer ) {
	THROW( CREDLIB_CALL_SEQUENCE );
    }

    if ( attrib > b->num_attribs-1 ) {
	THROW( CREDLIB_BRANDS_TOO_MANY_ATTRIBS );
    }

    if ( !b->show ) {
	b->show = CREDLIB_malloc( sizeof(bool_t)*b->num_attribs );
	/* by default show nothing */
	for ( i = 0; i < b->num_attribs; i++ ) { b->show[i] = false; }
    }

    b->show[attrib+1] = true;

 cleanup:
    FINALLY( CREDLIB_CALL_SEQUENCE ) { RESET(); }
    return ret;
}

int BRANDS_user_attrib_show_array( BRANDS* b, bool_t* show, uint_t show_num ) {
    EXCEPTION;
    int i;

    /* num_attribs includes alpha */
    if ( show && show_num > b->num_attribs-1 ) {
	THROW( CREDLIB_BRANDS_TOO_MANY_ATTRIBS );
    }
    if ( !b->show ) {
	b->show = CREDLIB_malloc( sizeof(bool_t)*b->num_attribs );
	/* by default show nothing */
	for ( i = 0; i < b->num_attribs; i++ ) { b->show[i] = false; }
    }

    if ( show ) {
	/* remember what was shown; if missing attribs assume not shown*/
	b->show[0] = false;
	for ( i = 0; i < show_num; i++ ) {
	    b->show[i+1] = show[i];
	}
	for ( i = show_num+1; i < b->num_attribs; i++ ) {
	    b->show[i] = false;	/* default hidden */
	}
    }
 cleanup:
    return ret;
}

int BRANDS_user_send_show( BRANDS* b, bool_t* show, uint_t show_num,
			   byte** out, int* out_len ) {
    EXCEPTION;
    BIGNUM* tmp = NULL;
    int i, alt_len, req_len;
    byte* show_out = NULL;
    int show_out_len;

    if ( !b ) { THROW( CREDLIB_NULL_PTR ); }
    if ( b->state != brands_cred || b->issuer ) {
	THROW( CREDLIB_CALL_SEQUENCE );
    }

    TRY( BRANDS_user_attrib_show_array( b, show, show_num ) );

    TRYM( b->w = CREDLIB_BN_array_malloc( b->num_attribs ) );
    /* w_0 = rand Zq */
    TRY( CREDLIB_rand_range( b->w[0], 0, b->params->q ) );
    TRACE( PRINT( "w[0] = ", b->w[0] ) );
    /* forall hidden i  */
    /* w_i = rand Zq */
    for ( i = 1; i < b->num_attribs; i++ ) {
	if ( !b->show[i] ) {	/* hidden */
	    TRY( CREDLIB_rand_range( b->w[i], 0, b->params->q ) );
	    TRACE( printf( "w[%d] = ", i ); PRINT( "", b->w[i] ) );
	}
    }

    /* a = SHA1( prod( g_i^w_i ).h'^w_0 ) for all hidden i */
    TRYM( b->a = BN_new() );
    TRYM( tmp = BN_new() );
    /* a = h'^w[0] */
    TRYL( BN_mod_exp( b->a, b->hp, b->w[0], b->params->p, b->ctx ) );
    for ( i = 1; i < b->num_attribs; i++ ) {
	/* tmp = g_i^w_i */
	TRYL( BN_mod_exp( tmp, b->g[i], b->w[i], b->params->p, b->ctx ) );
	/* a *= tmp */
	TRYL( BN_mod_mul( b->a, b->a, tmp, b->params->p, b->ctx ) );
    }
    TRACE( PRINT( "aprod = ", b->a ) );

    /* a = SHA1( a ) */
    TRY( CREDLIB_mod_hash( b->a, b->a, NULL, NULL, 0, b->params->p, b->ctx ) );
    TRACE( printf( "# a = SHA1( aprod ) mod p\n" ) );
    TRACE( PRINT( "a = ", b->a ) );

    /* c = SHA1( a||M||show[] ) mod q */
    show_out_len = CREDLIB_calc_bool_array_small( b->num_attribs, 1 );
    TRYM( show_out = CREDLIB_malloc( show_out_len ) );
    TRYIO_start( show_out );
    TRYIO( CREDLIB_write_bool_array_small( show_out, b->show,
					   b->num_attribs, 1 ) );
    if ( TRYIO_len( show_out ) != show_out_len ) {
	THROW( CREDLIB_IO_INCONSISTENCY );
    }

    TRYM( b->c = BN_new() );
    TRY( CREDLIB_mod_hash( b->c, b->a, b->M, show_out, show_out_len,
			   b->params->p, b->ctx ) );
    TRACE( PRINT( "c = ", b->c ) );

    /* r_0 = -c.alpha^-1 + w_0 */
    TRYM( b->r = CREDLIB_BN_array_malloc( b->num_attribs ) );
    /* r_0 = w_0 */
    TRYL( BN_copy( b->r[0], b->w[0] ) );
    /* tmp = c.alpha^-1 */
    TRYL( BN_mod_mul( tmp, b->c, b->inv_alpha, b->params->q, b->ctx ) );
    /* r_0 -= tmp */
    TRYL( BN_mod_sub( b->r[0], b->r[0], tmp, b->params->q, b->ctx ) );
    TRACE( PRINT( "r[0] = ", b->r[0] ) );

    /* forall hidden i */
    for ( i = 1; i < b->num_attribs; i++ ) {
	if ( !b->show[i] ) {
	    /* r_i = c.x_i + w_i */
	    /* r_i = c.x_i */
	    TRYL( BN_mod_mul( b->r[i], b->c, b->x[i], b->params->q, b->ctx ) );
	    /* r_i += w_i */
	    TRYL( BN_mod_add( b->r[i], b->r[i], b->w[i], b->params->q,
			      b->ctx ) );
	    TRACE( printf( "r[%d] = ", i ); PRINT( "", b->r[i] ) );
	}
    }

    req_len = CREDLIB_calc_bn( b->a ) +
	CREDLIB_calc_bn( b->hp ) +
	CREDLIB_calc_bn( b->up ) +
	CREDLIB_calc_bn( b->vp ) +
	show_out_len +
	CREDLIB_calc_bn( b->r[0] );
    for ( i = 1; i < b->num_attribs; i++ ) {
	req_len += b->show[i] ? CREDLIB_calc_bn( b->x[i] ) :
	    CREDLIB_calc_bn( b->r[i] );
    }
    TRY( CREDLIB_out( out, &out_len, &alt_len, req_len ) );
    TRYIO_start( *out );
    TRACE( PRINT( "oa = ", b->a ) );
    TRACE( PRINT( "ohp = ", b->hp ) );
    TRACE( PRINT( "oup = ", b->up ) );
    TRACE( PRINT( "ovp = ", b->vp ) );
    TRACE( for ( i = 1; i < b->num_attribs; i++ ) {
	printf( "oshow[%d] = %d\n", i, b->show[i] );
    } )
    TRACE( PRINT( "or[0] = ", b->r[0] ) );
    TRYIO( CREDLIB_write_bn( ptr, b->a ) );
    TRYIO( CREDLIB_write_bn( ptr, b->hp ) );
    TRYIO( CREDLIB_write_bn( ptr, b->up ) );
    TRYIO( CREDLIB_write_bn( ptr, b->vp ) );
    TRYIO( CREDLIB_write( ptr, show_out, show_out_len ) );
    TRYIO( CREDLIB_write_bn( ptr, b->r[0] ) );
    for ( i = 1; i < b->num_attribs; i++ ) {
	if ( b->show[i] ) {
	    TRACE( printf( "ox[%d] = ", i ); PRINT( "", b->x[i] ) )
	    TRYIO( CREDLIB_write_bn( ptr, b->x[i] ) );
	} else {
	    TRACE( printf( "or[%d] = ", i ); PRINT( "", b->r[i] ) )
	    TRYIO( CREDLIB_write_bn( ptr, b->r[i] ) );
 	}
    }
    if ( TRYIO_len( *out ) != req_len ) { THROW( CREDLIB_IO_INCONSISTENCY ); }
    b->state = brands_show;

 cleanup:
    FINALLY( CREDLIB_CALL_SEQUENCE ) { RESET(); }
    if ( show_out ) { CREDLIB_free( show_out ); }
    if ( tmp ) { BN_free( tmp ); }
    return ret;
}

static
int brands_verifier_verify( BRANDS* b ) {
    EXCEPTION;
    BIGNUM* tmp = NULL;
    BIGNUM* tmp2 = NULL;
    byte* show_out = NULL;
    int show_out_len, i;

    if ( !b ) { THROW( CREDLIB_NULL_PTR ); }

    TRYM( b->c = BN_new() );
    TRYM( b->e = BN_new() );

    show_out_len = CREDLIB_calc_bool_array_small( b->num_attribs, 1 );
    TRYM( show_out = CREDLIB_malloc( show_out_len ) );
    TRYIO_start( show_out );
    TRYIO( CREDLIB_write_bool_array_small( show_out, b->show,
					   b->num_attribs, 1 ) );
    if ( TRYIO_len( show_out ) != show_out_len ) {
	THROW( CREDLIB_IO_INCONSISTENCY );
    }

    /* c = SHA1( a||M||show[] ) mod q */
    TRY( CREDLIB_mod_hash( b->c, b->a, b->M, show_out, show_out_len,
			   b->params->q, b->ctx ) );
    TRACE( PRINT( "tc = ", b->c ) );

    TRYM( tmp = BN_new() );
    TRYM( tmp2 = BN_new() );

    /* e = ( prod( g_i^x_i ).h_0 )^c mod p */
    /* e = h_0 */
    TRYL( BN_copy( b->e, b->g[0] ) );
    for ( i = 1; i < b->num_attribs; i++ ) {
	if ( b->show[i] ) {
	    /* tmp = g_i^x_i */
	    TRYL( BN_mod_exp( tmp, b->g[i], b->x[i], b->params->p, b->ctx ) );
	    /* e *= tmp */
	    TRYL( BN_mod_mul( b->e, b->e, tmp, b->params->p, b->ctx ) );
	}
    }
    /* e = e^c */
    TRYL( BN_mod_exp( b->e, b->e, b->c, b->params->p, b->ctx ) );
    TRACE( PRINT( "te = ", b->e ) );

    /* a' =? SHA1( prod( g_i^r_i ).h'^r_0.e mod p ) */
    /* tmp = h'^r_0 */
    TRYL( BN_mod_exp( tmp, b->hp, b->r[0], b->params->p, b->ctx ) );
    /* tmp *= e */
    TRYL( BN_mod_mul( tmp, tmp, b->e, b->params->p, b->ctx ) );
    for ( i = 1; i < b->num_attribs; i++ ) {
	if ( !b->show[i] ) {
	    /* tmp2 = g_i^r_i */
	    TRYL( BN_mod_exp( tmp2, b->g[i], b->r[i], b->params->p, b->ctx ) );
	    /* tmp *= tmp */
	    TRYL( BN_mod_mul( tmp, tmp, tmp2, b->params->p, b->ctx ) );
	}
    }
    TRACE( PRINT( "aprodt = ", tmp ) );
    /* tmp = SHA1( tmp ) mod p */
    TRY( CREDLIB_mod_hash( tmp, tmp, NULL, NULL, 0, b->params->p, b->ctx ) );
    TRACE( PRINT( "ta = ", tmp ) );
    /* a =? tmp */
    if ( BN_cmp( b->a, tmp ) != 0 ) { THROW( CREDLIB_FAIL ); }

 cleanup:
    if ( tmp ) { BN_free( tmp ); }
    if ( tmp2 ) { BN_free( tmp2 ); }
    if ( show_out ) { CREDLIB_free( show_out ); }
    return ret;
}

int BRANDS_verifier_recv_show( BRANDS* b, byte* in, int in_len ) {
    EXCEPTION;
    int i, show_num;

    if ( !b || !in ) { THROW( CREDLIB_NULL_PTR ); }

    if ( b->state != brands_key ) { THROW( CREDLIB_CALL_SEQUENCE ); }

    if ( !b->show ) {
	b->show = CREDLIB_malloc( sizeof(bool_t)*b->num_attribs );
    }

    show_num = b->num_attribs;
    TRYIO_start( in );

    TRYIO( CREDLIB_read_bn( ptr, &b->a ) );
    TRYIO( CREDLIB_read_bn( ptr, &b->hp ) );
    TRYIO( CREDLIB_read_bn( ptr, &b->up ) );
    TRYIO( CREDLIB_read_bn( ptr, &b->vp ) );
    TRACE( PRINT( "ia = ", b->a ) );
    TRACE( PRINT( "ihp = ", b->hp ) );
    TRACE( PRINT( "iup = ", b->up ) );
    TRACE( PRINT( "ivp = ", b->vp ) );
    TRYIO( CREDLIB_read_bool_array_small( ptr, &b->show, &show_num, 1 ) );
    b->show[0] = false;		/* redundant, but be sure */
    for ( i = show_num; i < b->num_attribs; i++ ) {
	b->show[i] = false;	/* default not shown */
    }
    TRACE( for ( i = 1; i < b->num_attribs; i++ ) {
	printf( "ishow[%d] = %d\n", i, b->show[i] );
    } );
    if ( !b->r ) {
	TRYM( b->r = CREDLIB_BN_array_malloc( b->num_attribs ) );
    }
    TRYIO( CREDLIB_read_bn( ptr, &b->r[0] ) );
    TRACE( PRINT( "ir[0] = ", b->r[0] ) );

    for ( i = 1; i < b->num_attribs; i++ ) {
	if ( b->show[i] ) {
	    TRYIO( CREDLIB_read_bn( ptr, &b->x[i] ) );
	    TRACE( printf( "ix[%d] = ", i ); PRINT( "", b->x[i] ) )
	} else {
	    TRYIO( CREDLIB_read_bn( ptr, &b->r[i] ) );
	    TRACE( printf( "ir[%d] = ", i ); PRINT( "", b->r[i] ) )
 	}
    }

    /* u' =? SHA1( h' || (g^u'.h'^v' mod p) ) mod q */

    TRY( brands_user_verify( b ) );
    /* verify the show */
    TRY( brands_verifier_verify( b ) );
    b->state = brands_show;
 cleanup:
    FINALLY( CREDLIB_CALL_SEQUENCE ) { RESET(); }
    return ret;
}

int BRANDS_verify( BRANDS* b ) {
    EXCEPTION;

    if ( !b ) { THROW( CREDLIB_NULL_PTR ); }

    switch ( b->state ) {
    case brands_cred: TRY( brands_user_verify( b ) ); break;
    case brands_show: TRY( brands_verifier_verify( b ) ); break;
    default: THROW( CREDLIB_CALL_SEQUENCE ); break;
    }
 cleanup:
    FINALLY( CREDLIB_CALL_SEQUENCE ) { RESET(); } /* pass error out */
    return ret;
}

/* unimplemented */

int BRANDS_export( BRANDS* b, byte** out, int out_len ) {
    EXCEPTION;

    THROW( CREDLIB_UNIMPLEMENTED );
    if ( !b || !out ) { THROW( CREDLIB_NULL_PTR ); }
    switch ( b->state ) {
    case brands_key:
    case brands_show:
    default: break;
    }
 cleanup:
    FINALLY( CREDLIB_UNIMPLEMENTED ) { RESET(); } /* pass error out */
    return ret;
}

/* unimplemented */

int BRANDS_save( BRANDS* b, byte** out, int out_len ) {
    EXCEPTION;

    THROW( CREDLIB_UNIMPLEMENTED );
    if ( !b || !out ) { THROW( CREDLIB_NULL_PTR ); }
    switch ( b->state ) {
    case brands_key:
	if ( b->issuer ) {
	    /* save issuer private key */
	} else {
	    /* save issuer public key */
	}
	break;
    case brands_req: 		/* save after user request  */
	break;
    case brands_resp:		/* save after user response */
	break;
    case brands_cred:		/* save user credential */
	break;
    case brands_chal:		/* save after issuer challenge */
	break;
    case brands_show:		/* save verifier show */
    case brands_undef:		/*  */
    default: break;
    }

 cleanup:
    FINALLY( CREDLIB_UNIMPLEMENTED ) { RESET(); } /* pass error out */
    return ret;
}

int BRANDS_precompute( BRANDS* b ) {
    EXCEPTION;

    if ( !b ) { THROW( CREDLIB_NULL_PTR ); }

    switch ( b->state ) {
    case brands_key:
	if ( b->issuer ) {
	} else {
	    TRY( brands_user_request_precompute( b ) );
	}
	break;
    case brands_req:
	TRY( brands_user_response_precompute( b ) );
	break;
    default: break;		/* nothing to precompute */
    }
 cleanup:
    return ret;
}

int BRANDS_test( int key_size, int attribs, bool_t precompute ) {
    EXCEPTION;
    BRANDS* issuer = NULL;
    BRANDS* cred = NULL;
    BRANDS* verifier = NULL;
    byte* req = NULL;
    int req_len;
    byte* chal = NULL;
    int chal_len;
    byte* resp = NULL;
    int resp_len;
    byte* cert = NULL;
    int cert_len;
    byte* show = NULL;
    int show_len;

    TRACE( printf( "ibase=obase=16\n" ) );

    /* ISSUER: key gen */
    TRYM( issuer = BRANDS_new() );
    TRY( BRANDS_key_generate( issuer, NULL, key_size, attribs ) );

    /* USER: create a credential from working with this issuer */
    TRYM( cred = BRANDS_new() );
    TRY( BRANDS_key_set( cred, issuer ) );

    /* USER: set some attributes */

    if ( attribs > 0 ) {
	TRY( BRANDS_user_attrib_set( cred, 0, _("male") ) );
	if ( attribs > 1 ) {
	    TRY( BRANDS_user_attrib_set( cred, 1, _("british") ) );
	    if ( attribs > 2 ) {
		TRY( BRANDS_user_attrib_set( cred, 2, _("30-35") ) );
	    }
	}
    }

    /* USER -> ISSUER: request cred */
    if ( precompute ) { TRY( BRANDS_precompute( cred ) ); }
    TRY( BRANDS_user_request( cred, &req, &req_len ) );
    /* USER <- ISSUER: challenge  */
    TRY( BRANDS_issuer_challenge( issuer, req, req_len, &chal, &chal_len ) );
    /* USER -> ISSUER: response */
    if ( precompute ) { TRY( BRANDS_precompute( cred ) ); }
    TRY( BRANDS_user_response( cred, chal, chal_len, &resp, &resp_len ) );
    /* USER <- ISSUER: (blind) cert  */
    TRY( BRANDS_issuer_send_cert( issuer, resp, resp_len, &cert, &cert_len ) );
    TRY( BRANDS_user_recv_cert( cred, cert, cert_len ) );
    /* USER: re-verify (optional, already done by user_recv_cert) */
    TRY( BRANDS_verify( cred ) ); /* verifies cert */

    /* now showing */

    /* USER: choose some attribs to show */
    if ( attribs > 0 ) {
	TRY( BRANDS_user_attrib_show( cred, 0 ) );
	if ( attribs > 2 ) {
	    TRY( BRANDS_user_attrib_show( cred, 2 ) );
	}
    }
    /* show credential */
    TRY( BRANDS_user_send_show( cred, NULL, 0, &show, &show_len ) );
    fprintf( stderr, "show len = %d\n", show_len );
    /* USER: self verify show (optional) */
    TRY( BRANDS_verify( cred ) ); /* self verifies show */

    /* VERIFIER: verify credential */
    TRYM( verifier = BRANDS_new() );
    TRY( BRANDS_key_set( verifier, issuer ) );
    TRY( BRANDS_verifier_recv_show( verifier, show, show_len ) );
    /* VERIFIER: re-verify credential */
    TRY( BRANDS_verify( verifier ) ); /* 3rd party verifies show */

 cleanup:
    if ( issuer ) { BRANDS_free( issuer ); }
    if ( cred ) { BRANDS_free( cred ); }
    if ( req ) { CREDLIB_free( req ); }
    if ( chal ) { CREDLIB_free( chal ); }
    if ( cert ) { CREDLIB_free( cert ); }
    if ( show ) { CREDLIB_free( show ); }
    return ret;
}
