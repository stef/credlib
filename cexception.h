/* -*- Mode: C; c-file-style: "stroustrup" -*- */

#if !defined( _cexcept_h )
#define _cexcept_h

#if defined( __cplusplus )
extern "C" {
#endif

#include <limits.h>

/* C exception like stuff */

/* 0 = normal fail, 1 = ok, -ve codes are exceptions */

#define CEXCEPT_ALL INT_MIN

#define DO( x ) do { x } while (0)
#define RESET() ( (cexcept_file = NULL),(cexcept_line = 0),1 )
#define EXCEPTION int ret=1; byte* ptr=ptr
extern int cexcept_line;
extern const char* cexcept_file;
#define THROW( x ) do { ret = (x); \
	if ( cexcept_file == NULL && cexcept_line == 0 ) { \
		cexcept_line = __LINE__; cexcept_file = __FILE__; \
	} \
	goto cleanup; } while (0)
#define RETURN( x ) DO( ret=(x); goto cleanup; )
#define TRY( x ) DO( ret = (int)(x); if ( ret<1 ) { THROW(ret); } )
#define TRYIO_start( x ) ptr = (byte*)(x)
#define TRYIO( x ) DO( ret=(x); if(ret<0){ THROW(ret); } ptr+=ret; )
#define TRYIO_len( x ) ( ptr-(byte*)(x) )
#define TRYIO_mark( x ) ( (byte*)(x) = ptr )
#define TRYIO_mark_len( x ) ( ptr - (byte*)(x) )
#define CATCH( e ) if ( (ret == (e) || ((e) == CEXCEPT_ALL && ret<0)) && \
	((ret=1),RESET() ) )
#define FINALLY( e ) if ( ret == (e) || ((e) == CEXCEPT_ALL && ret<0) )

#define CEXCEPT_MAX_WHERE 1024
extern char cexcept_where[];
#define CEXCEPT_strwhere() (snprintf( cexcept_where, CEXCEPT_MAX_WHERE, \
	"at %s:%d", cexcept_file, cexcept_line ), cexcept_where)

extern const char* cexcept_err_string[];
#define CEXCEPT_strerror( x ) ((x)>0?"ok":( ((x)==0)?"fail":cexcept_err_string[ -((x)+1) ]))

#if defined( __cplusplus )
}
#endif

#endif
