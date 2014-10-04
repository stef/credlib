/* -*- Mode: C; c-file-style: "stroustrup" -*- */

#include <stdio.h>
#include <unistd.h>

#include "chaum.h"
#include "credlib.h"

void usage( const char* msg ) {
    if ( msg ) { fputs( msg, stderr ); fputs( "\n\n", stderr ); }
    fprintf( stderr, "usage:\tchaum [-v|-t|-k <bits>]\n" );
    EXIT( 0 );
}

int test_mode = 0;
int key_size = 768;

int main( int argc, char* argv[] ) {
    int opt, ret = 1;
    int res1;

    while ( ( opt = getopt( argc, argv, "k:tv" ) ) > 0 ) {
	switch ( opt ) {
	case 'v': verbose_flag = 1; break;
	case 't': test_mode = 1; break;
	case 'k': key_size = atoi( optarg ); break;
        case '?':
            fprintf( stderr, "error: unrecognized option -%c", optopt );
            usage( "" );
            break;
        case ':':
            fprintf( stderr, "error: option -%c missing argument", optopt );
            usage( "" );
            break;
        default:
            usage( "error with argument processing" );
            break;
        }
    }

    if ( test_mode ) { 
	if ( key_size < CHAUM_MIN_KEY_SIZE( CHAUM_SERIAL_LEN ) ) {
	    fprintf( stderr, "key size %d too small, must be >= %d\n",
		     key_size, CHAUM_MIN_KEY_SIZE( CHAUM_SERIAL_LEN ) );
	    usage( NULL );
	}
	res1 = CHAUM_test( key_size );
	printf( "chaum_test( %d ) = %s", key_size, CEXCEPT_strerror(res1) );
	if ( res1 < 1 ) { printf( " %s", CEXCEPT_strwhere() ); }
	printf( "\n" );
	EXIT( ret );
    } else {
	usage( "short usage:" );
    }
    EXIT( ret );
}
