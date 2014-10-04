/* -*- Mode: C; c-file-style: "stroustrup" -*- */

#include <stdio.h>
#include <unistd.h>

#include "brands.h"
#include "credlib.h"

void usage( const char* msg ) {
    if ( msg ) { fputs( msg, stderr ); fputs( "\n\n", stderr ); }
    fprintf( stderr, "usage:\tbrands -v|-t|-k <bits>|-a <attribs>\n" );
    EXIT( 0 );
}

int test_mode = 0;
int key_size = 1024;
int attribs = 0;

int main( int argc, char* argv[] ) {
    int opt, ret = 1;
    int res1;
    bool_t precompute = false;

    while ( ( opt = getopt( argc, argv, "a:k:ptv" ) ) > 0 ) {
	switch ( opt ) {
	case 'a': attribs = atoi( optarg ); break;
	case 'k': key_size = atoi( optarg ); break;
	case 'p': precompute = true; break;
	case 't': test_mode = 1; break;
	case 'v': verbose_flag = 1; break;
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
	res1 = BRANDS_test( key_size, attribs, precompute );
	printf( "brands_test( %d, %d ) = %s\n", key_size, attribs,
		CEXCEPT_strerror(res1) );
	if ( res1 < 1 ) { printf( "%s\n", CEXCEPT_strwhere() ); }
	EXIT( ret );
    } else {
	usage( "short usage:" );
    }
    EXIT( ret );
}
