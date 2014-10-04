/* -*- Mode: C; c-file-style: "stroustrup" -*- */

#if !defined( _types_h )
#define _types_h

#include <limits.h>

#define word unsigned
#define uint_t unsigned int

#define byte unsigned char 

#define bool_t byte
#define true 1
#define false 0


#define int8_t signed char
#define uint8_t unsigned char

#define int16_t signed short
#define uint16_t unsigned short

#if ( ULONG_MAX > 0xFFFFFFFFUL )
    #define int32_t signed int
    #define uint32_t unsigned int
    #define int64_t signed long
    #define uint64_t unsigned long
#elif ( UINT_MAX == 0xFFFFFFFFUL )
    #define int32_t signed int
    #define uint32_t unsigned int
#else 
    #define int32_t signed long
    #define uint32_t unsigned long
#endif

#if defined( __GNUC__ ) && !defined( word32 )
    #define int64_t signed long long
    #define uint64_t unsigned long long
#endif

#endif
