#ifndef TINC_COMPRESSION_H
#define TINC_COMPRESSION_H

typedef enum compression_level_t {
	COMPRESS_NONE = 0,

	COMPRESS_ZLIB_1 = 1,
	COMPRESS_ZLIB_2 = 2,
	COMPRESS_ZLIB_3 = 3,
	COMPRESS_ZLIB_4 = 4,
	COMPRESS_ZLIB_5 = 5,
	COMPRESS_ZLIB_6 = 6,
	COMPRESS_ZLIB_7 = 7,
	COMPRESS_ZLIB_8 = 8,
	COMPRESS_ZLIB_9 = 9,

	COMPRESS_LZO_LO = 10,
	COMPRESS_LZO_HI = 11,

	COMPRESS_LZ4 = 12,

	COMPRESS_GUARD = INT_MAX, /* ensure that sizeof(compression_level_t) == sizeof(int) */
} compression_level_t;

#endif
