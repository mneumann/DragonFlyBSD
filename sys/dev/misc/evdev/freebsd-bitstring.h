/*-
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Paul Vixie.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Copyright (c) 2014 Spectra Logic Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 *    substantially similar to the "NO WARRANTY" disclaimer below
 *    ("Disclaimer") and any redistribution must be conditioned upon
 *    including a substantially similar Disclaimer requirement for further
 *    binary redistribution.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDERS OR CONTRIBUTORS BE LIABLE FOR SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 *
 * $FreeBSD$
 */
#ifndef _SYS_FREEBSD_BITSTRING_H_
#define	_SYS_FREEBSD_BITSTRING_H_

#include <sys/types.h>

/*
 * Begin: Ad hoc definitions from FreeBSD sys/sys/types.h
 */

/*
 * Population count algorithm using SWAR approach
 * - "SIMD Within A Register".
 */
static __inline __uint16_t
__bitcount16(__uint16_t _x)
{

	_x = (_x & 0x5555) + ((_x & 0xaaaa) >> 1);
	_x = (_x & 0x3333) + ((_x & 0xcccc) >> 2);
	_x = (_x + (_x >> 4)) & 0x0f0f;
	_x = (_x + (_x >> 8)) & 0x00ff;
	return (_x);
}

static __inline __uint32_t
__bitcount32(__uint32_t _x)
{

	_x = (_x & 0x55555555) + ((_x & 0xaaaaaaaa) >> 1);
	_x = (_x & 0x33333333) + ((_x & 0xcccccccc) >> 2);
	_x = (_x + (_x >> 4)) & 0x0f0f0f0f;
	_x = (_x + (_x >> 8));
	_x = (_x + (_x >> 16)) & 0x000000ff;
	return (_x);
}

#ifdef __LP64__
static __inline __uint64_t
__bitcount64(__uint64_t _x)
{

	_x = (_x & 0x5555555555555555) + ((_x & 0xaaaaaaaaaaaaaaaa) >> 1);
	_x = (_x & 0x3333333333333333) + ((_x & 0xcccccccccccccccc) >> 2);
	_x = (_x + (_x >> 4)) & 0x0f0f0f0f0f0f0f0f;
	_x = (_x + (_x >> 8));
	_x = (_x + (_x >> 16));
	_x = (_x + (_x >> 32)) & 0x000000ff;
	return (_x);
}

#define	__bitcountl(x)	__bitcount64((unsigned long)(x))
#else
static __inline __uint64_t
__bitcount64(__uint64_t _x)
{

	return (__bitcount32(_x >> 32) + __bitcount32(_x));
}

#define	__bitcountl(x)	__bitcount32((unsigned long)(x))
#endif
#define	__bitcount(x)	__bitcount32((unsigned int)(x))
/*
 * End: Ad hoc definitions from FreeBSD sys/sys/types.h
 */

typedef	unsigned long bitstr_t;

/*---------------------- Private Implementation Details ----------------------*/
#define	_BITSTR_MASK (~0UL)
#define	_BITSTR_BITS (sizeof(bitstr_t) * 8)

#ifdef roundup2
#define        _bit_roundup2 roundup2
#else
#define        _bit_roundup2(x, y)        (((x)+((y)-1))&(~((y)-1))) /* if y is powers of two */
#endif

/* bitstr_t in bit string containing the bit. */
static inline int
_bit_idx(int _bit)
{
	return (_bit / _BITSTR_BITS);
}

/* bit number within bitstr_t at _bit_idx(_bit). */
static inline int
_bit_offset(int _bit)
{
	return (_bit % _BITSTR_BITS);
}

/* Mask for the bit within its long. */
static inline bitstr_t
_bit_mask(int _bit)
{
	return (1UL << _bit_offset(_bit));
}

static inline bitstr_t
_bit_make_mask(int _start, int _stop)
{
	return ((_BITSTR_MASK << _bit_offset(_start)) &
	    (_BITSTR_MASK >> (_BITSTR_BITS - _bit_offset(_stop) - 1)));
}

/*----------------------------- Public Interface -----------------------------*/
/* Number of bytes allocated for a bit string of nbits bits */
#define	bitstr_size(_nbits) (_bit_roundup2(_nbits, _BITSTR_BITS) / 8)

/* Allocate a bit string initialized with no bits set. */
#ifdef _KERNEL
static inline bitstr_t *
bit_alloc(int _nbits, struct malloc_type *type, int flags)
{
	return ((bitstr_t *)kmalloc(bitstr_size(_nbits), type, flags | M_ZERO));
}
#else
static inline bitstr_t *
bit_alloc(int _nbits)
{
	return ((bitstr_t *)calloc(bitstr_size(_nbits), 1));
}
#endif

/* Allocate a bit string on the stack */
#define	bit_decl(name, nbits) \
	((name)[bitstr_size(nbits) / sizeof(bitstr_t)])

/* Is bit N of bit string set? */
static inline int
bit_test(const bitstr_t *_bitstr, int _bit)
{
	return ((_bitstr[_bit_idx(_bit)] & _bit_mask(_bit)) != 0);
}

/* Set bit N of bit string. */
static inline void
bit_set(bitstr_t *_bitstr, int _bit)
{
	_bitstr[_bit_idx(_bit)] |= _bit_mask(_bit);
}

/* clear bit N of bit string name */
static inline void
bit_clear(bitstr_t *_bitstr, int _bit)
{
	_bitstr[_bit_idx(_bit)] &= ~_bit_mask(_bit);
}

/* Set bits start ... stop inclusive in bit string. */
static inline void
bit_nset(bitstr_t *_bitstr, int _start, int _stop)
{
	bitstr_t *_stopbitstr;

	_stopbitstr = _bitstr + _bit_idx(_stop);
	_bitstr += _bit_idx(_start);

	if (_bitstr == _stopbitstr) {
		*_bitstr |= _bit_make_mask(_start, _stop);
	} else {
		*_bitstr |= _bit_make_mask(_start, _BITSTR_BITS - 1);
		while (++_bitstr < _stopbitstr)
	    		*_bitstr = _BITSTR_MASK;
		*_stopbitstr |= _bit_make_mask(0, _stop);
	}
}

/* Clear bits start ... stop inclusive in bit string. */
static inline void
bit_nclear(bitstr_t *_bitstr, int _start, int _stop)
{
	bitstr_t *_stopbitstr;

	_stopbitstr = _bitstr + _bit_idx(_stop);
	_bitstr += _bit_idx(_start);

	if (_bitstr == _stopbitstr) {
		*_bitstr &= ~_bit_make_mask(_start, _stop);
	} else {
		*_bitstr &= ~_bit_make_mask(_start, _BITSTR_BITS - 1);
		while (++_bitstr < _stopbitstr)
			*_bitstr = 0;
		*_stopbitstr &= ~_bit_make_mask(0, _stop);
	}
}

/* Find the first '_match'-bit in bit string at or after bit start. */
static inline int
bit_ff_at_(bitstr_t *_bitstr, int _start, int _nbits, int _match)
{
	bitstr_t *_curbitstr;
	bitstr_t *_stopbitstr;
	bitstr_t _mask;
	bitstr_t _test;
	int _value;

	if (_start >= _nbits || _nbits <= 0)
		return (-1);

	_curbitstr = _bitstr + _bit_idx(_start);
	_stopbitstr = _bitstr + _bit_idx(_nbits - 1);
	_mask = _match ? 0 : _BITSTR_MASK;

	_test = _mask ^ *_curbitstr;
	if (_bit_offset(_start) != 0)
		_test &= _bit_make_mask(_start, _BITSTR_BITS - 1);
	while (_test == 0 && _curbitstr < _stopbitstr)
		_test = _mask ^ *(++_curbitstr);

	_value = ((_curbitstr - _bitstr) * _BITSTR_BITS) + ffsl(_test) - 1;
	if (_test == 0 ||
	    (_bit_offset(_nbits) != 0 && (u_int)_value >= _nbits))
		_value = -1;
	return (_value);
}

/* Find the first bit set in bit string at or after bit start. */
static inline void
bit_ffs_at(bitstr_t *_bitstr, int _start, int _nbits, int *_result)
{
	bitstr_t *_curbitstr;
	bitstr_t *_stopbitstr;
	bitstr_t _test;
	int _value, _offset;

	if (_nbits > 0) {
		_curbitstr = _bitstr + _bit_idx(_start);
		_stopbitstr = _bitstr + _bit_idx(_nbits - 1);

		_test = *_curbitstr;
		if (_bit_offset(_start) != 0)
			_test &= _bit_make_mask(_start, _BITSTR_BITS - 1);
		while (_test == 0 && _curbitstr < _stopbitstr)
			_test = *(++_curbitstr);

		_offset = ffsl(_test);
		_value = ((_curbitstr - _bitstr) * _BITSTR_BITS) + _offset - 1;
		if (_offset == 0 || _value >= _nbits)
			_value = -1;
	} else {
		_value = -1;
	}
	*_result = _value;
}

/* Find the first bit clear in bit string at or after bit start. */
static inline void
bit_ffc_at(bitstr_t *_bitstr, int _start, int _nbits, int *_result)
{
	bitstr_t *_curbitstr;
	bitstr_t *_stopbitstr;
	bitstr_t _test;
	int _value, _offset;

	if (_nbits > 0) {
		_curbitstr = _bitstr + _bit_idx(_start);
		_stopbitstr = _bitstr + _bit_idx(_nbits - 1);

		_test = *_curbitstr;
		if (_bit_offset(_start) != 0)
			_test |= _bit_make_mask(0, _start - 1);
		while (_test == _BITSTR_MASK && _curbitstr < _stopbitstr)
			_test = *(++_curbitstr);

		_offset = ffsl(~_test);
		_value = ((_curbitstr - _bitstr) * _BITSTR_BITS) + _offset - 1;
		if (_offset == 0 || _value >= _nbits)
			_value = -1;
	} else {
		_value = -1;
	}
	*_result = _value;
}

/* Find the first bit set in bit string. */
static inline void
bit_ffs(bitstr_t *_bitstr, int _nbits, int *_result)
{
	bit_ffs_at(_bitstr, /*start*/0, _nbits, _result);
}

/* Find the first bit clear in bit string. */
static inline void
bit_ffc(bitstr_t *_bitstr, int _nbits, int *_result)
{
	bit_ffc_at(_bitstr, /*start*/0, _nbits, _result);
}

/* Count the number of bits set in a bitstr of size _nbits at or after _start */
static inline void
bit_count(bitstr_t *_bitstr, int _start, int _nbits, int *_result)
{
	bitstr_t *_curbitstr, mask;
	int _value = 0, curbitstr_len;

	if (_start >= _nbits)
		goto out;

	_curbitstr = _bitstr + _bit_idx(_start);
	_nbits -= _BITSTR_BITS * _bit_idx(_start);
	_start -= _BITSTR_BITS * _bit_idx(_start);

	if (_start > 0) {
		curbitstr_len = (int)_BITSTR_BITS < _nbits ?
				(int)_BITSTR_BITS : _nbits;
		mask = _bit_make_mask(_start, _bit_offset(curbitstr_len - 1));
		_value += __bitcountl(*_curbitstr & mask);
		_curbitstr++;
		_nbits -= _BITSTR_BITS;
	}
	while (_nbits >= (int)_BITSTR_BITS) {
		_value += __bitcountl(*_curbitstr);
		_curbitstr++;
		_nbits -= _BITSTR_BITS;
	}
	if (_nbits > 0) {
		mask = _bit_make_mask(0, _bit_offset(_nbits - 1));
		_value += __bitcountl(*_curbitstr & mask);
	}

out:
	*_result = _value;
}

/* Traverse all set bits, assigning each location in turn to iter */
#define	bit_foreach_at(_bitstr, _start, _nbits, _iter)			\
	for ((_iter) = bit_ff_at_((_bitstr), (_start), (_nbits), 1);	\
	     (_iter) != -1;						\
	     (_iter) = bit_ff_at_((_bitstr), (_iter) + 1, (_nbits), 1))
#define	bit_foreach(_bitstr, _nbits, _iter)				\
	bit_foreach_at(_bitstr, /*start*/0, _nbits, _iter)

#endif	/* _SYS_FREEBSD_BITSTRING_H_ */
