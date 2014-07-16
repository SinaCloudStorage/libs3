/** **************************************************************************
 * util.c
 * 
 * Copyright 2008 Bryan Ischo <bryan@ischo.com>
 * 
 * This file is part of libs3.
 * 
 * libs3 is free software: you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation, version 3 of the License.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of this library and its programs with the
 * OpenSSL library, and distribute linked combinations including the two.
 *
 * libs3 is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License version 3
 * along with libs3, in a file named COPYING.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 ************************************************************************** **/

#define _XOPEN_SOURCE

#include <ctype.h>
#include <string.h>
#include "util.h"
#include <time.h>
#include <sys/time.h>


// Convenience utility for making the code look nicer.  Tests a string
// against a format; only the characters specified in the format are
// checked (i.e. if the string is longer than the format, the string still
// checks out ok).  Format characters are:
// d - is a digit
// anything else - is that character
// Returns nonzero the string checks out, zero if it does not.
static int checkString(const char *str, const char *format)
{
    while (*format) {
        if (*format == 'd') {
            if (!isdigit(*str)) {
                return 0;
            }
        }
        else if (*str != *format) {
            return 0;
        }
        str++, format++;
    }

    return 1;
}


int urlEncode(char *dest, const char *src, int maxSrcSize)
{
    static const char *hex = "0123456789ABCDEF";

    int len = 0;

    if (src) while (*src) {
        if (++len > maxSrcSize) {
            *dest = 0;
            return 0;
        }
        unsigned char c = *src;
        if (isalnum(c) ||
            (c == '-') || (c == '_') || (c == '.') || (c == '!') || 
            (c == '~') || (c == '*') || (c == '\'') || (c == '(') ||
            (c == ')') || (c == '/')) {
            *dest++ = c;
        }
        else if (*src == ' ') {
            *dest++ = '+';
        }
        else {
            *dest++ = '%';
            *dest++ = hex[c >> 4];
            *dest++ = hex[c & 15];
        }
        src++;
    }

    *dest = 0;

    return 1;
}


int64_t parseIso8601Time(const char *str)
{
    struct tm tm;
    time_t unixtime;
    strptime(str, "%a, %d %b %Y %H:%M:%S %z", &tm);
    unixtime = mktime(&tm);
    
    return unixtime;
    
    // Check to make sure that it has a valid format
    if (!checkString(str, "dddd-dd-ddTdd:dd:dd")) {
        return -1;
    }

#define nextnum() (((*str - '0') * 10) + (*(str + 1) - '0'))

    // Convert it
    struct tm stm;
    memset(&stm, 0, sizeof(stm));

    stm.tm_year = (nextnum() - 19) * 100;
    str += 2;
    stm.tm_year += nextnum();
    str += 3;

    stm.tm_mon = nextnum() - 1;
    str += 3;

    stm.tm_mday = nextnum();
    str += 3;

    stm.tm_hour = nextnum();
    str += 3;

    stm.tm_min = nextnum();
    str += 3;

    stm.tm_sec = nextnum();
    str += 2;

    stm.tm_isdst = -1;
    
    int64_t ret = mktime(&stm);

    // Skip the millis

    if (*str == '.') {
        str++;
        while (isdigit(*str)) {
            str++;
        }
    }
    
    if (checkString(str, "-dd:dd") || checkString(str, "+dd:dd")) {
        int sign = (*str++ == '-') ? -1 : 1;
        int hours = nextnum();
        str += 3;
        int minutes = nextnum();
        ret += (-sign * (((hours * 60) + minutes) * 60));
    }
    // Else it should be Z to be a conformant time string, but we just assume
    // that it is rather than enforcing that

    return ret;
}


uint64_t parseUnsignedInt(const char *str)
{
    // Skip whitespace
    while (is_blank(*str)) {
        str++;
    }

    uint64_t ret = 0;

    while (isdigit(*str)) {
        ret *= 10;
        ret += (*str++ - '0');
    }

    return ret;
}


int base64Encode(const unsigned char *in, int inLen, char *out)
{
    static const char *ENC = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    char *original_out = out;

    while (inLen) {
        // first 6 bits of char 1
        *out++ = ENC[*in >> 2];
        if (!--inLen) {
            // last 2 bits of char 1, 4 bits of 0
            *out++ = ENC[(*in & 0x3) << 4];
            *out++ = '=';
            *out++ = '=';
            break;
        }
        // last 2 bits of char 1, first 4 bits of char 2
        *out++ = ENC[((*in & 0x3) << 4) | (*(in + 1) >> 4)];
        in++;
        if (!--inLen) {
            // last 4 bits of char 2, 2 bits of 0
            *out++ = ENC[(*in & 0xF) << 2];
            *out++ = '=';
            break;
        }
        // last 4 bits of char 2, first 2 bits of char 3
        *out++ = ENC[((*in & 0xF) << 2) | (*(in + 1) >> 6)];
        in++;
        // last 6 bits of char 3
        *out++ = ENC[*in & 0x3F];
        in++, inLen--;
    }

    return (out - original_out);
}


#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

#define blk0L(i) (block->l[i] = (rol(block->l[i], 24) & 0xFF00FF00)     \
                  | (rol(block->l[i], 8) & 0x00FF00FF))

#define blk0B(i) (block->l[i])

#define blk(i) (block->l[i & 15] = rol(block->l[(i + 13) & 15] ^        \
                                       block->l[(i + 8) & 15] ^         \
                                       block->l[(i + 2) & 15] ^         \
                                       block->l[i & 15], 1))

#define R0_L(v, w, x, y, z, i)                                          \
    z += ((w & (x ^ y)) ^ y) + blk0L(i) + 0x5A827999 + rol(v, 5);       \
    w = rol(w, 30);
#define R0_B(v, w, x, y, z, i)                                          \
    z += ((w & (x ^ y)) ^ y) + blk0B(i) + 0x5A827999 + rol(v, 5);       \
    w = rol(w, 30);
#define R1(v, w, x, y, z, i)                                            \
    z += ((w & (x ^ y)) ^ y) + blk(i) + 0x5A827999 + rol(v, 5);         \
    w = rol(w, 30);
#define R2(v, w, x, y, z, i)                                            \
    z += (w ^ x ^ y) + blk(i) + 0x6ED9EBA1 + rol(v, 5);                 \
    w = rol(w, 30);
#define R3(v, w, x, y, z, i)                                            \
    z += (((w | x) & y) | (w & x)) + blk(i) + 0x8F1BBCDC + rol(v, 5);   \
    w = rol(w, 30);
#define R4(v, w, x, y, z, i)                                            \
    z += (w ^ x ^ y) + blk(i) + 0xCA62C1D6 + rol(v, 5);                 \
    w = rol(w, 30);

#define R0A_L(i) R0_L(a, b, c, d, e, i)
#define R0B_L(i) R0_L(b, c, d, e, a, i)
#define R0C_L(i) R0_L(c, d, e, a, b, i)
#define R0D_L(i) R0_L(d, e, a, b, c, i)
#define R0E_L(i) R0_L(e, a, b, c, d, i)

#define R0A_B(i) R0_B(a, b, c, d, e, i)
#define R0B_B(i) R0_B(b, c, d, e, a, i)
#define R0C_B(i) R0_B(c, d, e, a, b, i)
#define R0D_B(i) R0_B(d, e, a, b, c, i)
#define R0E_B(i) R0_B(e, a, b, c, d, i)

#define R1A(i) R1(a, b, c, d, e, i)
#define R1B(i) R1(b, c, d, e, a, i)
#define R1C(i) R1(c, d, e, a, b, i)
#define R1D(i) R1(d, e, a, b, c, i)
#define R1E(i) R1(e, a, b, c, d, i)

#define R2A(i) R2(a, b, c, d, e, i)
#define R2B(i) R2(b, c, d, e, a, i)
#define R2C(i) R2(c, d, e, a, b, i)
#define R2D(i) R2(d, e, a, b, c, i)
#define R2E(i) R2(e, a, b, c, d, i)

#define R3A(i) R3(a, b, c, d, e, i)
#define R3B(i) R3(b, c, d, e, a, i)
#define R3C(i) R3(c, d, e, a, b, i)
#define R3D(i) R3(d, e, a, b, c, i)
#define R3E(i) R3(e, a, b, c, d, i)

#define R4A(i) R4(a, b, c, d, e, i)
#define R4B(i) R4(b, c, d, e, a, i)
#define R4C(i) R4(c, d, e, a, b, i)
#define R4D(i) R4(d, e, a, b, c, i)
#define R4E(i) R4(e, a, b, c, d, i)


static void SHA1_transform(uint32_t state[5], const unsigned char buffer[64])
{
    uint32_t a, b, c, d, e;

    typedef union {
        unsigned char c[64];
        uint32_t l[16];
    } u;

    unsigned char w[64];
    u *block = (u *) w;

    memcpy(block, buffer, 64);

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];

    static uint32_t endianness_indicator = 0x1;
    if (((unsigned char *) &endianness_indicator)[0]) {
        R0A_L( 0);
        R0E_L( 1); R0D_L( 2); R0C_L( 3); R0B_L( 4); R0A_L( 5);
        R0E_L( 6); R0D_L( 7); R0C_L( 8); R0B_L( 9); R0A_L(10);
        R0E_L(11); R0D_L(12); R0C_L(13); R0B_L(14); R0A_L(15);
    }
    else {
        R0A_B( 0);
        R0E_B( 1); R0D_B( 2); R0C_B( 3); R0B_B( 4); R0A_B( 5);
        R0E_B( 6); R0D_B( 7); R0C_B( 8); R0B_B( 9); R0A_B(10);
        R0E_B(11); R0D_B(12); R0C_B(13); R0B_B(14); R0A_B(15);
    }
    R1E(16); R1D(17); R1C(18); R1B(19); R2A(20);
    R2E(21); R2D(22); R2C(23); R2B(24); R2A(25);
    R2E(26); R2D(27); R2C(28); R2B(29); R2A(30);
    R2E(31); R2D(32); R2C(33); R2B(34); R2A(35);
    R2E(36); R2D(37); R2C(38); R2B(39); R3A(40);
    R3E(41); R3D(42); R3C(43); R3B(44); R3A(45);
    R3E(46); R3D(47); R3C(48); R3B(49); R3A(50);
    R3E(51); R3D(52); R3C(53); R3B(54); R3A(55);
    R3E(56); R3D(57); R3C(58); R3B(59); R4A(60);
    R4E(61); R4D(62); R4C(63); R4B(64); R4A(65);
    R4E(66); R4D(67); R4C(68); R4B(69); R4A(70);
    R4E(71); R4D(72); R4C(73); R4B(74); R4A(75);
    R4E(76); R4D(77); R4C(78); R4B(79);

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}


typedef struct
{
    uint32_t state[5];
    uint32_t count[2];
    unsigned char buffer[64];
} SHA1Context;


static void SHA1_init(SHA1Context *context)
{
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
    context->count[0] = context->count[1] = 0;
}


static void SHA1_update(SHA1Context *context, const unsigned char *data,
                        unsigned int len)
{
    uint32_t i, j;

    j = (context->count[0] >> 3) & 63;

    if ((context->count[0] += len << 3) < (len << 3)) {
        context->count[1]++;
    }

    context->count[1] += (len >> 29);

    if ((j + len) > 63) {
        memcpy(&(context->buffer[j]), data, (i = 64 - j));
        SHA1_transform(context->state, context->buffer);
        for ( ; (i + 63) < len; i += 64) {
            SHA1_transform(context->state, &(data[i]));
        }
        j = 0;
    }
    else {
        i = 0;
    }

    memcpy(&(context->buffer[j]), &(data[i]), len - i);
}


static void SHA1_final(unsigned char digest[20], SHA1Context *context)
{
    uint32_t i;
    unsigned char finalcount[8];

    for (i = 0; i < 8; i++) {
        finalcount[i] = (unsigned char)
            ((context->count[(i >= 4 ? 0 : 1)] >>
              ((3 - (i & 3)) * 8)) & 255);
    }

    SHA1_update(context, (unsigned char *) "\200", 1);

    while ((context->count[0] & 504) != 448) {
        SHA1_update(context, (unsigned char *) "\0", 1);
    }

    SHA1_update(context, finalcount, 8);

    for (i = 0; i < 20; i++) {
        digest[i] = (unsigned char)
            ((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
    }

    memset(context->buffer, 0, 64);
    memset(context->state, 0, 20);
    memset(context->count, 0, 8);
    memset(&finalcount, 0, 8);

    SHA1_transform(context->state, context->buffer);
}


// HMAC-SHA-1:
//
// K - is key padded with zeros to 512 bits
// m - is message
// OPAD - 0x5c5c5c...
// IPAD - 0x363636...
//
// HMAC(K,m) = SHA1((K ^ OPAD) . SHA1((K ^ IPAD) . m))
void HMAC_SHA1(unsigned char hmac[20], const unsigned char *key, int key_len,
               const unsigned char *message, int message_len)
{
    unsigned char kopad[64], kipad[64];
    int i;
    
    if (key_len > 64) {
        key_len = 64;
    }

    for (i = 0; i < key_len; i++) {
        kopad[i] = key[i] ^ 0x5c;
        kipad[i] = key[i] ^ 0x36;
    }

    for ( ; i < 64; i++) {
        kopad[i] = 0 ^ 0x5c;
        kipad[i] = 0 ^ 0x36;
    }

    unsigned char digest[20];

    SHA1Context context;
    
    SHA1_init(&context);
    SHA1_update(&context, kipad, 64);
    SHA1_update(&context, message, message_len);
    SHA1_final(digest, &context);

    SHA1_init(&context);
    SHA1_update(&context, kopad, 64);
    SHA1_update(&context, digest, 20);
    SHA1_final(hmac, &context);
}

#define rot(x,k) (((x) << (k)) | ((x) >> (32 - (k))))

uint64_t hash(const unsigned char *k, int length)
{
    uint32_t a, b, c;

    a = b = c = 0xdeadbeef + ((uint32_t) length);

    static uint32_t endianness_indicator = 0x1;
    if (((unsigned char *) &endianness_indicator)[0]) {
        while (length > 12) {
            a += k[0];
            a += ((uint32_t) k[1]) << 8;
            a += ((uint32_t) k[2]) << 16;
            a += ((uint32_t) k[3]) << 24;
            b += k[4];
            b += ((uint32_t) k[5]) << 8;
            b += ((uint32_t) k[6]) << 16;
            b += ((uint32_t) k[7]) << 24;
            c += k[8];
            c += ((uint32_t) k[9]) << 8;
            c += ((uint32_t) k[10]) << 16;
            c += ((uint32_t) k[11]) << 24;
            a -= c; a ^= rot(c, 4);  c += b;
            b -= a; b ^= rot(a, 6);  a += c;
            c -= b; c ^= rot(b, 8);  b += a;
            a -= c; a ^= rot(c, 16);  c += b;
            b -= a; b ^= rot(a, 19);  a += c;
            c -= b; c ^= rot(b, 4);  b += a;
            length -= 12;
            k += 12;
        }
        
        switch(length) {
        case 12: c += ((uint32_t) k[11]) << 24;
        case 11: c += ((uint32_t) k[10]) << 16;
        case 10: c += ((uint32_t) k[9]) << 8;
        case 9 : c += k[8];
        case 8 : b += ((uint32_t) k[7]) << 24;
        case 7 : b += ((uint32_t) k[6]) << 16;
        case 6 : b += ((uint32_t) k[5]) << 8;
        case 5 : b += k[4];
        case 4 : a += ((uint32_t) k[3]) << 24;
        case 3 : a += ((uint32_t) k[2]) << 16;
        case 2 : a += ((uint32_t) k[1]) << 8;
        case 1 : a += k[0]; break;
        case 0 : goto end;
        }
    }
    else {
        while (length > 12) {
            a += ((uint32_t) k[0]) << 24;
            a += ((uint32_t) k[1]) << 16;
            a += ((uint32_t) k[2]) << 8;
            a += ((uint32_t) k[3]);
            b += ((uint32_t) k[4]) << 24;
            b += ((uint32_t) k[5]) << 16;
            b += ((uint32_t) k[6]) << 8;
            b += ((uint32_t) k[7]);
            c += ((uint32_t) k[8]) << 24;
            c += ((uint32_t) k[9]) << 16;
            c += ((uint32_t) k[10]) << 8;
            c += ((uint32_t) k[11]);
            a -= c; a ^= rot(c, 4);  c += b;
            b -= a; b ^= rot(a, 6);  a += c;
            c -= b; c ^= rot(b, 8);  b += a;
            a -= c; a ^= rot(c, 16);  c += b;
            b -= a; b ^= rot(a, 19);  a += c;
            c -= b; c ^= rot(b, 4);  b += a;
            length -= 12;
            k += 12;
        }

        switch(length) {
        case 12: c += k[11];
        case 11: c += ((uint32_t) k[10]) << 8;
        case 10: c += ((uint32_t) k[9]) << 16;
        case 9 : c += ((uint32_t) k[8]) << 24;
        case 8 : b += k[7];
        case 7 : b += ((uint32_t) k[6]) << 8;
        case 6 : b += ((uint32_t) k[5]) << 16;
        case 5 : b += ((uint32_t) k[4]) << 24;
        case 4 : a += k[3];
        case 3 : a += ((uint32_t) k[2]) << 8;
        case 2 : a += ((uint32_t) k[1]) << 16;
        case 1 : a += ((uint32_t) k[0]) << 24; break;
        case 0 : goto end;
        }
    }
    
    c ^= b; c -= rot(b, 14);
    a ^= c; a -= rot(c, 11);
    b ^= a; b -= rot(a, 25);
    c ^= b; c -= rot(b, 16);
    a ^= c; a -= rot(c, 4);
    b ^= a; b -= rot(a, 14);
    c ^= b; c -= rot(b, 24);

 end:
    return ((((uint64_t) c) << 32) | b);
}

int is_blank(char c)
{
    return ((c == ' ') || (c == '\t'));
}



#ifdef __MINGW32__

int conv_num(const char **buf, int *dest, int llim, int ulim)
{
    int result = 0;
    
    /* The limit also determines the number of valid digits. */
    int rulim = ulim;
    
    if (**buf < '0' || **buf > '9')
        return (0);
    
    do {
        result *= 10;
        result += *(*buf)++ - '0';
        rulim /= 10;
    } while ((result * 10 <= ulim) && rulim && **buf >= '0' && **buf <= '9');
    
    if (result < llim || result > ulim)
        return (0);
    
    *dest = result;
    return (1);
}


int strncasecmp(char *s1, char *s2, size_t n)
{
    if (n == 0)
        return 0;
    
    while (n-- != 0 && tolower(*s1) == tolower(*s2))
    {
        if (n == 0 || *s1 == '\0' || *s2 == '\0')
            break;
        s1++;
        s2++;
    }
    
    return tolower(*(unsigned char *) s1) - tolower(*(unsigned char *) s2);
}

char * strptime(const char *buf, const char *fmt, struct tm *tm)
{
    char c;
    const char *bp;
    size_t len = 0;
    int alt_format, i, split_year = 0;
    
    bp = buf;
    
    while ((c = *fmt) != '\0')
    {
        /* Clear `alternate' modifier prior to new conversion. */
        alt_format = 0;
        
        /* Eat up white-space. */
        if (isspace(c))
        {
            while (isspace(*bp))
                bp++;
            
            fmt++;
            continue;
        }
        
        if ((c = *fmt++) != '%')
            goto literal;
        
        
    again:   switch (c = *fmt++)
        {
            case '%': /* "%%" is converted to "%". */
            literal:
                if (c != *bp++)
                    return (0);
                break;
                
                /*
                 * "Alternative" modifiers. Just set the appropriate flag
                 * and start over again.
                 */
            case 'E': /* "%E?" alternative conversion modifier. */
                LEGAL_ALT(0);
                alt_format |= ALT_E;
                goto again;
                
            case 'O': /* "%O?" alternative conversion modifier. */
                LEGAL_ALT(0);
                alt_format |= ALT_O;
                goto again;
                
                /*
                 * "Complex" conversion rules, implemented through recursion.
                 */
            case 'c': /* Date and time, using the locale's format. */
                LEGAL_ALT(ALT_E);
                if (!(bp = strptime(bp, "%x %X", tm)))
                    return (0);
                break;
                
            case 'D': /* The date as "%m/%d/%y". */
                LEGAL_ALT(0);
                if (!(bp = strptime(bp, "%m/%d/%y", tm)))
                    return (0);
                break;
                
            case 'R': /* The time as "%H:%M". */
                LEGAL_ALT(0);
                if (!(bp = strptime(bp, "%H:%M", tm)))
                    return (0);
                break;
                
            case 'r': /* The time in 12-hour clock representation. */
                LEGAL_ALT(0);
                if (!(bp = strptime(bp, "%I:%M:%S %p", tm)))
                    return (0);
                break;
                
            case 'T': /* The time as "%H:%M:%S". */
                LEGAL_ALT(0);
                if (!(bp = strptime(bp, "%H:%M:%S", tm)))
                    return (0);
                break;
                
            case 'X': /* The time, using the locale's format. */
                LEGAL_ALT(ALT_E);
                if (!(bp = strptime(bp, "%H:%M:%S", tm)))
                    return (0);
                break;
                
            case 'x': /* The date, using the locale's format. */
                LEGAL_ALT(ALT_E);
                if (!(bp = strptime(bp, "%m/%d/%y", tm)))
                    return (0);
                break;
                
                /*
                 * "Elementary" conversion rules.
                 */
            case 'A': /* The day of week, using the locale's form. */
            case 'a':
                LEGAL_ALT(0);
                for (i = 0; i < 7; i++)
                {
                    /* Full name. */
                    len = strlen(day[i]);
                    if (strncasecmp((char *)(day[i]), (char *)bp, len) == 0)
                        break;
                    
                    /* Abbreviated name. */
                    len = strlen(abday[i]);
                    if (strncasecmp((char *)(abday[i]), (char *)bp, len) == 0)
                        break;
                }
                
                /* Nothing matched. */
                if (i == 7)
                    return (0);
                
                tm->tm_wday = i;
                bp += len;
                break;
                
            case 'B': /* The month, using the locale's form. */
            case 'b':
            case 'h':
                LEGAL_ALT(0);
                for (i = 0; i < 12; i++)
                {
                    /* Full name. */
                    
                    len = strlen(mon[i]);
                    if (strncasecmp((char *)(mon[i]), (char *)bp, len) == 0)
                        break;
                    
                    /* Abbreviated name. */
                    len = strlen(abmon[i]);
                    if (strncasecmp((char *)(abmon[i]),(char *) bp, len) == 0)
                        break;
                }
                
                /* Nothing matched. */
                if (i == 12)
                    return (0);
                
                tm->tm_mon = i;
                bp += len;
                break;
                
            case 'C': /* The century number. */
                LEGAL_ALT(ALT_E);
                if (!(conv_num(&bp, &i, 0, 99)))
                    return (0);
                
                if (split_year)
                {
                    tm->tm_year = (tm->tm_year % 100) + (i * 100);
                } else {
                    tm->tm_year = i * 100;
                    split_year = 1;
                }
                break;
                
            case 'd': /* The day of month. */
            case 'e':
                LEGAL_ALT(ALT_O);
                if (!(conv_num(&bp, &tm->tm_mday, 1, 31)))
                    return (0);
                break;
                
            case 'k': /* The hour (24-hour clock representation). */
                LEGAL_ALT(0);
                /* FALLTHROUGH */
            case 'H':
                LEGAL_ALT(ALT_O);
                if (!(conv_num(&bp, &tm->tm_hour, 0, 23)))
                    return (0);
                break;
                
            case 'l': /* The hour (12-hour clock representation). */
                LEGAL_ALT(0);
                /* FALLTHROUGH */
            case 'I':
                LEGAL_ALT(ALT_O);
                if (!(conv_num(&bp, &tm->tm_hour, 1, 12)))
                    return (0);
                if (tm->tm_hour == 12)
                    tm->tm_hour = 0;
                break;
                
            case 'j': /* The day of year. */
                LEGAL_ALT(0);
                if (!(conv_num(&bp, &i, 1, 366)))
                    return (0);
                tm->tm_yday = i - 1;
                break;
                
            case 'M': /* The minute. */
                LEGAL_ALT(ALT_O);
                if (!(conv_num(&bp, &tm->tm_min, 0, 59)))
                    return (0);
                break;
                
            case 'm': /* The month. */
                LEGAL_ALT(ALT_O);
                if (!(conv_num(&bp, &i, 1, 12)))
                    return (0);
                tm->tm_mon = i - 1;
                break;
                
            case 'S': /* The seconds. */
                LEGAL_ALT(ALT_O);
                if (!(conv_num(&bp, &tm->tm_sec, 0, 61)))
                    return (0);
                break;
                
            case 'U': /* The week of year, beginning on sunday. */
            case 'W': /* The week of year, beginning on monday. */
                LEGAL_ALT(ALT_O);
                /*
                 * XXX This is bogus, as we can not assume any valid
                 * information present in the tm structure at this
                 * point to calculate a real value, so just check the
                 * range for now.
                 */
                if (!(conv_num(&bp, &i, 0, 53)))
                    return (0);
                break;
                
            case 'w': /* The day of week, beginning on sunday. */
                LEGAL_ALT(ALT_O);
                if (!(conv_num(&bp, &tm->tm_wday, 0, 6)))
                    return (0);
                break;
                
            case 'Y': /* The year. */
                LEGAL_ALT(ALT_E);
                if (!(conv_num(&bp, &i, 0, 9999)))
                    return (0);
                
                tm->tm_year = i - TM_YEAR_BASE;
                break;
                
            case 'y': /* The year within 100 years of the epoch. */
                LEGAL_ALT(ALT_E | ALT_O);
                if (!(conv_num(&bp, &i, 0, 99)))
                    return (0);
                
                if (split_year)
                {
                    tm->tm_year = ((tm->tm_year / 100) * 100) + i;
                    break;
                }
                split_year = 1;
                if (i <= 68)
                    tm->tm_year = i + 2000 - TM_YEAR_BASE;
                else
                    tm->tm_year = i + 1900 - TM_YEAR_BASE;
                break;
                
                /*
                 * Miscellaneous conversions.
                 */
            case 'n': /* Any kind of white-space. */
            case 't':
                LEGAL_ALT(0);
                while (isspace(*bp))
                    bp++;
                break;
                
                
            default: /* Unknown/unsupported conversion. */
                return (0);
        }
        
        
    }
    
    /* LINTED functional specification */
    return ((char *)bp);
}

#endif
