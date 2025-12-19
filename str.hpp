#ifndef STR_H
#define STR_H

#include <intrin.h>

#ifdef _MSC_VER
#define strinline __forceinline
#define strnoinline __declspec(noinline)
#else
#define strinline __attribute__((always_inline)) inline
#define strnoinline __attribute__((noinline))
#endif

namespace str {

    using u8 = unsigned char;
    using u16 = unsigned short;
    using u32 = unsigned int;
    using u64 = unsigned long long;

    namespace detail {

        constexpr u64 seedhash(const char* s, u64 h = 0x1505ull) {
            while (*s) { h ^= static_cast<u64>(static_cast<u8>(*s++)); h *= 0x100000001b3ull; h ^= h >> 31; }
            return h;
        }

        constexpr u64 seed = seedhash(__TIME__) ^ seedhash(__DATE__) ^ seedhash(__FILE__) ^ __LINE__ * 0x9e3779b97f4a7c15ull ^ 0xdeadbeefcafebabeull;
        constexpr u64 key1 = seed ^ (seed >> 17) ^ 0xa5a5a5a5a5a5a5a5ull;
        constexpr u64 key2 = (seed << 13) ^ (seed >> 29) ^ 0x5a5a5a5a5a5a5a5aull;
        constexpr u64 key3 = (seed >> 7) ^ (seed << 41) ^ 0x1234567890abcdefull;
        constexpr u64 key4 = (seed << 23) ^ (seed >> 11) ^ 0xfedcba0987654321ull;
        constexpr u64 key5 = (seed ^ key1 ^ key2) * 0x517cc1b727220a95ull;

        template<u64 s, int n> struct rng {
            static constexpr u64 x = s ^ (s << 13), y = x ^ (x >> 7), z = y ^ (y << 17), w = z ^ (z >> 31);
            static constexpr u64 value = rng<w, n - 1>::value;
        };
        template<u64 s> struct rng<s, 0> { static constexpr u64 value = s; };

        template<int ctr> struct keygen {
            static constexpr u64 base = seed ^ static_cast<u64>(ctr * 0x517cc1b727220a95ull) ^ key1;
            static constexpr u64 value = rng<base, ((ctr ^ 0x55) % 7) + 4>::value;
            static constexpr u64 value2 = rng<value ^ key2, ((ctr ^ 0xaa) % 5) + 3>::value;
            static constexpr u64 value3 = rng<value2 ^ key3, ((ctr ^ 0x33) % 6) + 2>::value;
        };

        template<u64 k1, u64 k2, u64 k3, u64 i>
        strinline constexpr u8 enc(u8 c) {
            u8 a = static_cast<u8>(k1 >> ((i % 8) * 8)), b = static_cast<u8>(k2 >> (((i + 3) % 8) * 8)), d = static_cast<u8>(k3 >> (((i + 5) % 8) * 8));
            u8 e = static_cast<u8>((k1 >> 32) + i), f = static_cast<u8>((k2 >> 40) ^ (i * 7)), g = static_cast<u8>((k3 >> 48) + (i * 3));
            u8 s1 = c ^ a, s2 = s1 + e, s3 = ((s2 << 3) | (s2 >> 5)) ^ b, s4 = s3 - f, s5 = ((s4 << 5) | (s4 >> 3)) ^ d, s6 = s5 + g;
            return s6 ^ static_cast<u8>(i * 0x9e);
        }

        strinline void burn(void* p, u64 len) {
#ifdef _WIN32
            SecureZeroMemory(p, static_cast<size_t>(len));
#else
            volatile u8* ptr = static_cast<volatile u8*>(p);
            for (volatile u64 i = 0; i < len; i++) ptr[i] = 0;
            __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
        }

        strinline bool ctcmp32(u32 a, u32 b) {
            volatile u32 x = a ^ b, y = x; y |= y >> 16; y |= y >> 8; y |= y >> 4; y |= y >> 2; y |= y >> 1; return (y & 1) == 0;
        }

        strinline bool ctcmp64(u64 a, u64 b) {
            volatile u64 x = a ^ b, y = x; y |= y >> 32; y |= y >> 16; y |= y >> 8; y |= y >> 4; y |= y >> 2; y |= y >> 1; return (y & 1) == 0;
        }

        constexpr u64 siphash64(const char* s, u64 hk1, u64 hk2) {
            u64 v0 = 0x736f6d6570736575ull ^ hk1, v1 = 0x646f72616e646f6dull ^ hk2, v2 = 0x6c7967656e657261ull ^ hk1, v3 = 0x7465646279746573ull ^ hk2;
            u64 len = 0; const char* p = s; while (*p++) len++;
            u64 b = len << 56; const char* end = s + (len & ~7ull);
            while (s < end) {
                u64 m = 0; for (int i = 0; i < 8; i++) m |= static_cast<u64>(static_cast<u8>(s[i])) << (i * 8);
                v3 ^= m;
                for (int r = 0; r < 2; r++) { v0 += v1; v1 = (v1 << 13) | (v1 >> 51); v1 ^= v0; v0 = (v0 << 32) | (v0 >> 32); v2 += v3; v3 = (v3 << 16) | (v3 >> 48); v3 ^= v2; v0 += v3; v3 = (v3 << 21) | (v3 >> 43); v3 ^= v0; v2 += v1; v1 = (v1 << 17) | (v1 >> 47); v1 ^= v2; v2 = (v2 << 32) | (v2 >> 32); }
                v0 ^= m; s += 8;
            }
            for (int i = 0; i < static_cast<int>(len & 7); i++) b |= static_cast<u64>(static_cast<u8>(s[i])) << (i * 8);
            v3 ^= b;
            for (int r = 0; r < 2; r++) { v0 += v1; v1 = (v1 << 13) | (v1 >> 51); v1 ^= v0; v0 = (v0 << 32) | (v0 >> 32); v2 += v3; v3 = (v3 << 16) | (v3 >> 48); v3 ^= v2; v0 += v3; v3 = (v3 << 21) | (v3 >> 43); v3 ^= v0; v2 += v1; v1 = (v1 << 17) | (v1 >> 47); v1 ^= v2; v2 = (v2 << 32) | (v2 >> 32); }
            v0 ^= b; v2 ^= 0xff;
            for (int r = 0; r < 4; r++) { v0 += v1; v1 = (v1 << 13) | (v1 >> 51); v1 ^= v0; v0 = (v0 << 32) | (v0 >> 32); v2 += v3; v3 = (v3 << 16) | (v3 >> 48); v3 ^= v2; v0 += v3; v3 = (v3 << 21) | (v3 >> 43); v3 ^= v0; v2 += v1; v1 = (v1 << 17) | (v1 >> 47); v1 ^= v2; v2 = (v2 << 32) | (v2 >> 32); }
            return v0 ^ v1 ^ v2 ^ v3;
        }

        strinline u64 siphash64rt(const char* s, u64 hk1, u64 hk2) {
            u64 v0 = 0x736f6d6570736575ull ^ hk1, v1 = 0x646f72616e646f6dull ^ hk2, v2 = 0x6c7967656e657261ull ^ hk1, v3 = 0x7465646279746573ull ^ hk2;
            u64 len = 0; const char* p = s; while (*p++) len++;
            u64 b = len << 56; const char* end = s + (len & ~7ull);
            while (s < end) {
                u64 m = 0; for (int i = 0; i < 8; i++) m |= static_cast<u64>(static_cast<u8>(s[i])) << (i * 8);
                v3 ^= m;
                for (int r = 0; r < 2; r++) { v0 += v1; v1 = (v1 << 13) | (v1 >> 51); v1 ^= v0; v0 = (v0 << 32) | (v0 >> 32); v2 += v3; v3 = (v3 << 16) | (v3 >> 48); v3 ^= v2; v0 += v3; v3 = (v3 << 21) | (v3 >> 43); v3 ^= v0; v2 += v1; v1 = (v1 << 17) | (v1 >> 47); v1 ^= v2; v2 = (v2 << 32) | (v2 >> 32); }
                v0 ^= m; s += 8;
            }
            for (int i = 0; i < static_cast<int>(len & 7); i++) b |= static_cast<u64>(static_cast<u8>(s[i])) << (i * 8);
            v3 ^= b;
            for (int r = 0; r < 2; r++) { v0 += v1; v1 = (v1 << 13) | (v1 >> 51); v1 ^= v0; v0 = (v0 << 32) | (v0 >> 32); v2 += v3; v3 = (v3 << 16) | (v3 >> 48); v3 ^= v2; v0 += v3; v3 = (v3 << 21) | (v3 >> 43); v3 ^= v0; v2 += v1; v1 = (v1 << 17) | (v1 >> 47); v1 ^= v2; v2 = (v2 << 32) | (v2 >> 32); }
            v0 ^= b; v2 ^= 0xff;
            for (int r = 0; r < 4; r++) { v0 += v1; v1 = (v1 << 13) | (v1 >> 51); v1 ^= v0; v0 = (v0 << 32) | (v0 >> 32); v2 += v3; v3 = (v3 << 16) | (v3 >> 48); v3 ^= v2; v0 += v3; v3 = (v3 << 21) | (v3 >> 43); v3 ^= v0; v2 += v1; v1 = (v1 << 17) | (v1 >> 47); v1 ^= v2; v2 = (v2 << 32) | (v2 >> 32); }
            return v0 ^ v1 ^ v2 ^ v3;
        }

        constexpr u64 siphash64w(const wchar_t* s, u64 hk1, u64 hk2) {
            u64 v0 = 0x736f6d6570736575ull ^ hk1, v1 = 0x646f72616e646f6dull ^ hk2, v2 = 0x6c7967656e657261ull ^ hk1, v3 = 0x7465646279746573ull ^ hk2;
            u64 len = 0; const wchar_t* p = s; while (*p++) len++; len *= 2;
            u64 b = len << 56; const wchar_t* wp = s; u64 processed = 0;
            while (processed + 8 <= len) {
                u64 m = 0; for (int i = 0; i < 4; i++) { u16 wc = static_cast<u16>(wp[i]); m |= static_cast<u64>(wc & 0xff) << (i * 16); m |= static_cast<u64>((wc >> 8) & 0xff) << (i * 16 + 8); }
                v3 ^= m;
                for (int r = 0; r < 2; r++) { v0 += v1; v1 = (v1 << 13) | (v1 >> 51); v1 ^= v0; v0 = (v0 << 32) | (v0 >> 32); v2 += v3; v3 = (v3 << 16) | (v3 >> 48); v3 ^= v2; v0 += v3; v3 = (v3 << 21) | (v3 >> 43); v3 ^= v0; v2 += v1; v1 = (v1 << 17) | (v1 >> 47); v1 ^= v2; v2 = (v2 << 32) | (v2 >> 32); }
                v0 ^= m; wp += 4; processed += 8;
            }
            for (u64 i = 0; i < len - processed; i++) { u64 widx = i / 2; u8 byte = (i % 2 == 0) ? static_cast<u8>(wp[widx] & 0xff) : static_cast<u8>((wp[widx] >> 8) & 0xff); b |= static_cast<u64>(byte) << (i * 8); }
            v3 ^= b;
            for (int r = 0; r < 2; r++) { v0 += v1; v1 = (v1 << 13) | (v1 >> 51); v1 ^= v0; v0 = (v0 << 32) | (v0 >> 32); v2 += v3; v3 = (v3 << 16) | (v3 >> 48); v3 ^= v2; v0 += v3; v3 = (v3 << 21) | (v3 >> 43); v3 ^= v0; v2 += v1; v1 = (v1 << 17) | (v1 >> 47); v1 ^= v2; v2 = (v2 << 32) | (v2 >> 32); }
            v0 ^= b; v2 ^= 0xff;
            for (int r = 0; r < 4; r++) { v0 += v1; v1 = (v1 << 13) | (v1 >> 51); v1 ^= v0; v0 = (v0 << 32) | (v0 >> 32); v2 += v3; v3 = (v3 << 16) | (v3 >> 48); v3 ^= v2; v0 += v3; v3 = (v3 << 21) | (v3 >> 43); v3 ^= v0; v2 += v1; v1 = (v1 << 17) | (v1 >> 47); v1 ^= v2; v2 = (v2 << 32) | (v2 >> 32); }
            return v0 ^ v1 ^ v2 ^ v3;
        }

        strinline u64 siphash64rtw(const wchar_t* s, u64 hk1, u64 hk2) {
            u64 v0 = 0x736f6d6570736575ull ^ hk1, v1 = 0x646f72616e646f6dull ^ hk2, v2 = 0x6c7967656e657261ull ^ hk1, v3 = 0x7465646279746573ull ^ hk2;
            u64 len = 0; const wchar_t* p = s; while (*p++) len++; len *= 2;
            u64 b = len << 56; const wchar_t* wp = s; u64 processed = 0;
            while (processed + 8 <= len) {
                u64 m = 0; for (int i = 0; i < 4; i++) { u16 wc = static_cast<u16>(wp[i]); m |= static_cast<u64>(wc & 0xff) << (i * 16); m |= static_cast<u64>((wc >> 8) & 0xff) << (i * 16 + 8); }
                v3 ^= m;
                for (int r = 0; r < 2; r++) { v0 += v1; v1 = (v1 << 13) | (v1 >> 51); v1 ^= v0; v0 = (v0 << 32) | (v0 >> 32); v2 += v3; v3 = (v3 << 16) | (v3 >> 48); v3 ^= v2; v0 += v3; v3 = (v3 << 21) | (v3 >> 43); v3 ^= v0; v2 += v1; v1 = (v1 << 17) | (v1 >> 47); v1 ^= v2; v2 = (v2 << 32) | (v2 >> 32); }
                v0 ^= m; wp += 4; processed += 8;
            }
            for (u64 i = 0; i < len - processed; i++) { u64 widx = i / 2; u8 byte = (i % 2 == 0) ? static_cast<u8>(wp[widx] & 0xff) : static_cast<u8>((wp[widx] >> 8) & 0xff); b |= static_cast<u64>(byte) << (i * 8); }
            v3 ^= b;
            for (int r = 0; r < 2; r++) { v0 += v1; v1 = (v1 << 13) | (v1 >> 51); v1 ^= v0; v0 = (v0 << 32) | (v0 >> 32); v2 += v3; v3 = (v3 << 16) | (v3 >> 48); v3 ^= v2; v0 += v3; v3 = (v3 << 21) | (v3 >> 43); v3 ^= v0; v2 += v1; v1 = (v1 << 17) | (v1 >> 47); v1 ^= v2; v2 = (v2 << 32) | (v2 >> 32); }
            v0 ^= b; v2 ^= 0xff;
            for (int r = 0; r < 4; r++) { v0 += v1; v1 = (v1 << 13) | (v1 >> 51); v1 ^= v0; v0 = (v0 << 32) | (v0 >> 32); v2 += v3; v3 = (v3 << 16) | (v3 >> 48); v3 ^= v2; v0 += v3; v3 = (v3 << 21) | (v3 >> 43); v3 ^= v0; v2 += v1; v1 = (v1 << 17) | (v1 >> 47); v1 ^= v2; v2 = (v2 << 32) | (v2 >> 32); }
            return v0 ^ v1 ^ v2 ^ v3;
        }

        template<u64 k1, u64 k2, u64 k3, u64 idx> struct encbyte { strinline static constexpr u8 get(u8 c) { return enc<k1, k2, k3, idx>(c); } };

        template<u64 k1, u64 k2, u64 k3> constexpr u32 calchash(const char* s, u64 sz) {
            u32 h = static_cast<u32>(k1 & 0xffffffff);
            for (u64 i = 0; i < sz; i++) { h ^= static_cast<u8>(s[i]); h *= 0x01000193; h ^= static_cast<u8>(k2 >> ((i % 8) * 8)); h = ((h << 5) | (h >> 27)) ^ static_cast<u8>(k3 >> (((i + 3) % 8) * 8)); }
            return h ^ static_cast<u32>(k2 >> 32) ^ static_cast<u32>(k3 >> 32);
        }

        template<u64 k1, u64 k2, u64 k3> constexpr u32 calchashw(const wchar_t* s, u64 sz) {
            u32 h = static_cast<u32>(k1 & 0xffffffff);
            for (u64 i = 0; i < sz; i++) {
                u64 widx = i / 2;
                u8 byte = (i % 2 == 0) ? static_cast<u8>(s[widx] & 0xff) : static_cast<u8>((s[widx] >> 8) & 0xff);
                h ^= byte; h *= 0x01000193; h ^= static_cast<u8>(k2 >> ((i % 8) * 8)); h = ((h << 5) | (h >> 27)) ^ static_cast<u8>(k3 >> (((i + 3) % 8) * 8));
            }
            return h ^ static_cast<u32>(k2 >> 32) ^ static_cast<u32>(k3 >> 32);
        }

#ifdef _MSC_VER
#pragma optimize("", off)
#pragma runtime_checks("", off)
#endif

        template<u64 k1, u64 k2, u64 k3, u64 sz, u32 hash, int var>
        strnoinline bool decode(const u8* src, u8* dst, volatile u32* status) {
            volatile u64 rx = __rdtsc(), ry = reinterpret_cast<u64>(&rx), rz = rx ^ ry ^ key4, rw = (rx << 32) | (ry >> 32);
            volatile u8 work[64], fake[64]; volatile u64 vi = 0, vj = 0; volatile u8 va, vb, vc, vd, ve; volatile u32 vh = static_cast<u32>(k1 & 0xffffffff);
            for (vj = 0; vj < 64; vj++) { work[vj] = static_cast<u8>(rz ^ vj ^ (rw >> (vj & 7))); fake[vj] = static_cast<u8>(rw ^ vj ^ (rz >> (vj & 7))); }
            vi = 0;
        l_entry: if (vi >= sz) goto l_verify; va = src[vi]; if ((rz & 0x3) == 0) goto l_fake1; if ((rx ^ ry) == vi) goto l_fake2; if (rw == 0) goto l_fake3;
        l_dec: {
            u8 a = static_cast<u8>(k1 >> ((vi % 8) * 8)), b = static_cast<u8>(k2 >> (((vi + 3) % 8) * 8)), d = static_cast<u8>(k3 >> (((vi + 5) % 8) * 8));
            u8 ee = static_cast<u8>((k1 >> 32) + vi), f = static_cast<u8>((k2 >> 40) ^ (vi * 7)), g = static_cast<u8>((k3 >> 48) + (vi * 3));
            u8 s7 = va ^ static_cast<u8>(vi * 0x9e), s6 = s7 - g, s5 = s6 ^ d, s4 = ((s5 >> 5) | (s5 << 3)), s3 = s4 + f, s2 = s3 ^ b, s1 = ((s2 >> 3) | (s2 << 5)), s0 = s1 - ee; vb = s0 ^ a;
        }
        vh ^= vb; vh *= 0x01000193; vh ^= static_cast<u8>(k2 >> ((vi % 8) * 8)); vh = ((vh << 5) | (vh >> 27)) ^ static_cast<u8>(k3 >> (((vi + 3) % 8) * 8));
        if ((rw & 0xf) > 1) goto l_store1; goto l_store2;
    l_store1: dst[vi] = vb; work[vi & 63] ^= vb; goto l_next;
    l_store2: work[(vi + 7) & 63] = vb; dst[vi] = vb; fake[vi & 63] ^= va; goto l_next;
    l_fake1: vc = (va ^ static_cast<u8>(k1 >> 40)) - static_cast<u8>(vi ^ k2); work[vi & 63] = vc; vd = ((va >> 2) | (va << 6)) ^ static_cast<u8>((k3 + vi) >> 8); fake[(vi + 5) & 63] ^= vd; if ((ry & 0x7) == 7) goto l_fake1b; goto l_dec;
    l_fake1b: ve = (va + static_cast<u8>(k2 >> 24)) ^ static_cast<u8>(vi * 3); work[(vi + 11) & 63] ^= ve; fake[(vi + 3) & 63] = vc ^ vd; goto l_dec;
    l_fake2: vd = va ^ static_cast<u8>(k1) ^ static_cast<u8>(vi); fake[(vi ^ 7) & 63] = vd; vc = ((va << 4) | (va >> 4)) ^ static_cast<u8>(k2 >> 16); work[(vi + 13) & 63] ^= vc; if ((rz & 0xf00) == 0) goto l_fake3; goto l_dec;
    l_fake3: vc = (va - static_cast<u8>(vi)) ^ static_cast<u8>(k3 >> 8); vd = (va + static_cast<u8>(k1 >> 56)) ^ static_cast<u8>(vi * 5); work[(vi + 17) & 63] = vc; fake[(vi + 23) & 63] ^= vd; if (ry > rx + 0x7000000000000000ull) goto l_fake1; goto l_dec;
    l_next: vi++; rx = (rx >> 1) | ((rx & 1) << 63); rz = rx ^ ry ^ (vi * key5); rw ^= rz; ry ^= vi; goto l_entry;
    l_verify: vh ^= static_cast<u32>(k2 >> 32) ^ static_cast<u32>(k3 >> 32); if (!ctcmp32(vh, hash)) goto l_tamper; *status = 1; va = 0; for (vj = 0; vj < 64; vj++) va ^= work[vj] ^ fake[vj]; (void)va; return true;
    l_tamper: burn(dst, sz); *status = 2; for (vj = 0; vj < 64; vj++) { work[vj] = 0; fake[vj] = 0; } return false;
        }

#ifdef _MSC_VER
#pragma runtime_checks("", restore)
#pragma optimize("", on)
#endif

        template<u64 k1, u64 k2, u64 k3, u64 sz, u32 hash, int var> class encrypted {
            alignas(16) u8 buf[sz];
        public:
            template<u64... idx> strinline constexpr encrypted(const char* s, std::integer_sequence<u64, idx...>) : buf{ encbyte<k1, k2, k3, idx>::get(static_cast<u8>(s[idx]))... } {}
            strinline const u8* data() const { return buf; }
            static constexpr u64 size() { return sz; } static constexpr u64 getk1() { return k1; } static constexpr u64 getk2() { return k2; } static constexpr u64 getk3() { return k3; } static constexpr u32 gethash() { return hash; } static constexpr int getvar() { return var; }
        };

        template<u64 k1, u64 k2, u64 k3, u64 sz, u32 hash, int var> class encryptedw {
            alignas(16) u8 buf[sz];
            template<u64 i> static constexpr u8 encwbyte(const wchar_t* s) { u64 idx = i / 2; u8 byte = (i % 2 == 0) ? static_cast<u8>(s[idx] & 0xff) : static_cast<u8>((s[idx] >> 8) & 0xff); return encbyte<k1, k2, k3, i>::get(byte); }
        public:
            template<u64... idx> strinline constexpr encryptedw(const wchar_t* s, std::integer_sequence<u64, idx...>) : buf{ encwbyte<idx>(s)... } {}
            strinline const u8* data() const { return buf; }
            static constexpr u64 size() { return sz; } static constexpr u64 getk1() { return k1; } static constexpr u64 getk2() { return k2; } static constexpr u64 getk3() { return k3; } static constexpr u32 gethash() { return hash; } static constexpr int getvar() { return var; }
        };

        template<u64 sz> class tempbuf {
            alignas(16) char buf[sz]; volatile u32 status;
        public:
            strinline tempbuf() : status(0) { for (u64 i = 0; i < sz; i++) buf[i] = 0; }
            strinline ~tempbuf() { burn(buf, sz); }
            strinline char* data() { return buf; } strinline const char* c_str() const { return buf; } strinline bool valid() const { return status == 1; } strinline volatile u32* statusptr() { return &status; }
            tempbuf(const tempbuf&) = delete; tempbuf& operator=(const tempbuf&) = delete; tempbuf(tempbuf&&) = delete; tempbuf& operator=(tempbuf&&) = delete;
        };

        template<u64 sz> class tempbufw {
            alignas(16) wchar_t buf[sz / sizeof(wchar_t)]; volatile u32 status;
        public:
            strinline tempbufw() : status(0) { for (u64 i = 0; i < sz / sizeof(wchar_t); i++) buf[i] = 0; }
            strinline ~tempbufw() { burn(buf, sz); }
            strinline wchar_t* data() { return buf; } strinline const wchar_t* c_str() const { return buf; } strinline bool valid() const { return status == 1; } strinline volatile u32* statusptr() { return &status; }
            tempbufw(const tempbufw&) = delete; tempbufw& operator=(const tempbufw&) = delete; tempbufw(tempbufw&&) = delete; tempbufw& operator=(tempbufw&&) = delete;
        };

        template<u64 n> using idxseq = std::make_integer_sequence<u64, n>;

        template<typename E, typename F>
        strinline void with_decrypted(const E& enc, F&& fn) {
            tempbuf<E::size()> tmp;
            decode<E::getk1(), E::getk2(), E::getk3(), E::size(), E::gethash(), E::getvar()>(enc.data(), reinterpret_cast<u8*>(tmp.data()), tmp.statusptr());
            if (tmp.valid()) fn(tmp.c_str());
        }

        template<typename E, typename F>
        strinline void with_decryptedw(const E& enc, F&& fn) {
            tempbufw<E::size()> tmp;
            decode<E::getk1(), E::getk2(), E::getk3(), E::size(), E::gethash(), E::getvar()>(enc.data(), reinterpret_cast<u8*>(tmp.data()), tmp.statusptr());
            if (tmp.valid()) fn(tmp.c_str());
        }

    }
}

#define e_cmp(input, s) (::str::detail::ctcmp64(::str::detail::siphash64rt(input, ::str::detail::key4, ::str::detail::key5), ::str::detail::siphash64(s, ::str::detail::key4, ::str::detail::key5)))
#define e_cmpw(input, s) (::str::detail::ctcmp64(::str::detail::siphash64rtw(input, ::str::detail::key4, ::str::detail::key5), ::str::detail::siphash64w(L##s, ::str::detail::key4, ::str::detail::key5)))

#define e_use(s, code) do { \
    constexpr int _c = __COUNTER__; \
    constexpr auto _k1 = ::str::detail::keygen<_c>::value, _k2 = ::str::detail::keygen<_c>::value2, _k3 = ::str::detail::keygen<_c>::value3; \
    constexpr auto _h = ::str::detail::calchash<_k1, _k2, _k3>(s, sizeof(s)); \
    static constexpr ::str::detail::encrypted<_k1, _k2, _k3, sizeof(s), _h, _c> _enc(s, ::str::detail::idxseq<sizeof(s)>{}); \
    ::str::detail::with_decrypted(_enc, [&](const char* it) { code; }); \
} while (0)

#define ew_use(s, code) do { \
    constexpr int _c = __COUNTER__; \
    constexpr auto _k1 = ::str::detail::keygen<_c>::value, _k2 = ::str::detail::keygen<_c>::value2, _k3 = ::str::detail::keygen<_c>::value3; \
    constexpr auto _h = ::str::detail::calchashw<_k1, _k2, _k3>(L##s, sizeof(L##s)); \
    static constexpr ::str::detail::encryptedw<_k1, _k2, _k3, sizeof(L##s), _h, _c> _enc(L##s, ::str::detail::idxseq<sizeof(L##s)>{}); \
    ::str::detail::with_decryptedw(_enc, [&](const wchar_t* it) { code; }); \
} while (0)

#define e_call(s, fn) e_use(s, { fn(it); })
#define ew_call(s, fn) ew_use(s, { fn(it); })

#endif