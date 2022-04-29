#include "fuzzed_data_provider.hh"

#include <iostream>

/* expect (I'll add tests at some point):
 * A
 * A
 * A
 * 16705
 * 16705
 * 16705
 * 16705
 * 16705
 * 16705
 * 1094795585
 * 1094795585
 * 1094795585
 * 1094795585
 * 1094795585
 * 4702111234474983745
 * 4702111234474983745
 * 4702111234474983745
 * 4702111234474983745
 * 4702111234474983745
 * 4702111234474983745
 * 12.0784
 * 2.26163e+06
 * nan
 * A
 * A
 * AAAAAAAA
 */

int main() {
    uint8_t *data = new uint8_t[1000];
    memset(data, 0x41, 1000);
    FuzzedDataProvider fdp(data, 1000);
    char c = fdp.consume<char>();
    std::cout << c << std::endl;
    signed char sc = fdp.consume<signed char>();
    std::cout << sc << std::endl;
    unsigned char uc = fdp.consume<unsigned char>();
    std::cout << uc << std::endl;
    short s = fdp.consume<short>();
    std::cout << s << std::endl;
    short int shi = fdp.consume<short int>();
    std::cout << shi << std::endl;
    signed short ss = fdp.consume<signed short>();
    std::cout << ss << std::endl;
    signed short int ssi = fdp.consume<signed short int>();
    std::cout << ssi << std::endl;
    unsigned short us = fdp.consume<unsigned short>();
    std::cout << us << std::endl;
    unsigned short int usi = fdp.consume<unsigned short int>();
    std::cout << usi << std::endl;
    int i = fdp.consume<unsigned short int>();
    std::cout << i << std::endl;
    signed sgn = fdp.consume<signed>();
    std::cout << sgn << std::endl;
    signed int si = fdp.consume<signed int>();
    std::cout << si << std::endl;
    unsigned u = fdp.consume<unsigned>();
    std::cout << u << std::endl;
    unsigned int ui = fdp.consume<unsigned int>();
    std::cout << ui << std::endl;
    long l = fdp.consume<long>();
    std::cout << l << std::endl;
    long int li = fdp.consume<long int>();
    std::cout << li << std::endl;
    signed long sl = fdp.consume<signed long>();
    std::cout << sl << std::endl;
    signed long int sli = fdp.consume<signed long int>();
    std::cout << sli << std::endl;
    unsigned long ul = fdp.consume<unsigned long>();
    std::cout << ul << std::endl;
    unsigned long int uli = fdp.consume<unsigned long int>();
    std::cout << uli << std::endl;
    float f = fdp.consume<float>();
    std::cout << f << std::endl;
    double d = fdp.consume<double>();
    std::cout << d << std::endl;
    long double ld = fdp.consume<long double>();
    std::cout << ld << std::endl;
    char *cp = fdp.pointer<char>(c);
    std::cout << cp << std::endl;
    char **cpp = fdp.pointer<char *>(cp);
    std::cout << *cpp << std::endl;
    uint8_t *u8p = fdp.consume<uint8_t>(8);
    std::cout << u8p << std::endl;
    uint8_t **u8pp = fdp.pointer<uint8_t *>(u8p);
    std::cout << *u8pp << std::endl;
}