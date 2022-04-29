#include "fuzzed_data_provider.hh"

#include <iostream>

int main() {
    uint8_t *data = new uint8_t[1000];
    memset(data, 0x41, 1000);
    FuzzedDataProvider fdp(data, 1000);
    char c = fdp.ConsumeChar();
    std::cout << c << std::endl;
    signed char sc = fdp.ConsumeSignedChar();
    std::cout << sc << std::endl;
    unsigned char uc = fdp.ConsumeUnsignedChar();
    std::cout << uc << std::endl;
    short s = fdp.ConsumeShort();
    std::cout << s << std::endl;
    short int shi = fdp.ConsumeShortInt();
    std::cout << shi << std::endl;
    signed short ss = fdp.ConsumeSignedShort();
    std::cout << ss << std::endl;
    signed short int ssi = fdp.ConsumeSignedShortInt();
    std::cout << ssi << std::endl;
    unsigned short us = fdp.ConsumeUnsignedShort();
    std::cout << us << std::endl;
    unsigned short int usi = fdp.ConsumeUnsignedShortInt();
    std::cout << usi << std::endl;
    int i = fdp.ConsumeInt();
    std::cout << i << std::endl;
    signed sgn = fdp.ConsumeSigned();
    std::cout << sgn << std::endl;
    signed int si = fdp.ConsumeSignedInt();
    std::cout << si << std::endl;
    unsigned u = fdp.ConsumeUnsigned();
    std::cout << u << std::endl;
    unsigned int ui = fdp.ConsumeUnsignedInt();
    std::cout << ui << std::endl;
    long l = fdp.ConsumeLong();
    std::cout << l << std::endl;
    long int li = fdp.ConsumeLongInt();
    std::cout << li << std::endl;
    signed long sl = fdp.ConsumeSignedLong();
    std::cout << sl << std::endl;
    signed long int sli = fdp.ConsumeSignedLongInt();
    std::cout << sli << std::endl;
    unsigned long ul = fdp.ConsumeUnsignedLong();
    std::cout << ul << std::endl;
    unsigned long int uli = fdp.ConsumeUnsignedLongInt();
    std::cout << uli << std::endl;
    float f = fdp.ConsumeFloat();
    std::cout << f << std::endl;
    double d = fdp.ConsumeDouble();
    std::cout << d << std::endl;
    long double ld = fdp.ConsumeLongDouble();
    std::cout << ld << std::endl;
    char *cp = fdp.pointer<char>(c);
    std::cout << cp << std::endl;
    char **cpp = fdp.pointer<char *>(cp);
    std::cout << *cpp << std::endl;
    const uint8_t *u8p = fdp.ConsumeBytes(8);
    std::cout << u8p << std::endl;
}