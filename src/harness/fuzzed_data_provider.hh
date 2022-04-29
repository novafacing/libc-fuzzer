#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <string>

class FuzzedDataProviderException : public std::exception {
    const std::string msg;

public:
    FuzzedDataProviderException(const char *msg) : msg(msg) {}
    virtual const char *what() const noexcept {
        return ("FuzzedDataProviderException: " + msg).c_str();
    }
};

class FuzzedDataProvider {
private:
    const uint8_t *data;
    const size_t size;
    size_t offset = 0;
    const bool throw_on_ood = true;

public:
    FuzzedDataProvider(const uint8_t *data, const size_t size,
                       const bool throw_on_ood = true)
        : data(std::move(data)), size(size), throw_on_ood(throw_on_ood) {}

    /* CHAR_BITS, no signedness guarantees */
    const char ConsumeChar();
    /* CHAR_BITS, [-127,127] signed */
    const signed char ConsumeSignedChar();
    /* CHAR_BITS, [0,255] unsigned */
    const unsigned char ConsumeUnsignedChar();
    /* 16 bits, [-32767,32767] signed */
    const short ConsumeShort();
    const short int ConsumeShortInt();
    const signed short ConsumeSignedShort();
    const signed short int ConsumeSignedShortInt();

    /* 16 bits, [0,65535] unsigned */
    const unsigned short ConsumeUnsignedShort();
    const unsigned short int ConsumeUnsignedShortInt();

    /* 16-32 bits, [-2147483647,2147483647] signed */
    const int ConsumeInt();
    const signed ConsumeSigned();
    const signed int ConsumeSignedInt();

    /* 16-32 bits, [0,4294967295] unsigned */
    const unsigned ConsumeUnsigned();
    const unsigned int ConsumeUnsignedInt();

    /* 32 bits, [-2147483647-,2147483647+] signed */
    const long ConsumeLong();
    const long int ConsumeLongInt();
    const signed long ConsumeSignedLong();
    const signed long int ConsumeSignedLongInt();

    /* 32 bits, [0,4294967295+] unsigned */
    const unsigned long ConsumeUnsignedLong();
    const unsigned long int ConsumeUnsignedLongInt();

    /* 64 bits, [-9223372036854775807,9223372036854775807] signed */
    const long long ConsumeLongLong();
    const long long int ConsumeLongLongInt();
    const signed long long ConsumeSignedLongLong();
    const signed long long int ConsumeSignedLongLongInt();

    /* 64 bits, [0,18446744073709551615] unsigned */
    const unsigned long long ConsumeUnsignedLongLong();
    const unsigned long long int ConsumeUnsignedLongLongInt();

    /* 32 bits, IEEE 754 single precision */
    const float ConsumeFloat();

    /* 64 bits, IEEE 754 double precision */
    const double ConsumeDouble();

    /* 64 bits, IEEE 754 extended precision */
    const long double ConsumeLongDouble();

    /* 8 bits, [0,1] */
    const bool ConsumeBool();

    /* char * sequence, null terminated */
    const char *ConsumeChars(size_t length);

    /* uint8_t * sequence, not necessarily null terminated */
    const uint8_t *ConsumeBytes(size_t length);

    /* Create a pointer to some data */
    template <typename T> T *pointer(T value) {
        T *rv = new T(value);
        return rv;
    }
};