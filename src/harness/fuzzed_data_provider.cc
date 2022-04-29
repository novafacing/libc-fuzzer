#include "fuzzed_data_provider.hh"

const char FuzzedDataProvider::ConsumeChar() {
    if (offset >= size && throw_on_ood) {
        throw FuzzedDataProviderException("ConsumeChar: out of data");
    }

    const char rv = *reinterpret_cast<const char *>(data + offset);

    offset += sizeof(char);
    return rv;
}

const signed char FuzzedDataProvider::ConsumeSignedChar() {
    if (offset >= size && throw_on_ood) {
        throw FuzzedDataProviderException("ConsumeSignedChar: out of data");
    }

    const signed char rv = *reinterpret_cast<const signed char *>(data + offset);

    offset += sizeof(signed char);
    return rv;
}

const unsigned char FuzzedDataProvider::ConsumeUnsignedChar() {
    if (offset >= size && throw_on_ood) {
        throw FuzzedDataProviderException("ConsumeUnsignedChar: out of data");
    }

    const unsigned char rv = *reinterpret_cast<const unsigned char *>(data + offset);

    offset += sizeof(unsigned char);
    return rv;
}

const short FuzzedDataProvider::ConsumeShort() {
    if (offset >= size && throw_on_ood) {
        throw FuzzedDataProviderException("ConsumeShort: out of data");
    }

    const short rv = *reinterpret_cast<const short *>(data + offset);

    offset += sizeof(short);
    return rv;
}

const short int FuzzedDataProvider::ConsumeShortInt() {
    if (offset >= size && throw_on_ood) {
        throw FuzzedDataProviderException("ConsumeShortInt: out of data");
    }

    const short int rv = *reinterpret_cast<const short int *>(data + offset);

    offset += sizeof(short int);
    return rv;
}

const signed short FuzzedDataProvider::ConsumeSignedShort() {
    if (offset >= size && throw_on_ood) {
        throw FuzzedDataProviderException("ConsumeSignedShort: out of data");
    }

    const signed short rv = *reinterpret_cast<const signed short *>(data + offset);

    offset += sizeof(signed short);
    return rv;
}

const signed short int FuzzedDataProvider::ConsumeSignedShortInt() {
    if (offset >= size && throw_on_ood) {
        throw FuzzedDataProviderException("ConsumeSignedShortInt: out of data");
    }

    const signed short int rv =
        *reinterpret_cast<const signed short int *>(data + offset);

    offset += sizeof(signed short int);
    return rv;
}

const unsigned short FuzzedDataProvider::ConsumeUnsignedShort() {
    if (offset >= size && throw_on_ood) {
        throw FuzzedDataProviderException("ConsumeUnsignedShort: out of data");
    }

    const unsigned short rv = *reinterpret_cast<const unsigned short *>(data + offset);

    offset += sizeof(unsigned short);
    return rv;
}

const unsigned short int FuzzedDataProvider::ConsumeUnsignedShortInt() {
    if (offset >= size && throw_on_ood) {
        throw FuzzedDataProviderException("ConsumeUnsignedShortInt: out of data");
    }

    const unsigned short int rv =
        *reinterpret_cast<const unsigned short int *>(data + offset);

    offset += sizeof(unsigned short int);
    return rv;
}

const int FuzzedDataProvider::ConsumeInt() {
    if (offset >= size && throw_on_ood) {
        throw FuzzedDataProviderException("ConsumeInt: out of data");
    }

    const int rv = *reinterpret_cast<const int *>(data + offset);

    offset += sizeof(int);
    return rv;
}

const signed FuzzedDataProvider::ConsumeSigned() {
    if (offset >= size && throw_on_ood) {
        throw FuzzedDataProviderException("ConsumeSigned: out of data");
    }

    const signed rv = *reinterpret_cast<const signed *>(data + offset);

    offset += sizeof(signed);
    return rv;
}

const signed int FuzzedDataProvider::ConsumeSignedInt() {
    if (offset >= size && throw_on_ood) {
        throw FuzzedDataProviderException("ConsumeSignedInt: out of data");
    }

    const signed int rv = *reinterpret_cast<const signed int *>(data + offset);

    offset += sizeof(signed int);
    return rv;
}

const unsigned FuzzedDataProvider::ConsumeUnsigned() {
    if (offset >= size && throw_on_ood) {
        throw FuzzedDataProviderException("ConsumeUnsigned: out of data");
    }

    const unsigned rv = *reinterpret_cast<const unsigned *>(data + offset);

    offset += sizeof(unsigned);
    return rv;
}

const unsigned int FuzzedDataProvider::ConsumeUnsignedInt() {
    if (offset >= size && throw_on_ood) {
        throw FuzzedDataProviderException("ConsumeUnsignedInt: out of data");
    }

    const unsigned int rv = *reinterpret_cast<const unsigned int *>(data + offset);

    offset += sizeof(unsigned int);
    return rv;
}

const long FuzzedDataProvider::ConsumeLong() {
    if (offset >= size && throw_on_ood) {
        throw FuzzedDataProviderException("ConsumeLong: out of data");
    }

    const long rv = *reinterpret_cast<const long *>(data + offset);

    offset += sizeof(long);
    return rv;
}

const long int FuzzedDataProvider::ConsumeLongInt() {
    if (offset >= size && throw_on_ood) {
        throw FuzzedDataProviderException("ConsumeLongInt: out of data");
    }

    const long int rv = *reinterpret_cast<const long int *>(data + offset);

    offset += sizeof(long int);
    return rv;
}

const signed long FuzzedDataProvider::ConsumeSignedLong() {
    if (offset >= size && throw_on_ood) {
        throw FuzzedDataProviderException("ConsumeSignedLong: out of data");
    }

    const signed long rv = *reinterpret_cast<const signed long *>(data + offset);

    offset += sizeof(signed long);
    return rv;
}

const signed long int FuzzedDataProvider::ConsumeSignedLongInt() {
    if (offset >= size && throw_on_ood) {
        throw FuzzedDataProviderException("ConsumeSignedLongInt: out of data");
    }

    const signed long int rv =
        *reinterpret_cast<const signed long int *>(data + offset);

    offset += sizeof(signed long int);
    return rv;
}

const unsigned long FuzzedDataProvider::ConsumeUnsignedLong() {
    if (offset >= size && throw_on_ood) {
        throw FuzzedDataProviderException("ConsumeUnsignedLong: out of data");
    }

    const unsigned long rv = *reinterpret_cast<const unsigned long *>(data + offset);

    offset += sizeof(unsigned long);
    return rv;
}

const unsigned long int FuzzedDataProvider::ConsumeUnsignedLongInt() {
    if (offset >= size && throw_on_ood) {
        throw FuzzedDataProviderException("ConsumeUnsignedLongInt: out of data");
    }

    const unsigned long int rv =
        *reinterpret_cast<const unsigned long int *>(data + offset);

    offset += sizeof(unsigned long int);
    return rv;
}

const long long FuzzedDataProvider::ConsumeLongLong() {
    if (offset >= size && throw_on_ood) {
        throw FuzzedDataProviderException("ConsumeLongLong: out of data");
    }

    const long long rv = *reinterpret_cast<const long long *>(data + offset);

    offset += sizeof(long long);
    return rv;
}

const long long int FuzzedDataProvider::ConsumeLongLongInt() {
    if (offset >= size && throw_on_ood) {
        throw FuzzedDataProviderException("ConsumeLongLongInt: out of data");
    }

    const long long int rv = *reinterpret_cast<const long long int *>(data + offset);

    offset += sizeof(long long int);
    return rv;
}

const signed long long FuzzedDataProvider::ConsumeSignedLongLong() {
    if (offset >= size && throw_on_ood) {
        throw FuzzedDataProviderException("ConsumeSignedLongLong: out of data");
    }

    const signed long long rv =
        *reinterpret_cast<const signed long long *>(data + offset);

    offset += sizeof(signed long long);
    return rv;
}

const signed long long int FuzzedDataProvider::ConsumeSignedLongLongInt() {
    if (offset >= size && throw_on_ood) {
        throw FuzzedDataProviderException("ConsumeSignedLongLongInt: out of data");
    }

    const signed long long int rv =
        *reinterpret_cast<const signed long long int *>(data + offset);

    offset += sizeof(signed long long int);
    return rv;
}

const unsigned long long FuzzedDataProvider::ConsumeUnsignedLongLong() {
    if (offset >= size && throw_on_ood) {
        throw FuzzedDataProviderException("ConsumeUnsignedLongLong: out of data");
    }

    const unsigned long long rv =
        *reinterpret_cast<const unsigned long long *>(data + offset);

    offset += sizeof(unsigned long long);
    return rv;
}

const unsigned long long int FuzzedDataProvider::ConsumeUnsignedLongLongInt() {
    if (offset >= size && throw_on_ood) {
        throw FuzzedDataProviderException("ConsumeUnsignedLongLongInt: out of data");
    }

    const unsigned long long int rv =
        *reinterpret_cast<const unsigned long long int *>(data + offset);

    offset += sizeof(unsigned long long int);
    return rv;
}

const float FuzzedDataProvider::ConsumeFloat() {
    if (offset >= size && throw_on_ood) {
        throw FuzzedDataProviderException("ConsumeFloat: out of data");
    }

    const float rv = *reinterpret_cast<const float *>(data + offset);

    offset += sizeof(float);
    return rv;
}

const double FuzzedDataProvider::ConsumeDouble() {
    if (offset >= size && throw_on_ood) {
        throw FuzzedDataProviderException("ConsumeDouble: out of data");
    }

    const double rv = *reinterpret_cast<const double *>(data + offset);

    offset += sizeof(double);
    return rv;
}

const long double FuzzedDataProvider::ConsumeLongDouble() {
    if (offset >= size && throw_on_ood) {
        throw FuzzedDataProviderException("ConsumeLongDouble: out of data");
    }

    const long double rv = *reinterpret_cast<const long double *>(data + offset);

    offset += sizeof(long double);
    return rv;
}

const bool FuzzedDataProvider::ConsumeBool() {
    if (offset >= size && throw_on_ood) {
        throw FuzzedDataProviderException("ConsumeBool: out of data");
    }

    const bool rv = *reinterpret_cast<const bool *>(data + offset);

    offset += sizeof(bool);
    return rv;
}

const char *FuzzedDataProvider::ConsumeChars(size_t length) {
    if (offset >= size && throw_on_ood) {
        throw FuzzedDataProviderException("ConsumeChars: out of data");
    }

    char *rv = new char[length];
    memcpy(rv, data + offset, length - 1);
    rv[length - 1] = '\0';

    return rv;
}

const uint8_t *FuzzedDataProvider::ConsumeBytes(size_t length) {
    if (offset >= size && throw_on_ood) {
        throw FuzzedDataProviderException("ConsumeBytes: out of data");
    }

    uint8_t *rv = new uint8_t[length];
    memcpy(rv, data + offset, length);

    return rv;
}