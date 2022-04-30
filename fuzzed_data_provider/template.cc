#include <cstddef>
#include <cstdint>
/* Header file this harness is fuzzing against */
#include <{hdr}>
/* FuzzedDataProvider header library */
#include <{fdplib}>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    try {
        /* clang-format off */
        FuzzedDataProvider fdp(data, size);
{body}
        /* clang-format on */
    } catch (FuzzedDataProviderException &e) {
        return 1;
    }

    return 0;
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    __AFL_FUZZ_INIT();
    return 0;
}