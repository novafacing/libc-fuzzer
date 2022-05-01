#include <cstddef>
#include <cstdint>
/* Header file this harness is fuzzing against */
#include <{hdr}>
/* FuzzedDataProvider header library */
#include <{fdplib}>

__AFL_FUZZ_INIT();

/* Persistent-mode fuzzing ready harness, can't use this to debug the program */
int main() {

#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    uint8_t *data = (uint8_t *)__AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(10000)) {
        size_t len = (size_t)__AFL_FUZZ_TESTCASE_LEN;

        try {
            FuzzedDataProvider fdp(data, len);
            /* clang-format off */
{body}
            /* clang-format on */
        } catch (FuzzedDataProviderException &e) {
            continue;
        }
    }

    return 0;
}