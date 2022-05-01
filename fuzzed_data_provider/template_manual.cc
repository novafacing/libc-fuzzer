#include <cstddef>
#include <cstdint>
/* Header file this harness is fuzzing against */
#include <{hdr}>
/* FuzzedDataProvider header library */
#include <{fdplib}>

/* Non-fuzzaable testing main for use to debug the harness */
int main() {

    try {
        FuzzedDataBroker broker;
        FuzzedDataProvider fdp(broker.data(), broker.size());
        /* clang-format off */
{body}
        /* clang-format on */
    } catch (FuzzedDataProviderException &e) {
        printf("%s\n", e.what());
        return 1;
    }

    return 0;
}