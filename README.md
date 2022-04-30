# libc-fuzzer

This does what it sounds like! It attempts to, as automatically as possible, generate and
run fuzzers for up to the entire set of libc (in the default case, musl-libc, because
glibc is really hard!) functions.

It uses [`tree-sitter`](https://tree-sitter.github.io/tree-sitter/) to parse source code
and obtain function declarations, then creates simple harness(es) using
[`LibAFL`](https://github.com/AFLplusplus/LibAFL).

## Usage

`build.rs` will take care of most things for you, and `tree-sitter` is provided in
[`third_party`](third_party/tree-sitter-c/), so there is no need to manually download
`musl-libc` or anything.

To generate a harness, run `cargo run --bin harnesser [FUNC ...]`, for example:

```sh
$ cargo run --bin harnesser regcomp
[2022-04-30T05:56:20Z INFO  harnesser] Found 1301 functions.
[2022-04-30T05:56:20Z INFO  harnesser] Generating fuzzer for atoi: int atoi(const char *)
[2022-04-30T05:56:20Z INFO  harnesser] Harness code:
    #include <cstddef>
    #include <cstdint>
    /* Header file this harness is fuzzing against */
    #include <stdlib.h>
    /* FuzzedDataProvider header library */
    #include <fuzzed_data_provider.hh>
    
    extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        try {
            /* clang-format off */
            FuzzedDataProvider fdp(data, size);
            const char * param0 = fdp.consume<const char *>(fdp.consume<size_t>());
            int rv = atoi(param0);
    
            /* clang-format on */
        } catch (FuzzedDataProviderException &e) {
            return 1;
        }
    
        return 0;
    }
[2022-04-30T05:56:20Z INFO  harnesser] Generating fuzzer for regcomp: int regcomp(regex_t *, const char *, int)
[2022-04-30T05:56:20Z INFO  harnesser] Harness code:
    #include <cstddef>
    #include <cstdint>
    /* Header file this harness is fuzzing against */
    #include <regex.h>
    /* FuzzedDataProvider header library */
    #include <fuzzed_data_provider.hh>
    
    extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        try {
            /* clang-format off */
            FuzzedDataProvider fdp(data, size);
            regex_t * param0 = new regex_t;
            const char * param1 = fdp.consume<const char *>(fdp.consume<size_t>());
            int param2 = fdp.consume<int>();
            int rv = regcomp(param0, param1, param2);
    
            /* clang-format on */
        } catch (FuzzedDataProviderException &e) {
            return 1;
        }
    
        return 0;
    }
```

## Known Issues

* Structs: harnesser does not deduce or generate singly or multiply nested structs yet.
* Double (or greater) indirection: results for functions that take double pointers will
  be inconsistent at best, and probably will not work.
