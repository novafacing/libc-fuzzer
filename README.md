# libc-fuzzer

This does what it sounds like! It attempts to, as automatically as possible, generate and
run fuzzers for up to the entire set of libc (in the default case, ~~musl-libc~~, because
glibc is really hard!) functions. I started this project thinking I would fuzz musl-libc
but that actually ended up being tricky because of compiler things. I still use musl-libc
to extract prototypes (hey, libc *is* a standard, after all!), but they are actually fuzzed
on the regular standard library. Less likely to find bugs, but the proof of concept is there!

It uses [`tree-sitter`](https://tree-sitter.github.io/tree-sitter/) to parse source code
and obtain function declarations, then creates simple harness(es) using
[`LibAFL`](https://github.com/AFLplusplus/LibAFL).

## Requirements

You will need `cargo` (and by extension, `rustc` and the rust toolchain).

You will also need `AFLplusplus` and LLVM 14.0.

### Install AFLPlusplus

Installing AFLPlusplus is pretty easy by following the documentation
[here](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/INSTALL.md). We don't
need anything special, following the steps up to `make distrib` should do it. Then, you
will need to add the path to wherever you installed it to your `$PATH`.

### Install LLVM 14

LLVM has, thankfully, made this much easier in recent years. Follow the instructions
[here](https://apt.llvm.org/) to install latest (which right now is 14, but in the
future you may need to follow the instructions that read `sudo ./llvm.sh 14`).
## Usage

`build.rs` will take care of most things for you, and `tree-sitter` is provided in
[`third_party`](third_party/tree-sitter-c/), so there is no need to manually download
`musl-libc` or anything.

### Harness Generation

To generate a harness, run:
```
libc-fuzzer 0.1.0

USAGE:
    harnesser [FUNCTIONS]...

ARGS:
    <FUNCTIONS>...    

OPTIONS:
    -h, --help       Print help information
    -V, --version    Print version information
```


Basically just `cargo run --bin harnesser [FUNC ...]`, for example:

```sh
$ cargo run --bin harnesser atoi regcomp
[2022-05-01T04:56:35Z INFO  harnesser] Found 1301 functions.
[2022-05-01T04:56:35Z INFO  harnesser] Generating fuzzer for atoi: int atoi(const char *)
[2022-05-01T04:56:35Z INFO  harnesser] Harness code:
    #include <cstddef>
    #include <cstdint>
    /* Header file this harness is fuzzing against */
    #include <stdlib.h>
    /* FuzzedDataProvider header library */
    #include <fuzzed_data_provider.hh>
    
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
                const char * param0 = fdp.consume<char>(fdp.consume<uint8_t>());
                int rv = atoi(param0);
    
                /* clang-format on */
            } catch (FuzzedDataProviderException &e) {
                continue;
            }
        }
    
        return 0;
    }
afl-cc ++3.15a by Michal Zalewski, Laszlo Szekeres, Marc Heuse - mode: LLVM-PCGUARD
SanitizerCoveragePCGUARD++3.15a
[+] Instrumented 88 locations with no collisions (non-hardened mode).
[2022-05-01T04:56:36Z INFO  harnesser] Generating fuzzer for regcomp: int regcomp(regex_t *, const char *, int)
[2022-05-01T04:56:36Z INFO  harnesser] Harness code:
    #include <cstddef>
    #include <cstdint>
    /* Header file this harness is fuzzing against */
    #include <regex.h>
    /* FuzzedDataProvider header library */
    #include <fuzzed_data_provider.hh>
    
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
                regex_t * param0 = new regex_t[1];
                const char * param1 = fdp.consume<char>(fdp.consume<uint8_t>());
                int param2 = fdp.consume<int>();
                int rv = regcomp(param0, param1, param2);
    
                /* clang-format on */
            } catch (FuzzedDataProviderException &e) {
                continue;
            }
        }
    
        return 0;
    }
```

This will generate four files for each function:

* The fuzzer harness supporting persistent mode. (`harness-FUNCNAME.cc`)
* Another fuzzer harness that takes straight from stdin and allows you to debug
  the setup more easily with GDB if that's your thing. (`harness-FUCNAME-manual.cc`)
* All four of those, compiled and ready to go! (`harness-FUNCNAME`,
  `harness-FUNCNAME-manual`)

### Running the Fuzzer

The fuzzer is pretty simple, because I intend to use it to get more into the weeds of
LibAFL as I go, but this is a PoC and I was focused on getting the automatic harness
generation going. In any case, to run the fuzzer, you just run with:

```
Program to start the LibAFL fuzzer on the generated harness

USAGE:
    libc-fuzzer <PROGRAM> <CORPUS_DIR>

ARGS:
    <PROGRAM>       The relative path to the program -- if it is in the local directory, be sure
                    that the path starts with `./`
    <CORPUS_DIR>    The relative path to the corpus directory to start with ex `./corpus`

OPTIONS:
    -h, --help       Print help information
    -V, --version    Print version information
```

So, for example to run our generated `atoi` fuzzer, we can run:

```
cargo run --bin libc-fuzzer ./fuzzer-atoi corpus
warning: dependency (clap) specified without providing a local path, Git repository, or version to use. This will be considered an error in future versions
warning: unused manifest key: dependencies.clap.verison
    Finished dev [unoptimized + debuginfo] target(s) in 0.06s
     Running `target/debug/libc-fuzzer ./fuzzer-atoi corpus`
All right - fork server is up.
Using SHARED MEMORY FUZZING feature.
Loading file "corpus/atoi.input.1" ...
[Stats #0] run time: 0h-0m-0s, clients: 1, corpus: 0, objectives: 0, executions: 0, exec/sec: 0
Client 000:
     NaN: Scheduler
     NaN: Manager
  Feedbacks:
     NaN: Not Measured

[Testcase #0] run time: 0h-0m-0s, clients: 1, corpus: 1, objectives: 0, executions: 1, exec/sec: 0
Client 000:
     NaN: Scheduler
     NaN: Manager
  Feedbacks:
     NaN: Not Measured

Loading file "corpus/input" ...
File "corpus/input" was not interesting, skipped.
[LOG Debug]: Loaded 1 initial testcases.
We imported 1 inputs from disk.
[Stats #0] run time: 0h-0m-0s, clients: 1, corpus: 1, objectives: 0, executions: 1, exec/sec: 0
Client 000:
     NaN: Scheduler
     NaN: Manager
  Feedbacks:
     NaN: Not Measured

[Testcase #0] run time: 0h-0m-0s, clients: 1, corpus: 2, objectives: 0, executions: 4, exec/sec: 0
Client 000:
     NaN: Scheduler
     NaN: Manager
  Feedbacks:
     NaN: Not Measured

[PerfMonitor #0] run time: 0h-0m-15s, clients: 1, corpus: 2, objectives: 0, executions: 1827, exec/sec: 0
Client 000:
  0.0002: Scheduler
  0.0000: Manager
  Stage 0:
    0.0002: GetInputFromCorpus
    0.0028: Mutate
    0.0000: MutatePostExec
    0.0468: TargetExecution
    0.1804: PreExecObservers
    0.2913: PostExecObservers
  Feedbacks:
    0.4752: shared_mem
    0.0001: time
    0.0000: TimeoutFeedback
  0.0030: Not Measured
```

Once you start getting `PerfMonitor` output, it should be working!


## Known Issues

* Structs: harnesser does not deduce or generate singly or multiply nested structs yet.
* Double (or greater) indirection: results for functions that take double pointers will
  be inconsistent at best, and probably will not work.
