# Installation & Evaluation on Hikey960

Hardware Prerequisites:

- A 64-bit x86 host machine with 20.04 LTS installed, at least 64GB of free disk space, and preferably a multi-core CPU.
- A Hikey960 development board with 3GB of RAM.

> The test time are based on our machine (i7-12700 20 cores).

These two pictures show a close shot on our Hikey 960 development board:

![](./pics/Hikey960%20Close%20Shot.jpg)

![](./pics/Cables%20for%20HIkey960.jpg)

## Downloading Sources

Our artifacts are based on the OP-TEE software stack. Download our artifacts and init the software stack following [OP-TEE's documentation](https://optee.readthedocs.io/en/3.21.0/building/prerequisites.html):

```bash
$ git clone https://github.com/TZChameleon/CHAMELEON.git && cd CHAMELEON/
$ mkdir Chameleon-Hikey960/ && cd Chameleon-Hikey960/
$ repo init -u https://github.com/OP-TEE/manifest.git -m hikey960.xml -b 3.21.0
$ repo sync -c --fetch-submodules -j$(nproc)
```

## Buliding Sources (approximately 30 minutes)

Before building, update the `optee_os/` and `trusted-firmware-a` folder. Moreover, add the real-world applications to the `optee_examples/` folder:

```bash
$ rm -rf optee_os/ trusted-firmware-a/
$ cp -r ../Chameleon-EL3/optee_os/ .
$ cp -r ../Chameleon-EL3/arm-tf ./trusted-firmware-a/
$ cp -r ../rw-apps/* optee_examples/
```

Downloading the cross-compile toolchains and build all the software stack:

```bash
$ cd build/ && make -j2 toolchains
$ make -j$(nproc)
```

Finally, following the [Linux Host Installation for HiKey960](https://www.96boards.org/documentation/consumer/hikey/hikey960/installation/linux-fastboot.md.html), power on and set up the Hikey960 board. Flash the images:

```bash
$ sudo make flash
```

## Running Evaluation (approximately 5 minutes for running all the benchmark)

Use the `scripts/` folder to evaluate the system. Following are the expected results.

For Xtest OS Features:

Benchmark|Command|Cost Time
:-:|:-:|:-:
Core|`time -f "time: %E" xtest _10`|46.22s
Network|`time -f "time: %E" xtest _40`|9.53s
Crypto|`time -f "time: %E" xtest _5`|0.25s
Internal|`time -f "time: %E" xtest _41`|3.41s
Global|`time -f "time: %E" xtest _80`|0.42s
Storage|`time -f "time: %E" xtest _20`|2.79s
SharedMemory|`time -f "time: %E" xtest _7`|0.01s
KeyDerivation|`time -f "time: %E" xtest _60`|19.42s
mbedTLS|`time -f "time: %E" xtest _81`|0.83s

For Xtest Benchmarks (these outputs should be parsed by the corresponding `parser-*.py`):

Benchmark|Command|Cost Time
:-:|:-:|:-:
SHA1|`xtest -t benchmark _20`|51.33us
SHA226|`xtest -t benchmark _20`|53.54us
ECB|`xtest -t benchmark _20`|47.14us
CBC|`xtest -t benchmark _20`|47.83us
WRITE|`xtest -t benchmark 1001`|761.33ms
READ|`xtest -t benchmark 1002`|511.88ms
REWRITE|`xtest -t benchmark 1003`|879.73ms

For TAs:

Benchmark|Command|Cost Time
:-:|:-:|:-:
Acipher|`time -f "time: %E" optee_example_acipher 1024 THIS_IS_A_TEST_STRING`|0.27s
Media DRM|`time -f "time: %E" optee_example_clearkey`|0.86s
Hotp|`time -f "time: %E" optee_example_hotp`|0.18s
Secure Storage|`time -f "time: %E" optee_example_secure_storage`|0.15s
Wallet|`time -f "time: %E" optee_example_wallet`|1.97s
