# CHAMELEON

We present two deployment options for Chameleon (EL1 and EL3), along with a collection of 41 open-source TA repositories and an analysis of 138 high-risk CVEs related to TrustZone TEE.

```bash
$ git clone https://github.com/TZChameleon/CHAMELEON.git
$ cd artifacts/
$ docker build . -t chameleon-el3
$ ./run_chameleon.sh
```

## Chameleon-EL1

This prototype runs on Hikey960 development board.

- The `optee_os` folder is the source code of the Trusted OS.

## Chameleon-EL3

This prototype runs on Hikey960 development board.

- The `optee_os` folder is the source code of the Trusted OS.
- The `arm-tf` folder is the source code of the Monitor.

We will supplement detailed deployment steps after the paper is published.
