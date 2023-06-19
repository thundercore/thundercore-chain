# ThunderCore Chain

[PaLa](https://eprint.iacr.org/2018/981) is a byzantine fault tolerant consensus protocol invented by T-H. Hubert Chan, Rafael Pass, and Elaine Shi. It can achieve low latency and high throughput in a partially synchronous network setting. PaLa allows support seamless proposer switch with no delay in normal operation. When there is a network partition, the protocol switches proposers with little delay (say 6s) to keep liveness as long as there are at least one honest proposer and 2/3 voters in a single partition. All honest nodes maintain consistency no matter how the network is partitioned.

## Distributed Consensus in Practice

To fill the gap between the academic paper and a working product, our developers discussed the details of [PaLa](https://eprint.iacr.org/2018/981) with Prof. Elaine Shi and came up with the [pseudocode](https://github.com/thundercore/pala-poc/blob/master/documents/doubly-pipelined-pala-pseudo-code.txt). The pseudocode is the reference for this project and is a good starting point for understanding this beautiful consensus protocol.

## Development Environment Setup

#### Compile with local go(recommand version 1.16)
```
$ make pala
```
#### Run all tests
```
$ make test
```

## Localchain

#### You need Docker
Please refer to https://docs.docker.com/install/ for Docker installation

#### Start or Stop localchain
```
$ cd ./scripts
$ python3 ./chain.py start
$ python3 ./chain.py stop
$ python3 ./chain.py start --help  # for more options
```

#### Single Process Pala
clear the datadir and launch the single process 
```
$ ./scripts/test/pala-dev -c
$ ./scripts/test/pala-dev
```
## Contributing

Feel free to fork and make PRs. We are glad to see feedback from the community and make the implementation and tests more complete.

## Supporting Documents

* [Doubly Pipelined PaLa pseudocode](https://github.com/thundercore/pala/blob/master/documents/doubly-pipelined-pala-pseudo-code.txt): understand how the consensus protocol is implemented in practice.
* [Terminology and data flow](https://docs.google.com/presentation/d/1vQ1Kh5O_kNXe0y0GK9c26UTmblPIdx8DDoKmPhrrr3c/edit?usp=sharing): understand how PaLa works via examples of different scenarios.
* [Software architecture](https://docs.google.com/presentation/d/1AY-GiujqkzRdfdleDSrj516d48-3w-z70w4DQiy_3HY/edit?usp=sharing): understand the architecture and how objects interact.
* [Goroutines and Channels](https://docs.google.com/presentation/d/1gWASAqIgjMtjYy5O31bIRwg3VViDpc9GIRPiwiA7BHo/edit?usp=sharing): understand the concurrency design.
* [Slides for PaLa talk](https://docs.google.com/presentation/d/1O_FEApTCfWywIZ2fMl18xE51AkJgx5LWY_NGdtbhUIk/edit): Slides for a talk on PaLa and PaLa software architecture given by Chia-Hao Lo @ COSCUP 2019. A recording of the talk itself given in Mandarin is available [here](https://www.youtube.com/watch?v=HbDmtB0FGcs&feature=youtu.be).

## License
[MIT](https://github.com/thundercore/pala/blob/master/LICENSE)
Copyright (C) 2017-2023 Thunder Token Inc.
