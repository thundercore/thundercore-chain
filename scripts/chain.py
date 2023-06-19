#!/usr/bin/env python3
""" Convenient command for starting/stopping local chains from thunder base dir """

from local_chain.local_chain import LocalChain

if __name__ == '__main__':
    LocalChain().run()
