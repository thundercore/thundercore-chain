"""Restarts the local chain containers with docker-compose"""

import sys
import os
import subprocess
import tarfile

from local_chain import config
from local_chain.local_chain_command_base import (LocalChainCommand,
                                                  _clean_data_volumes,
                                                  KeyOutputPaths,
                                                  cmd_print,
                                                  get_key_paths,
                                                  load_yml, dump_yml,)

class RestartCmd(LocalChainCommand):
    YML_PATH = config.LOCAL_CHAIN_ROOT_DIR.joinpath('docker-compose.yml')
    CMD_NAME = 'restart'

    def add_subcommand(self, subparsers):
        sub = subparsers.add_parser(self.CMD_NAME, help='Restarts the local chain with docker-compose')
        sub.set_defaults(cmd=self.CMD_NAME)
        sub.add_argument('--use-existing-data', action='store_true', default=False,
                         help='If true, existing data dir (if any) is used directly,'
                         'otherwise it\'s deleted and recreated')
        sub.add_argument('-p', '--prefix', default='pala', required=False,
                         help='Container prefix. (default: pala)')

    def run(self, args):
        p = subprocess.Popen(config.DOCKER_COMPOSE_CMD + ['-p', args.prefix, 'down'])

        r = p.wait()
        if r != 0:
            cmd_print('chain restart: `docker-compose down` failed but this is allowed')
        if not args.use_existing_data:
            _clean_data_volumes(prefix=args.prefix)
        subprocess.check_call(config.DOCKER_COMPOSE_CMD + ['-p', args.prefix, 'up', '--no-build', '-d'])
