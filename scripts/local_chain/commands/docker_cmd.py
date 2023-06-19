""" Shortcut for docker-compose """

import subprocess

from local_chain import config
from local_chain.local_chain_command_base import LocalChainCommand

# pylint: disable=missing-docstring
class DockerCmd(LocalChainCommand):
    YML_PATH = config.LOCAL_CHAIN_ROOT_DIR.joinpath("docker-compose.yml")
    CMD_NAME = "docker"

    def add_subcommand(self, subparsers):
        sub = subparsers.add_parser(self.CMD_NAME, help="Shortcut for docker-compose")

        sub.set_defaults(cmd=self.CMD_NAME)
        sub.add_argument('args', nargs='*', help='docker-compose arguments')

    def run(self, args):
        dccmd = config.DOCKER_COMPOSE_CMD
        if '-p' not in args.args:
            dccmd += ['-p', 'pala']
        dccmd += args.args
        subprocess.check_call(dccmd)
