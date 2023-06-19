""" Stops the local chain """

import sys
import os
import tempfile
import time
import subprocess

import docker

from local_chain import config, utils
from local_chain.local_chain_command_base import LocalChainCommand

def backup_debuging_files(args):
    def _copy(cont, f, dest):
        cmd = ['docker', 'cp', '{}:{}'.format(cont.name, f), dest]
        try:
            subprocess.check_call(cmd)
        except subprocess.CalledProcessError:
            print("Failed! {} doesn't existed".format(f), file=sys.stderr)
            raise

    client = docker.from_env()
    with tempfile.TemporaryDirectory() as tempdir:
        localchain = 'localchain-{}'.format(int(time.time()))
        containers = utils.get_containers(args.prefix)
        for cont in containers:
            dest = os.path.join(tempdir, localchain, cont.name)
            os.makedirs(dest, exist_ok=True)
            _copy(cont, '/logs', dest)

        if containers:
            tarfile = os.path.join(config.THUNDER_ROOT, localchain + '.tar')
            subprocess.check_call(['tar', 'zcf', tarfile, '-C', tempdir, '.'])
            print('Create tarball {}'.format(tarfile))


# pylint: disable=missing-docstring
class StopCmd(LocalChainCommand):
    CMD_NAME = "stop"

    def add_subcommand(self, subparsers):
        sub = subparsers.add_parser(self.CMD_NAME, help="Stops the local chain")
        sub.set_defaults(cmd=self.CMD_NAME)
        sub.add_argument('-f', '--force', default=False, action='store_true',
                         help='Directly kill the docker containers(using docker rm -f)')
        sub.add_argument('-p', '--prefix', default='pala', required=False,
                         help='Container prefix. (default: pala)')
        sub.add_argument('-b', '--backup', default=False, action='store_true',
                         help='Backup debuging files before containers be destroyed')

    def run(self, args):
        if args.backup:
            backup_debuging_files(args)

        dccmd = config.DOCKER_COMPOSE_CMD + ['-p', args.prefix]
        if args.force:
            print("Killing all docker containers (using force)")
            subprocess.check_call(dccmd + ['kill'])

        print("Stopping docker services")
        subprocess.check_call(dccmd + ['down'])

        network = utils.get_docker_network()
        if network:
            if len(network.containers) == 0:
                network.remove()
            else:
                print("network {} is in use".format(config.DOCKER_NETWORK))
