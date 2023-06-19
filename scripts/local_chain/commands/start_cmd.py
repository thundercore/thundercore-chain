""" Starts local chain """

import argparse
import configparser
import docker
import getpass
import yaml
import shutil
import json
import logging
import sys
import os
from pathlib import Path
import platform
import subprocess

from local_chain.local_chain_command_base import (
    LocalChainCommand,
    _clean_data_volumes,
    PalaStatus,
    cmd_print,
    cmd_output,
    get_key_paths,
)

from local_chain import docker_compose_builder, utils, config
from local_chain import accounts

# Ports info:
# Format: <ports used by role> [increment value for next instance of that role]
# For eg. 8888 [+10] => proposer_0 uses 8888, proposer_1 uses 8898
#
# Ports for fast-path:
#     Proposer: 888{7, 8, 9} [+10]
#     Opened to host: 8887, 8889
#
#     Fullnode: 8545/46 [+2]
#     Opened to host: 8545/46
LOG = logging.getLogger(__name__)

class BuildDockerImageError(Exception):
    pass


def build_docker_image():
    'build binaries then build docker image'
    if platform.system() == "Linux" or platform.system() == "Darwin":
        build_cmd = ['docker', 'build', '../.', '-t', 'thunder']        
    else:
        raise BuildDockerImageError('Unsupported OS {}. Only Linux and MacOS are supported. Exiting'.format(
            platform.system()))
    cmd_print('\n> Build the docker image\n')
    subprocess.check_call(build_cmd)
    return 'thunder'

def _generate_all_keys_to_fs(comm_size, dst_dir):
    """Create keys directories and ensure that they contain the right keys."""
    _generate_keys_to_fs("genvotekeys", comm_size, dst_dir)
    _generate_keys_to_fs("genstakeinkeys", comm_size, dst_dir)

def _generate_keys_to_fs(gen_key_type, num_keys, dst_dir):
    """Generates account keypairs."""
    if gen_key_type not in ["genvotekeys", "genstakeinkeys"]:
        LOG.error("Account key generation failed: unknown command %s", gen_key_type)
        sys.exit(1)

    cmd = ['docker', 'exec', 'thunder-keygen', 
        'thundertool', '--noencrypt', gen_key_type, '--fs-destdir', str(dst_dir), '--num-keys', str(num_keys)
    ]

    print("> Generate keys")
    print(" ".join(cmd))
    subprocess.check_call(cmd)

def _load_keys_from_kms_to_file(key_types, source_key_dir):
    for key_type, (filename, num) in key_types.items():
        cmd_print('\n> Writing the %s keys to %s' % (key_type, filename))
        cmd = [ 'docker', 'exec', 'thunder-keygen', 
            'thundertool', '--noencrypt', 'getkeys', '--num-keys', str(num),
            '--key-type', key_type, '--output', filename,
            '--fs-srcdir', source_key_dir
        ]
        print(" ".join(cmd))
        subprocess.check_call(cmd)

def _prepare_genesis_comm_info_with_nodes(key_store_path, comm_info_path, r2_info_path, args):
    cmd_print('\n> Writing genesis_comm_info.json to {}'.format(comm_info_path))
    cmd = [ 'docker', 'exec', 'thunder-keygen', 
        'thundertool', '--noencrypt', 'gencomminfo', '--config', str(config.DOCKER_NODE_SETTING_FILE), '--output', comm_info_path, '--r2', r2_info_path,
        '--fs-srcdir', key_store_path
    ]
    print(" ".join(cmd))
    subprocess.check_call(cmd)

def _prepare_genesis_comm_info(key_store_path, comm_info_path, num_comm, num_proposer):
    cmd_print('\n> Writing genesis_comm_info.json to {}'.format(comm_info_path))
    cmd = [ 'docker', 'exec', 'thunder-keygen', 
        'thundertool', '--noencrypt', 'gencomminfo', '--num-prop-keys', str(num_proposer),
        '--num-keys', str(num_comm), '--output', comm_info_path, '--fs-srcdir', key_store_path
    ]
    print(" ".join(cmd))
    subprocess.check_call(cmd)

def _prepare_genesis_json(alloc_path, genesis_file_path):
    cmd_print('\n> Writing genesis.json to {}'.format(genesis_file_path))
    cmd = [ 'docker', 'exec', 'thunder-keygen', 
        'generategenesis', '--allocFile', alloc_path, '--genesisFile', genesis_file_path,
    ]
    print(" ".join(cmd))
    subprocess.check_call(cmd)   

# Reason for disabling no-member: https://github.com/PyCQA/pylint/issues/1660
# pylint: disable=missing-docstring,no-member
class StartCmd(LocalChainCommand):
    YML_PATH = config.YML_PATH
    CMD_NAME = "start"
    FAST_PATH_KEYSTORE = config.FAST_PATH_KEYSTORE
    FAST_PATH_OVERRIDE_YAML = os.path.join('config', 'fastpath_override.yaml')
    yml_builder = ""
    volumes_section_builder = ""

    def __init__(self):
        super().__init__()
        # Setup the PATH to run thundertool
        self._repo_root = os.path.join(os.getcwd(), 'bin')
        path = os.environ['PATH'].split(':')
        path.append(self._repo_root)
        os.environ['PATH'] = ':'.join(path)

    def add_subcommand(self, subparsers):
        sub = subparsers.add_parser(self.CMD_NAME,
                                    help="Starts a new local chain",
                                    formatter_class=argparse.RawTextHelpFormatter)
        sub.set_defaults(cmd=self.CMD_NAME)
        sub.add_argument('-b', '--node-config', type=str, default='local_chain/default-config.json', help='Config file to build containers and configs.')
        sub.add_argument('-img', '--docker-image', type=str, help='Docker image to use.\n'
                         'Can be image\'s name:tag or id or even remote image, for eg.\n'
                         '172.31.9.153:5000/thunder:master-latest')
        sub.add_argument('--use-existing-data', default=False,
                         help='If true, existing data dir (if any) is used directly,'
                         'otherwise it\'s deleted and recreated')
        sub.add_argument('--use-existing-key', default=False,
                         help='path to existing keys. (local_chain/.generated/keys)')
        sub.add_argument('-p', '--prefix', required=False, default='pala', help='Container prefix [pala].')
        sub.add_argument('--setup-only', help='setup docker-compose.yml and necessary files.')

    def _get_local_chain_listening(self, service, excluded=""):
        client = docker.APIClient()
        for c in client.containers():
            n = c['Names'][0]
            if service in n:
                if len(excluded) and excluded in n:
                    continue
                port = int(c['Ports'][0]['PublicPort'])
                hostname = subprocess.check_output([
                    'docker', 'inspect', '--format', '{{range .NetworkSettings.Networks}}{{index .Aliases 0}}{{end}}', n
                ]).decode().strip()
                return '{}:{}'.format(hostname, port)
        return None

    def run(self, args):
        """ Starts local chain.
        Creates new docker image if none is specified in command line.
        """
        client = docker.from_env()

        config.GENERATED_DIR.mkdir(exist_ok=True)


        if args.node_config:
            with open(args.node_config) as f:
                args.nodes = json.load(f)

            args.num_proposer= sum(1 for n in args.nodes if 'proposer' in n['role'])
            args.num_comm = sum(1 for n in args.nodes if 'voter' in n['role'])
            args.num_full = sum(1 for n in args.nodes if 'fullnode' in n['role'])
            args.has_r2 = sum(1 for n in args.nodes if 'r2proposer' in n['role']) > 0
            args.num_keys_required = sum(1 for n in args.nodes if {'proposer', 'voter', 'r2proposer' }.intersection(n['role']))

            subprocess.check_call(['cp', args.node_config, config.NODE_SETTING_FILE])

        # Clean old data and logs docker volumes, unless --use-existing-data is set.
        if not args.use_existing_data:
            self._clean_setup(args.prefix)


        # Create new docker image if none specified
        if args.docker_image is None:
            args.docker_image = build_docker_image()
            cmd_print('>> Using docker image: %s\n' % args.docker_image)

        #
        # Step 1: Generate keys. Also generate the genesis comm info for Pala.
        #
        subprocess.check_call(
            ['docker', 'run', '-tid', '--entrypoint', '/bin/sh', 
                '-v', str(config.GENERATED_DIR)+':/.generated',
                '-v', str(config.CONFIG_DIR)+':/config',
                '--name', 'thunder-keygen', 'thunder'])
        if args.use_existing_key == False:
            shutil.rmtree(str(config.FAST_PATH_KEYSTORE), ignore_errors=True)
            os.makedirs(str(config.FAST_PATH_KEYSTORE), exist_ok=True)            
            _generate_all_keys_to_fs(args.num_keys_required, config.DOCKER_FAST_PATH_KEYSTORE)

        key_paths = get_key_paths(config.DOCKER_GENERATED_DIR)
        comm_info_path, r2_info_path = self._generate_keys(args, key_paths)
        
        #
        # Step 2: Generate the docker-compose.yml and the corresponding config files.
        #
        cmd_print('> Speeding up chain data setup with genesis.json')
        args.genesis_file_path = os.path.join(config.GENERATED_DIR, 'genesis.json')
        self.setup_chain_data(args.num_comm, get_key_paths(config.GENERATED_DIR), config.GENERATED_DIR)
        _prepare_genesis_json(os.path.join(config.DOCKER_GENERATED_DIR, 'alloc.json'), os.path.join(config.DOCKER_GENERATED_DIR, 'genesis.json'))

        yml_content = self._build_docker_compose_yml(args, comm_info_path, r2_info_path)

        if self.YML_PATH.exists():
            self.YML_PATH.unlink()    # Delete old docker-compose.yml file
        self.YML_PATH.write_text(yml_content)

        subprocess.check_call(['docker', 'rm', '-f', 'thunder-keygen'])    
        
        if args.setup_only:
            cmd_print('> Setting up docker compose only. Done.')
            return

        #
        # Step 3: Start docker services
        #
        network = utils.get_docker_network()
        if network is None:
            client.networks.create(config.DOCKER_NETWORK, attachable=True)
        subprocess.check_call(config.DOCKER_COMPOSE_CMD + ['-p', args.prefix, 'up', '--build', '-d'])

        # Wait for chain RPC to become ready and then set up the stake-in accounts.
        chain_status = PalaStatus()
        chain_status.wait_till_rpc_ready(self)

        if args.use_existing_data:
            cmd_print('> Use existing data. Skip the transfers.')
            return

    def _clean_setup(self, prefix):
        _clean_data_volumes(prefix)

    def _prepare_keys(self, fast_path_key_dir, num_comm, key_paths):
        # Keys for fast-path
        #
        # Load the proposing/voting/stake-in keys.
        # The output file will be used after the chain starts.
        key_types = {
            'stakein': (key_paths._stake_in_key_output, num_comm),
            'vote': (key_paths._voting_key_output, num_comm)
        }
        _load_keys_from_kms_to_file(key_types, fast_path_key_dir)


    def _generate_keys(self, args, key_paths):
        self._prepare_keys(str(config.DOCKER_FAST_PATH_KEYSTORE), args.num_keys_required, key_paths)

        key_store_path = str(config.DOCKER_FAST_PATH_KEYSTORE)
        comm_info_path = os.path.join(key_store_path, 'genesis_comm_info.json')
        r2_info_path = os.path.join(key_store_path, 'r2_comm_info.json')
        if args.nodes:
            _prepare_genesis_comm_info_with_nodes(key_store_path, comm_info_path, r2_info_path, args)
        else:
            _prepare_genesis_comm_info(key_store_path, comm_info_path, args.num_comm, args.num_proposer)
        return os.path.join(config.FAST_PATH_KEYSTORE, 'genesis_comm_info.json'), os.path.join(config.FAST_PATH_KEYSTORE, 'r2_comm_info.json')

    def _build_docker_compose_yml(self, args, comm_info_path, r2_info_path):
        """ :return Content for auto-generated docker-compose.yml file """
        hardfork_yaml = 'hardfork.yaml'

        hardfork_path = os.path.join(config.CONFIG_DIR, hardfork_yaml)

        builder = docker_compose_builder.Builder(
            args.docker_image, #image
            comm_info_path, #genesis_comm_info_path
            config.GENERATED_DIR, #override_config_dir
            args.genesis_file_path, #fastpath_genesis_json_path
            os.path.join(config.CONFIG_DIR, 'hardfork.yaml'),  #fastpath_hardfork_yaml_path
            os.path.join(config.CONFIG_DIR, 'thunder.yaml'), #fastpath_thunder_yaml_path
            r2_info_path, #r2_comm_info_path
        )

        key_dir = str(self.FAST_PATH_KEYSTORE)

        # NOTE: the key id matches thundertool's usage. See GetKeyIDsForFS() and GetKeyIDsForAWS()
        # in keymanager/utils.go. It'd be better to generate key ids in the local chain
        # and pass ids to thundertool and the docker-compose builder.
        for i, n in enumerate(args.nodes):
            if {'proposer', 'voter', 'r2proposer'}.intersection(n['role']):
                n['voting_key_id'] = 'vote%d' % i
                n['stakein_key_id'] = 'stakein%d' % i

        for n in args.nodes:
            n['key_store_path'] = key_dir
        return builder.build(args.nodes, config.DOCKER_NETWORK)
