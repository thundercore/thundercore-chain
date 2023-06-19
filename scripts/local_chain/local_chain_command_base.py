""" Base class for commands """
from abc import ABCMeta, abstractmethod
import time
import json
import sys
import os
import shutil
import urllib
import urllib.error
import subprocess
import tempfile
import argparse
import http.client

import docker
import yaml

from local_chain import accounts
from local_chain import config

def cmd_print(m, newline=True):
    sys.stderr.write(m)
    if newline:
        sys.stderr.write('\n')

class NoResponseError(Exception):
    pass

class KeyOutputPaths:
    'collection of file system paths for key files'
    def __init__(self, dir_path):
        self._fastpath_proposing_key_output = os.path.join(
            dir_path, 'fastpath_proposal_keys.json')
        self._slowpath_proposing_key_output = os.path.join(
            dir_path, 'slowpath_proposal_keys.json')
        self._stake_in_key_output = os.path.join(dir_path, 'stakein_keys.json')
        self._voting_key_output = os.path.join(dir_path, 'vote_keys.json')

def get_key_paths(path):
    return KeyOutputPaths(path)

def _get_role(role, accel_role, is_auxnet):
    assert((role is not None) or (accel_role is not None))
    if role is None:
        return accel_role
    if is_auxnet:
        return "%s_%s" % (config.AUXNET_NAME, role)
    else:
        return role

class LocalChainCommand(metaclass=ABCMeta):
    """ Base class for local chain commands. """
    docker_client = docker.from_env()
    DEBUG_PORT = 9000

    @abstractmethod
    def add_subcommand(self, subparsers):
        """ Add parser for subcommand """

    @abstractmethod
    def run(self, args):
        """ Runs the sub command """

    def add_optional_role_argument(self, parser):
        return self._add_role_argument(parser, is_optional=True)

    def add_role_argument(self, parser):
        return self._add_role_argument(parser, is_optional=False)

    def _add_role_argument(self, parser, is_optional):
        """ Adds params for specifying role and fast-path/aux-net. """
        if is_optional:
            nargs = '?'
        else:
            nargs = None
        parser.add_argument('role', default=None, nargs=nargs, type=str,
                            help='Role name. For eg. proposer_0, accel_0, comm_2 or fullnode_0')

    @staticmethod
    def get_role(args):
        """Returns name of role in command params depending on fast-path/aux-net selection """
        return _get_role(role=args.role, accel_role=None, is_auxnet=False)

    def get_all_roles(self, auxnet=False, getall=False):
        """ Returns list of names of all thunder roles running in docker containers.
        By default, returns name for fast path.
        """
        all_roles = [c.attrs['Config']['Labels']['com.docker.compose.service']
                     for c in self.docker_client.containers.list()
                     if 'com.docker.compose.service' in c.attrs['Config']['Labels']]
        if getall:
            return all_roles
        return list(filter(lambda x: config.AUXNET_NAME not in x, all_roles))

    def find_container_by_role(self, role):
        """ Returns container object for the specified role. """
        for container in self.docker_client.containers.list():
            labels = container.attrs['Config']['Labels']
            if 'com.docker.compose.service' in labels and \
                labels['com.docker.compose.service'] == role:
                return container
        raise ValueError("Role '{}' not found.".format(role))

    def exec(self, role, cmd):
        """ Executes the command on the role and returns the output of command. """
        cont = self.find_container_by_role(role)
        # doing it this way makes the pipeing (|) work properly
        mod_cmd = ['sh', '-c', cmd]
        return cont.exec_run(mod_cmd).output.decode('utf-8')

    def setup_chain_data(self, num_comm, key_paths, temp_dir):
        'Initialize chain data to the point where the chain is ready for service'
        chain_setup = ChainDataSetup()
        #
        # Step 4: Make transfers to operating accounts and deploy the vault proxy contract.
        #
        # Write the high-value account private key to a file (for use by tools/transfer.py)
        # For local chain, we assume the high-value account has a specific hard coded private key
        # This will NOT be the case in the production chain
        high_value_file_name = os.path.join(temp_dir, 'high_value_key.hex')
        cmd_print('\n> Exporting private key of high-value account to %r' % (os.path.relpath(high_value_file_name,)))
        high_value_address = accounts.GENESIS_ACCOUNT['address']
        with open(high_value_file_name, 'w') as f:
            f.write(accounts.GENESIS_ACCOUNT['privateKey'])

        # Write the low-value account to a file (for use by tools/transfer.py)
        low_value_file_name = os.path.join(temp_dir, 'low_value_key.hex')
        cmd_print('> Exporting private key of low-value account to %r' % (os.path.relpath(low_value_file_name,)))
        low_value_address = accounts.SRC_ACCOUNT['address']
        with open(low_value_file_name, 'w') as f:
            f.write(accounts.SRC_ACCOUNT['privateKey'])

        # Ensure Random TPC contract state isn't considered "empty" by transferring 1 wei to it
        cmd_print('\n> Transfering 1 ella from high-value account to RandomNumberGenerator Precompiled-Contract\n')
        try:
            chain_setup.transfer_random_tpc(high_value_file_name, high_value_address)
        except ChainSetupError as e:
            handle_chain_setup_error('Failed to transfer funds to RandomNumberGenerator Precompiled-Contract', e)

        # Prepare the low-value account by sending funds to it from the high value account above.
        # In the production chain, the high-value account key is stored in
        # the provided custody and the low-value one is stored in our local custody.
        #
        # We must create offline transactions in the air-gapped machine (custody)
        # and then send the transactions in another machine.
        # Simulate this process here. For convenience, the rest code creates
        # and sends the transaction in one step.
        value = 10**20
        cmd_print('\n> Transfering %d from high-value account to low-value account\n' % value)
        try:
            chain_setup.simulate_using_custody_to_transfer(
                high_value_file_name,
                high_value_address,
                low_value_address,
                value)
        except ChainSetupError as e:
            handle_chain_setup_error('Failed to transfer tokens from high-value to low-value account', e)

        # TODO(scottt): adjust bidder parameters to selected election algorithm
        # value mut be >= election.MinBidderStake in thunder for there to be sufficient stake
        # to start a committee.
        value_per_comm = 10**24

        # Need tx fees + stake in tokens when bidding directly.
        stakein_value = value_per_comm + 10**18
        source_file_name = high_value_file_name
        source_address = high_value_address

        chain_setup.simulate_using_custody_to_transfer_to_stake_in_accounts(
            source_file_name,
            source_address,
            key_paths._stake_in_key_output,
            stakein_value)

        chain_setup.dump_genesis(os.path.join(temp_dir, 'alloc.json'))

def _clean_data_volumes(prefix='pala'):
    """ Removes old data & log volumes. Removes old keys and generates new ones. """
    docker_client = docker.from_env()
    for vol in docker_client.volumes.list():
        if not vol.name.startswith("{}_".format(prefix)):
            continue

        # Clean old data volumes
        if vol.name.endswith("_datadir"):
            vol.remove(force=True)

        # Clean old log volumes
        if vol.name.endswith("_logs"):
            vol.remove(force=True)


def pala_containers_are_running(docker_client):
    for c in docker_client.containers.list():
        if c.name.startswith('pala_'):
            return True
    return False

def eth_get_block(url, max_wait_seconds):
    data = json.dumps({ 'jsonrpc': '2.0',
            'method': 'eth_getBlockByNumber',
            'params': ['latest', False], # latest block, header only
            'id': 1,
    }).encode('ascii')
    req = urllib.request.Request(url,
            data=data,
            headers={'Content-Type': 'application/json'},
            method='POST')

    for i in range(int(max_wait_seconds/0.2)):
        try:
            with urllib.request.urlopen(req) as res:
                s = res.read()
                d = json.loads(s)
                # '''{ "jsonrpc": "2.0",
                #      "id": 1,
                #      "result": {
                #        "difficulty": "0x1",
                #        "extraData": "0x",
                #        "gasLimit": "0x5f5e100",
                #        "gasUsed": "0x0",
                #        "hash": "0x39deadeb8dd0c3af5995b828b54f18ab7b73ff2affb0633229ab118d0624292a",
                #        "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                #        "miner": "0xc4f3c85bb93f33a485344959cf03002b63d7c4e3",
                #        "mixHash": "0x70bdb1d0066f8e3e11b8fba05a348e643695b3728d8830c7db7d3156338556c1",
                #        "nonce": "0x00000000000000aa",
                #        "number": "0x34f",
                #        "parentHash": "0xee8aa3e4a5d85554b7954680b517fcbd9f749102a45f0c692c051f849606f945",
                #        "receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
                #        "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
                #        "size": "0x1ff",
                #        "stateRoot": "0x7ffc19baf8a9bd6afa1c0cf7e9dd3e23513960efa6607104e15d74ab020f7576",
                #        "timestamp": "0x5d80e805",
                #        "totalDifficulty": "0x350",
                #        "transactions": [],
                #        "transactionsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
                #        "uncles": []
                #      }
                #    } '''
                number = int(d['result']['number'], base=0)
                if number == 0: 
                    time.sleep(0.2)
                    continue
                return number
        except (urllib.error.URLError, json.JSONDecodeError, KeyError, ValueError, http.client.RemoteDisconnected):
            time.sleep(0.2)
            continue
    return None

class ChainReadyMixIn:
    def wait_till_rpc_ready(self, local_chain_command):
        max_wait_seconds = 15.0
        now = time.time()

        url = 'http://127.0.0.1:8545'
        current_block = eth_get_block(url, max_wait_seconds)
        if current_block is None:
            raise NoResponseError('Full node of localchain not responding to RPC requests')
        else:
            cmd_print("The chain is alive after %.1fs" % (time.time() - now))    
            cmd_print("Last block number %.f" % current_block)

    @classmethod
    def get_role(cls, role, is_auxnet):
        if role is None:
            accel_role = cls.accel_role(accel_id=0, is_auxnet=is_auxnet)
        else:
            accel_role = None
        return _get_role(role=role, accel_role=accel_role, is_auxnet=is_auxnet)

def load_yml(path):
    with open(path) as f:
        return yaml.load(f, Loader=yaml.SafeLoader)

def dump_yml(data, path):
    with open(path, 'w') as f:
        yaml.dump(data, stream=f)

class PalaStatus(ChainReadyMixIn):
    PROPOSER_ROLE_PREFIX = 'proposer_'
    LEADER_ROLE_PREFIX = PROPOSER_ROLE_PREFIX

class DockerComposeYamlLayoutMixin:
    @classmethod
    def get_image_in_compose_yml(cls, compose_yml):
        role = cls.LEADER_ROLE_PREFIX + '0'
        return compose_yml['services'][role]['image']

    @classmethod
    def set_image_in_compose_yml(cls, compose_yml, value):
        for i in compose_yml['services'].values():
            i['image'] = value

def cmd_output(cmd):
    with (tempfile.TemporaryFile(mode='w+')) as tf0, (
        tempfile.TemporaryFile(mode='w+')) as tf1:
        r = subprocess.call(cmd, stdout=tf0, stderr=tf1)
        tf0.seek(0)
        tf1.seek(0)
        if r != 0:
            raise subprocess.CalledProcessError(r, cmd, None, tf1.read())
        return tf0.read()

class ChainSetupError(Exception):
    def __init__(self, msg, called_process_error):
        self.msg = msg
        self.called_process_error = called_process_error

def handle_chain_setup_error(msg, e):
    cmd_print(msg)
    cmd_print(e.msg)
    cmd_print(str(e.called_process_error))
    cmd_print(str(e.called_process_error.stderr))
    sys.exit(1)

class GenesisAllocator(object):
    def __init__(self):
        self._entries = []

    def add_entry(self, address, value):
        self._entries.append([str(address), str(value)])

    def dump(self, path):
        data = {'balances': [{'address': v[0], 'value': v[1]} for v in self._entries]}
        with open(path, 'w') as f:
            json.dump(data, f)

class ChainDataSetup:
    'Send transactions for initial chain setup'
    def __init__(self):
        self._genesis_allocator = GenesisAllocator()

    def transfer_random_tpc(self, source_key_file_name, source_address):
        random_tpc_address = '0x8cC9C2e145d3AA946502964B1B69CE3cD066A9C7'
        try:
            self.transfer(source_key_file_name, source_address, random_tpc_address, 1)
        except subprocess.CalledProcessError as e:
            raise ChainSetupError('Failed to transfer to Random Precompiled-Contract at %r' % (random_tpc_address,), e)

    def simulate_using_custody_to_transfer_to_stake_in_accounts(
            self, source_key_file_name, source_address, stake_in_json_file_name, value):
        cmd_print('\n> Transfering %d from %s to each stake-in operator account\n'
            % (value, source_address))
        addrs = []
        with open(stake_in_json_file_name) as f:
            obj = json.load(f)
            addrs = obj['Addresses']

        for addr in addrs:
            self._genesis_allocator.add_entry(addr, value)
        self._genesis_allocator.add_entry(source_address, -value * len(addrs))

    def simulate_using_custody_to_transfer(
            self, source_key_file_name, source_address, to_address, value):
        self.transfer(source_key_file_name, source_address, to_address, value)

    def transfer(self, source_key_file_name, source_address, to_address, value):
        self._genesis_allocator.add_entry(source_address, -value)
        self._genesis_allocator.add_entry(to_address, value)

    def dump_genesis(self, path):
        self._genesis_allocator.dump(path)

def json_prettys(s):
    try:
        d = json.loads(s)
    except json.JSONDecodeError:
        return ''
    return json.dumps(d, indent=2)
