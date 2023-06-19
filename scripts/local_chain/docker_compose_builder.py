from collections import OrderedDict
import errno
import os
import yaml


_container_paths = {
    'data_dir': '/datadir',
    'genesis_comm_info': '/config/fastpath/pala/genesis_comm_info.json',
    'fs_key_store': '/keystore',
    'fastpath_config': '/config/fastpath/pala/',
    'genesis_config': '/config/fastpath/pala/genesis.json',
    'r2_comm_info': '/config/fastpath/pala/r2_comm_info.json',
}

RPC_HTTP_PORT = 8545
RPC_WS_PORT = 8546

class OrderedDumper(yaml.Dumper):
    pass

def _dict_representer(dumper, data):
    return dumper.represent_mapping(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        data.items())


OrderedDumper.add_representer(OrderedDict, _dict_representer)

# docker-compose config.
class _ServiceConfig(object):
    def __init__(self, image, genesis_comm_info, hardfork_yaml_path, thunder_yaml_path, name):
        self._data = OrderedDict()
        self._data['image'] = image
        self._data['security_opt'] = ['seccomp:unconfined']
        self._data['volumes'] = []
        self._data['environment'] = []
        self._data['restart'] = 'always'
        self._data['command'] = ['/entrypoint.sh', '--configPath', _container_paths['fastpath_config']]

        self._volumes = []
        self._add_volume('%s_datadir' % name, _container_paths['data_dir'])
        self._add_volume('%s_logs' % name, '/logs')
        self._add_volume_binding(genesis_comm_info, _container_paths['genesis_comm_info'])
        default_configs = ((hardfork_yaml_path, 'hardfork.yaml'),
                           (thunder_yaml_path, 'thunder.yaml'),)
        for (path, basename) in default_configs:
            self._add_volume_binding(path, os.path.join(_container_paths['fastpath_config'],
                                                        basename))

    def set_genesis_config_path(self, path):
        self._add_volume_binding(path, os.path.join(_container_paths['fastpath_config'],
                                                    'genesis.json'))

    def set_key_store_path(self, path):
        self._add_volume_binding(path, _container_paths['fs_key_store'])

    def set_override_config(self, path):

        self._add_volume_binding(path, os.path.join(_container_paths['fastpath_config'],
                                                    'override.yaml'))

    def set_extra_comm_info(self, path):
        # TODO (thunder): maybe there would be further comminfo
        self._add_volume_binding(path, _container_paths['r2_comm_info'])

    def open_port(self, host_port, container_port):
        key = 'ports'
        if key not in self._data:
            self._data[key] = []
        self._data[key].append('%s:%s' % (host_port, container_port))

    def get_config(self):
        return self._data

    def get_volumes(self):
        return self._volumes

    def _add_volume(self, source, target):
        self._data['volumes'].append('%s:%s' % (source, target))
        self._volumes.append(source)

    def _add_volume_binding(self, source, target):
        self._data['volumes'].append({
            'type': 'bind',
            'source': source,
            'target': target,
        })


# remove_port("localhost:8888") -> "localhost"
def remove_port(hostname_port):
    i = hostname_port.find(':')
    if i == -1:
        return hostname_port
    return hostname_port[:i]

class Builder(object):
    '''
    A docker-compose.yml builder
    '''
    def __init__(self, image, genesis_comm_info_path,
                 override_config_dir, fastpath_genesis_json_path,
                 fastpath_hardfork_yaml_path, fastpath_thunder_yaml_path,
                 r2_comm_info_path):
        self._image = image
        self._genesis_comm_info_path = genesis_comm_info_path
        self._override_config_dir = override_config_dir
        self._fastpath_genesis_json_path = fastpath_genesis_json_path
        self._fastpath_hardfork_yaml_path = fastpath_hardfork_yaml_path
        self._fastpath_thunder_yaml_path = fastpath_thunder_yaml_path
        self._r2_comm_info_path = r2_comm_info_path
        try:
            os.makedirs(self._override_config_dir)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise

    def build(self, nodes, network):
        # TODO(thunder): support auxnet when yell/alive is required.
        cfg = OrderedDict()
        cfg['version'] = '3.2'
        cfg['services'] = OrderedDict()
        cfg['volumes'] = OrderedDict()
        cfg['networks'] = {
            'default': {
                'external': {
                    'name': network,
                }
            }
        }

        role_names = ['proposer', 'voter', 'fullnode', 'bootnode']
        node_names = {
            r: [ n['name'] for n in nodes if r in n['role']] for r in role_names
        }

        has_r2 = sum(1 for n in nodes if 'r2proposer' in n['role']) > 0
        n_full = 0
        for node in nodes:
            name = node['name']
            role = node['role']
            c  = _ServiceConfig(self._image, self._genesis_comm_info_path,
                                self._fastpath_hardfork_yaml_path,
                                self._fastpath_thunder_yaml_path,
                                name)
            bootnodes = [n['name']+':8888' for n in nodes if 'bootnode' in n['role']]
            override_config_path = self._generate_override_config(
                node, node_names, bootnodes, has_r2)

            if has_r2:
                c.set_extra_comm_info(self._r2_comm_info_path)

            c.set_override_config(override_config_path)
            if self._fastpath_genesis_json_path:
                c.set_genesis_config_path(self._fastpath_genesis_json_path)
            c.set_key_store_path(node['key_store_path'])
            if 'fullnode' in role:
                c.open_port(RPC_HTTP_PORT + n_full * 10, RPC_HTTP_PORT)  # Ethereum RPC using HTTP
                c.open_port(RPC_WS_PORT + n_full * 10, RPC_WS_PORT)  # Ethereum RPC using WebSocket
                n_full += 1

            cfg['services'][name] = c.get_config()
            for v in c.get_volumes():
                cfg['volumes'][v] = {}

        # Return result.
        return '# Generated by ./chain start --pala\n' + \
            yaml.dump(cfg, None, OrderedDumper, default_flow_style=False)

    def _generate_override_config(self, node, node_names, trusted_bootnodes, has_r2):
        name = node['name']
        cfg = OrderedDict()
        cfg['loggingId'] = name
        cfg['dataDir'] = _container_paths['data_dir']
        cfg['key'] = {
            'GenesisCommPath': _container_paths['genesis_comm_info'],
        }
        if has_r2:
            cfg['key']['alterCommPath'] = _container_paths['r2_comm_info']
        cfg['pala'] = OrderedDict()
        cfg['pala']['fromGenesis'] = True

        cfg['pala']['bootnode'] = OrderedDict()
        cfg['pala']['bootnode']['trusted'] = trusted_bootnodes

        cfg['rpc'] = {
            'logRequests': True,
            'http': {
                'hostname': '0.0.0.0',
                'port': RPC_HTTP_PORT,
            },
            'ws': {
                'hostname': '0.0.0.0',
                'port': RPC_WS_PORT,
            },
        }
        cfg['chain'] = OrderedDict()
        if self._fastpath_genesis_json_path:
            cfg['chain']['genesis'] = _container_paths['genesis_config']
        cfg['proposer'] = {
            # Containers connect to each other using the container name.
            'bindingIPPort': '%s:8888' % node['name'],
        }
        if 'proposer' in node['role'] or 'voter' in node['role'] or 'r2proposer' in node['role']:
            cfg['key']['KeyStorePath'] = _container_paths['fs_key_store']
            cfg['key']['VotingKeyId'] = node['voting_key_id']
            cfg['key']['StakeInKeyId'] = node['stakein_key_id']
            cfg['key']['ProposingKeyId'] = node['voting_key_id']
        if 'proposer' in node['role'] or 'r2proposer' in node['role']:
            cfg['pala']['isProposer'] = True
        if 'voter' in node['role']:
            cfg['pala']['isVoter'] = True
            cfg['bidder'] = {
                'rpcUrl': 'ws://{}:{}'.format(node_names['fullnode'][0], RPC_WS_PORT),
            }
        if 'bootnode' in node['role']:
            port = 8888
            cfg['pala']['bootnode']['port'] = port
            cfg['pala']['bootnode']['ownPublicAddress'] = node['name']
        if 'fullnode' in node['role']:
            cfg['pala']['isFullNode'] = True
            cfg['rpc']['logs'] = {
                'BlockRange': 86400
            }
        path = os.path.abspath(
            os.path.join(self._override_config_dir, 'override_%s.yaml' % name))
        with open(path, 'w') as fw:
            fw.write(yaml.dump(cfg, None, OrderedDumper, default_flow_style=False))
        return path


if __name__ == '__main__':
    # Example of usage.
    builder = Builder(
        '085892847382.dkr.ecr.us-west-2.amazonaws.com/dev/thunder:branch-c7c396a0',
        '0x9A78d67096bA0c7C1bCdc0a8742649Bc399119c0',
        '/path/to/local_chain/pala-checkpoint2/keys/fastpath/keystore/genesis_comm_info.json',
        'localchain/tmp2',
    )
    proposers = [{
        'role': 'proposer',
        'name': 'proposer_0',
        'key_store_path': '/path/to/local_chain/pala-checkpoint2/keys/fastpath/keystore/accel_0',
    }]
    voters = [{
        'role': 'voter',
        'name': 'voter_0',
        'key_store_path': '/path/to/local_chain/pala-checkpoint2/keys/fastpath/keystore/comm_0',
    }]
    bootnodes = [{
    }]
    print(builder.build(proposers, voters))
