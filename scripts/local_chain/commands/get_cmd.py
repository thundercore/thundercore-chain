""" Copy config/data/logs from a given role. """

import argparse
import subprocess
import shlex
import os
import datetime

from local_chain.local_chain_command_base import LocalChainCommand

def getTimestamp():
    return datetime.datetime.now().strftime('%Y-%m-%d_%H%M%S')

class GetCmd(LocalChainCommand):
    CMD_NAME = "get"

    def add_subcommand(self, subparsers):
        sub = subparsers.add_parser(self.CMD_NAME,
                help="Copy chain config & data from a role.")
        sub.set_defaults(cmd=self.CMD_NAME)
        self.add_role_argument(sub)
        sub.add_argument('-o', '--output', type=str,
                help='Output directory name')

    def run(self, args):
        out_dir = 'chain_' + getTimestamp()
        if args.output:
            out_dir = args.output

        roles = []
        if args.role == 'all':
            roles = self.get_all_roles(getall=True)
        else:
            roles.append(self.get_role(args))

        os.makedirs(out_dir, exist_ok=True)

        for role in roles:
            print("Getting chain files for role {} ...".format(role))
            cont = self.find_container_by_role(role)
            os.makedirs(out_dir + "/" + role, exist_ok=True)
            for d in ['config', 'datadir', 'keystore', 'logs']:
                if d == 'keystore' and 'cdnserver' in role:
                    continue
                cpcmd = ['docker', 'cp',
                        '{:.12}:/{}'.format(cont.id, d),
                        '{}/{}/{}'.format(out_dir, role, d)]
                print('  ', ' '.join(shlex.quote(x) for x in cpcmd))
                try:
                    subprocess.check_call(cpcmd)
                except Exception as err:
                    #path not existed, ignore silently
                    pass


