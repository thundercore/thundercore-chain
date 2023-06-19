""" Dive into terminal of a given role. """
import argparse
import subprocess
import shlex

from local_chain.local_chain_command_base import (LocalChainCommand,
                                                  PalaStatus,
                                                  pala_containers_are_running,)

# pylint: disable=missing-docstring
class DiveCmd(LocalChainCommand):
    CMD_NAME = "dive"

    def add_subcommand(self, subparsers):
        sub = subparsers.add_parser(self.CMD_NAME,
                                    help='Dive into container shell session',
                                    formatter_class=argparse.RawDescriptionHelpFormatter)
        sub.set_defaults(cmd=self.CMD_NAME)
        self.add_optional_role_argument(sub)
        sub.add_argument('--printonly', action='store_true',
                         help='print the command only, do not run it')

    def run(self, args):
        chain_status = PalaStatus()
        role_str = chain_status.get_role(args.role, False)
        cont = self.find_container_by_role(role_str)
        divecmd = ['docker', 'exec',
                   '-e', 'PS1={} # '.format(role_str), # change shell prompt
                   '-it', '{:.12}'.format(cont.id), 'ash']
        if args.printonly:
            print(' '.join(shlex.quote(x) for x in divecmd))
        else:
            subprocess.check_call(divecmd)
