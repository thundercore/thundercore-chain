""" Execute a command in docker container of a role """
import argparse

from local_chain.local_chain_command_base import LocalChainCommand


# pylint: disable=missing-docstring
class ExecCmd(LocalChainCommand):
    CMD_NAME = "exec"

    def add_subcommand(self, subparsers):
        sub = subparsers.add_parser(self.CMD_NAME, help="Execute command in container of a role.",
                                    formatter_class=argparse.RawTextHelpFormatter)
        sub.set_defaults(cmd=self.CMD_NAME)
        sub.add_argument('role', type=str,
                         help='Name of role. For eg. accel or comm2 or full1.\n'
                              '"all" to get debug port for all roles.')
        sub.add_argument('command', type=str, help='Command to execute')

    def run(self, args):
        roles = []
        if args.role == 'all':
            roles = self.get_all_roles(auxnet=args.auxnet)
            roles.sort()
        else:
            roles.append(self.get_role(args))
        for role in roles:
            print("\nRole: %s" % role)
            print("Command: %s" % args.command)
            print("--------------------")
            output = self.exec(role, args.command)
            print(output)
