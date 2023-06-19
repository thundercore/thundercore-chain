""" Class to manage local chain """

import argparse
import os
import sys

from local_chain import config
from local_chain.commands.dive_cmd import DiveCmd
from local_chain.commands.exec_cmd import ExecCmd
from local_chain.commands.start_cmd import StartCmd
from local_chain.commands.stop_cmd import StopCmd
from local_chain.commands.restart_cmd import RestartCmd
from local_chain.commands.logs_cmd import LogsCmd
from local_chain.commands.docker_cmd import DockerCmd
from local_chain.commands.get_cmd import GetCmd

os.environ['GOPATH'] = str(config.LOCAL_CHAIN_ROOT_DIR.parent)

# pylint: disable=missing-docstring
class LocalChain:
    commands = dict()
    COMMAND_LIST = [StartCmd, StopCmd, RestartCmd, LogsCmd, ExecCmd,
                    DiveCmd, DockerCmd, GetCmd]
    parser = argparse.ArgumentParser(description="Tool to manage local chain",
                                     formatter_class=argparse.RawTextHelpFormatter)

    def __init__(self):
        subparsers = self.parser.add_subparsers(help="")
        for cmd_class in self.COMMAND_LIST:
            cmd = cmd_class()
            self.commands[cmd.CMD_NAME] = cmd
            # Initialize sub-commands in the parser
            cmd.add_subcommand(subparsers)

    def run(self, args=None):
        """ Runs the sub-command (start/stop/etc) specified in given args """
        args = self.parser.parse_args(args=args)
        if 'cmd' not in args:
            print("No command specified. See help message using -h")
            sys.exit(1)
        self.commands[args.cmd].run(args)