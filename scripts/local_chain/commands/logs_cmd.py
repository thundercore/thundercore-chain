""" Returns path to log file of a role. """

import argparse
import os
import subprocess
import shlex

from local_chain.local_chain_command_base import LocalChainCommand

OUTPUT_DIR = "./testlogs"

# pylint: disable=missing-docstring
class LogsCmd(LocalChainCommand):
    CMD_NAME = "logs"

    def add_subcommand(self, subparsers):
        sub = subparsers.add_parser(self.CMD_NAME,
                                    help="Show file containing logs for a role\n"
                                         "***IMPORTANT NOTE***\n"
                                         "WIP: Right now these files are owned by root.\n"
                                         "So use it like: sudo tail -f `./chain logs voter_0`\n"
                                         "MacOS need to use --dump to dump logs\n",
                                    formatter_class=argparse.RawDescriptionHelpFormatter)
        sub.set_defaults(cmd=self.CMD_NAME)
        self.add_role_argument(sub)
        sub.add_argument('--dump', action='store_true',
                         help='dump logs to local disk, (may need to run with sudo)')

    def run(self, args):
        if args.dump:
            roles = []
            if args.role == 'all':
                roles = self.get_all_roles(getall=True)
            else:
                roles.append(self.get_role(args))
            if not os.path.exists(OUTPUT_DIR):
                os.mkdir(OUTPUT_DIR)
            for role in roles:
                if 'webserver' in role:
                    # The webserver doesn't have thunder.log. Skip it.
                    continue
                print("\nDumping log for role: %s using" % role)
                cont = self.find_container_by_role(role)
                cpcmd = ['docker', 'cp',
                         '{:.12}:/logs/thunder.log'.format(cont.id),
                         '%s/%s.log' % (OUTPUT_DIR, role)]
                print(' '.join(shlex.quote(x) for x in cpcmd))
                try:
                    subprocess.check_call(cpcmd)
                except Exception as err:
                    print('Failed to copy the log: %s' % err)
        else:
            volumes = self.docker_client.volumes.list()
            role_logs_volume = "%s_logs" % self.get_role(args)
            for vol in volumes:
                # Noticed that jenkins use 'local_chain' as prefix but my local machine was using
                # 'localchain', so not doing full string match
                if vol.attrs['Labels']['com.docker.compose.volume'] == role_logs_volume:
                    print("%s/thunder.log" % vol.attrs["Mountpoint"])
                    return
            print("Could not find volume: %s" % role_logs_volume)
