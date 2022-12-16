import subprocess
import logging
import json
import os
from time import sleep

import requests
from munch import munchify

logging.basicConfig(
    format="%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s",
    handlers=[
        # logging.FileHandler('log/20_import_dd.log'),
        logging.StreamHandler()
    ],
    level=logging.INFO
    # level=logging.DEBUG
)

logger = logging.getLogger(__name__)
logger.setLevel("DEBUG")


class Struct:
    def __init__(self, **entries):
        self.__dict__.update(entries)


def filter_ec2_by_name(instances, name):
    selection = [i for i in instances if name in [j.Value for j in i.Tags]]

    if len(selection) > 1:
        return selection

    if len(selection) == 0:
        raise Exception("No ec2 instance with name {}".format(name))

    return selection[0]


class Pac:
    cmd_ec2_describe_instances = """aws ec2 describe-instances"""
    cmd_ec2_describe_secutity_group = """aws ec2 describe-security-groups --group-id {}"""
    cmd_ec2_authorize_security_group = 'aws ec2 authorize-security-group-ingress --group-name {group} ' \
                                       '--ip-permissions IpProtocol=tcp,FromPort={port},ToPort={port},' \
                                       'IpRanges=[{{CidrIp={ip}/32,Description="{description}"}}]'
    cmd_ec2_revoke_security_group = "aws ec2 revoke-security-group-ingress --group-name {group} --protocol " \
                                    "tcp --port {port} --cidr {ip}/32 "
    cmd_ec2_stop_instance = "aws ec2 stop-instances --instance-ids {}"
    url_current_ip = "http://api.ipify.org/"

    def __init__(self, proxy):
        """

        :type proxy: str, the http url of the proxy, something like user:password@url:port
        """
        self.proxy = proxy
        if proxy:
            self.set_proxy()

        self.instance_name = None
        self.instances = None
        self.security_groups = None
        self.target = None

        self.pubblic_ip = self._get_current_ip()

    def inspect(self, instance_name):
        self.instance_name = instance_name
        self.get_instances()
        if len(self.instance_name) == 0:
            raise Exception("No instances with required name")

        self.target = filter_ec2_by_name(self.instances, name=self.instance_name)

        self.get_security_groups()
        self.log_infos()

    def set_proxy(self):
        os.environ["HTTP_PROXY"] = self.proxy
        os.environ["HTTPS_PROXY"] = self.proxy

    def stop_instance(self, instance_id):
        cmd = self.cmd_ec2_stop_instance.format(instance_id)
        self._run_process(cmd)
        self.log_running(update=True)

    def log_running(self, update=True):

        if update:
            self.get_instances()

        for i in self.instances:
            if i.State.Name != 'stopped':
                logging.info(
                    "Instance {:>15}, status {}, address {:>15}, type {}, sec {} {}".format(
                        i.Tags[0].Value,
                        i.State.Name,
                        [j.PrivateIpAddress for j in i.NetworkInterfaces][0] or None,
                        i.InstanceType,
                        [j.GroupId for j in i.SecurityGroups],
                        i.InstanceId
                    )
                )

    def log_infos(self, update=False):

        if update:
            self.get_security_groups()

        if not self.target:
            raise Exception("Log infos requires setting self.target")

        logging.info(
            "Instance {}, status {}, address {}, type {}, sec {}".format(
                self.instance_name,
                self.target.State.Name,
                [i.PrivateIpAddresses[0].Association.PublicIp for i in self.target.NetworkInterfaces][0] or None,
                self.target.InstanceType,
                self.target.SecurityGroups[0].GroupId,
            )
        )

        for group in self.security_groups:
            for permission in group.IpPermissions:
                port = permission.FromPort
                for address in permission.IpRanges:
                    logging.info(
                        "group {}, port {:>5}, addr {:>20} description {} {}".format(
                            group.GroupName,
                            port,
                            address.CidrIp,
                            address.get("Description", ""),
                            "<-----------" if self.pubblic_ip in address.CidrIp else "",
                        )
                    )

    def _get_current_ip(self):
        r = requests.get(self.url_current_ip)
        if r.status_code != 200:
            raise Exception(
                "Current IP cannot be optained from {}".format(self.url_current_ip)
            )
        return r.text

    def set_rule(self, group_name, port, description, address=None):

        if group_name not in [i.GroupName for i in self.security_groups]:
            raise Exception(
                "Pac refuse to set a rule for an instance other than {}".format(
                    self.instance_name
                )
            )

        cmd = self.cmd_ec2_authorize_security_group.format(
            port=port,
            description=description,
            ip=address or self.pubblic_ip,
            group=group_name,
        )
        self._run_process(cmd)
        self.log_infos(update=True)

    def unset_rule(self, group_name, port, address=None):

        if group_name not in [i.GroupName for i in self.security_groups]:
            raise Exception(
                "Pac refuse to set a rule for an instance other than {}".format(
                    self.instance_name
                )
            )

        cmd = self.cmd_ec2_revoke_security_group.format(
            port=port, ip=address or self.pubblic_ip, group=group_name
        )
        self._run_process(cmd)
        self.log_infos(update=True)

    @staticmethod
    def _run_process(cmd, cmd_description=None):
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        pipe = p.communicate()
        if p.returncode != 0:
            msg = "Command {} returns error code {}".format(
                cmd_description or cmd, p.returncode
            )
            logging.error(pipe)
            raise Exception(msg)
        if len(pipe[0]) > 0:
            return json.loads(pipe[0])
        else:
            return []

    def get_instances(self):
        body = self._run_process(
            cmd=self.cmd_ec2_describe_instances,
            cmd_description="cmd_ec2_describe_instances",
        )
        instances = [i["Instances"] for i in body["Reservations"]]
        self.instances = [munchify(i[0]) for i in instances]

    def get_security_groups(self):
        body = self._run_process(
            cmd=self.cmd_ec2_describe_secutity_group.format(
                self.target.SecurityGroups[0].GroupId
            ),
            cmd_description="cmd_ec2_describe_secutity_group",
        )
        if len(body["SecurityGroups"]) > 1:
            logging.warning(
                "Discovered {} SecurityGroups".format(len(body["SecurityGroups"]))
            )
        self.security_groups = munchify(body["SecurityGroups"])