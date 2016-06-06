# Copyright 2016 Dmitry Kireev <dmitry@kireev.co>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import os
import shutil
import threading
import re
import subprocess
import platform
import time
import nmap
import yaml
from pprint import pprint
import paramiko
import click
import logging
import socket

import atexit
import re
import time


from pyVim import connect
from pyVmomi import vmodl
from pyVmomi import vim
import ssl
import yaml

from operator import itemgetter
import socket

from jinja2 import Environment, PackageLoader,FileSystemLoader, Undefined
JINJA2_ENVIRONMENT_OPTIONS = { 'undefined' : Undefined }

logging.basicConfig()

class InventoryTamer(object):
    def __init__(self, home):
        self.defaults_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'defaults')
        self.default_templates_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'templates')

        self.home = home
        self.config_dir = os.path.join(home, '.ad')
        if not os.path.exists(self.config_dir):
            os.makedirs(self.config_dir)

        self.discovered_dir = os.path.join(home, 'discovered')
        if not os.path.exists(self.discovered_dir):
            os.makedirs(self.discovered_dir)

        self.templates_dir = os.path.join(home, 'templates')
        if not os.path.exists(self.templates_dir):
            os.makedirs(self.templates_dir)


        self.scan_target = ''


        self.credentials_file = os.path.join(self.config_dir, 'credentials.yml')
        self.os_signatures_file = os.path.join(self.config_dir, 'os_signatures.yml')

        self.verbose = False
        self.inventory = {}
        self.ansible_playbook = []
        self.credentials = []
        self.os_signatures = []
        self.discovered_inventory_file = None
        self.ansible_inventory_file = None
        self.csv_inventory_file = None
        self.md_inventory_file = None


        # Determine our default gateway for primitive "is network up?" checks
        self.default_gateway = [l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1], [[(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0]




    def init_credentials(self, force=False):
        if not os.path.exists(self.credentials_file) or force:
            shutil.copy(os.path.join(self.defaults_dir, 'credentials.yml'), self.credentials_file)
            click.secho("Created demo credentials in {home}".format(home=self.home), fg='green')
        else:
            click.secho("Credentials config file is already initialized. --force to override".format(home=self.home), fg='magenta')


    def init_os_signatures(self, force=False):
        if not os.path.exists(self.os_signatures_file) or force:
            shutil.copy(os.path.join(self.defaults_dir, 'os_signatures.yml'), self.os_signatures_file)
            click.secho("Created OS signatures in {os_signatures_file}".format(os_signatures_file=self.os_signatures_file), fg='green')
        else:
            click.secho("OS signatures config file is already initialized --force to override".format(), fg='magenta')

    def init_templates(self, force=False):
        if os.path.exists(self.templates_dir) and not len(os.listdir(self.templates_dir)) > 0 or force:
            src_files = os.listdir(self.default_templates_dir)
            for file_name in src_files:
                full_file_name = os.path.join(self.default_templates_dir, file_name)
                if os.path.isfile(full_file_name):
                    shutil.copy(full_file_name, self.templates_dir)
            click.secho("Created template files in {templates_dir}".format(templates_dir=self.templates_dir), fg='green')
        else:
            click.secho("Templates are already initialized --force to override".format(), fg='magenta')


    def load_os_signatures(self, force=False):
        os_signatures = []
        if not os.path.exists(self.os_signatures_file):
            if click.confirm("No os signatures file found. Initialize one?", default=False, abort=False, prompt_suffix=': ', show_default=True, err=False):
                self.init_os_signatures(force)
            else:
                click.secho("Can't continue without OS signatures", fg='red')
                exit(1)
        else:
            with open(self.os_signatures_file, 'r') as yaml_file:
                os_signatures = yaml.load(yaml_file.read())
                yaml_file.close()

            if len(os_signatures) > 0 and 'os_family' in os_signatures[0] and 'query' in os_signatures[0]:
                click.secho("Loaded {os_signatures_quantity} OS signatures from {os_signatures_file}".format(os_signatures_file=self.os_signatures_file, os_signatures_quantity=len(os_signatures)), fg='green')
            else:
                click.secho("Error loading OS signatures from {os_signatures_file}. Check format.".format(os_signatures_file=self.os_signatures_file), fg='red')
                exit(1)

        return os_signatures


    def load_credentials(self, force=False):
        credentials = []
        if not os.path.exists(self.credentials_file):
            if click.confirm("No credentials file found. Initialize a demo one?", default=False, abort=False, prompt_suffix=': ', show_default=True, err=False):
                self.init_credentials()
            else:
                click.secho("Can't continue without credentials", fg='red')
                exit(1)
        else:
            with open(self.credentials_file, 'r') as yaml_file:
                credentials = yaml.load(yaml_file.read())
                yaml_file.close()

            if len(credentials) > 0 and 'username' in credentials[0] and 'password' in credentials[0]:
                click.secho("Loaded {credentials_quantity} credentials from {credentials_file}".format(credentials_file=self.credentials_file, credentials_quantity=len(credentials)),fg='green')
            else:
                click.secho("Error loading credentials from {credentials_file}. Check format.".format(credentials_file=self.credentials_file),fg='red')
                exit(1)

        return credentials

    def get_ssh_cred(self, host):
        for credential in self.credentials:
            # Connect and run a basic command
            if self.verbose:
                click.secho("{host}: Trying credential ({username})".format(host=host, username=credential['username']), fg='yellow')

            result, error = self.ssh_exec(host, credential['username'], credential['password'], "uname -r")

            if not result:
                if self.verbose:
                    click.secho("{host}: Credential didn't work ({username})".format(host=host, username=credential['username']), fg='cyan')

                if not error:
                    continue
                else:
                    print(error)
                    click.secho("{host}: SSH doesn't seem to work. Stopping".format(host=host, username=credential['username']), fg='red')
                    return None, None
            else:
                break
        else:
            click.secho("Can't find credentials.", fg='red')
            return False, False

        click.secho("{host}: Found credential: ({username})".format(host=host, username=credential['username']), fg='green')
        return credential['username'], credential['password']

    def get_os(self, host, username, password):
        # Initialize some vars
        os_version = None
        major = None
        minor = None
        patch = None
        revision = None
        os_family = None


        for os_signature in self.os_signatures:
            if self.verbose:
                click.secho("Trying {query} on {hostname}".format(query=os_signature['query'], hostname=host))

            result, error = self.ssh_exec(host, username, password, os_signature['query'])
            if result and not error:
                match = re.match(os_signature['pattern'], result, re.M | re.I)

                if not match:
                    continue

                matches = match.groupdict()

                if 'major' in matches:
                    major = matches['major']

                if 'minor' in match.groupdict():
                    minor = matches['minor']

                if 'patch' in match.groupdict():
                    patch = matches['patch']

                if 'revision' in match.groupdict():
                    revision = matches['revision']

                if 'os_family' in match.groupdict():
                    os_family = matches['os_family']
                else:
                    os_family = os_signature['os_family']


                if major:
                    os_version = os_signature['version'].format(os_family=os_family, major=major, minor=minor, patch=patch, revision=revision)
                    break
            else:
                # click.secho("Error", fg='red')
                continue

        if os_version:
            return os_version, os_family
        else:
            return False, "Unknown"

    def get_host_name(self, nm, host, username, password, os_family):
        host_name = None
        if username and password:
            if os_family is not "Windows" and not "iLo":
                host_name, error = self.ssh_exec(host, username, password, 'hostname')
                if host_name:
                    host_name = host_name.rstrip("\n\r")

        if not host_name:
            if host in nm.all_hosts() and 'hostnames' in nm[host]:
                host_names = nm[host]['hostnames']

            if host_names and 'name' in host_names[0]:
                host_name = host_names[0]['name']
            else:
                return host
        return host_name

    def load_exclude_list(self, exclude_list):
        exclude_list = []
        if os.path.isfile(exclude_list):
            with open(exclude_list, 'r') as exclude_list_file:
                exlude_hosts = exclude_list_file.read().splitlines()
                exclude_list_file.close()
        return exclude_list



    def load_inventory(self):
        with open(self.discovered_inventory_file, 'r') as yaml_file:
            self.inventory = dict(yaml.load(yaml_file.read()))
            yaml_file.close()

    def save_inventory(self):
        if self.verbose:
            click.secho("Saving inventory to {inventory_file}".format(inventory_file=self.discovered_inventory_file))

        with open(self.discovered_inventory_file, 'w') as yaml_file:
            yaml_file.write(yaml.dump(self.inventory, default_flow_style=False))
            click.secho("Saved inventory to {inventory_file}".format(inventory_file=os.path.basename(self.discovered_inventory_file)), fg='green')

    def render_inventory(self, format, group=None):
        self.load_inventory()
        report_file_path = None
        if not os.path.exists(self.templates_dir) or not len(os.listdir(self.templates_dir)) > 0:
            if click.confirm("No templates found. Initialize?", default=False, abort=False, prompt_suffix=': ', show_default=True, err=False):
                self.init_templates()
            else:
                click.secho("Can't continue without template files. Run init again?", fg='red')
                exit(1)

        env = Environment(loader=FileSystemLoader(self.templates_dir))
        if format == 'ansible':
            if not os.path.exists(os.path.dirname(self.ansible_inventory_file)):
                os.makedirs(os.path.dirname(self.ansible_inventory_file))
            report_file_path = self.ansible_inventory_file

        elif format == 'csv':
            if not os.path.exists(os.path.dirname(self.csv_inventory_file)):
                os.makedirs(os.path.dirname(self.csv_inventory_file))
            report_file_path = self.csv_inventory_file

        elif format == 'csv-vmware':
            if not os.path.exists(os.path.dirname(self.csv_inventory_file)):
                os.makedirs(os.path.dirname(self.csv_inventory_file))
            report_file_path = self.csv_inventory_file

        elif format == 'md-vmware':
            if not os.path.exists(os.path.dirname(self.md_inventory_file)):
                os.makedirs(os.path.dirname(self.md_inventory_file))
            report_file_path = self.md_inventory_file


        with open(report_file_path, 'w') as report_file:
            click.secho("Renderring {inventory_file_path}".format(inventory_file_path=os.path.basename(report_file_path)))
            template = env.get_template('{format}.j2'.format(format=format))
            report_file.write(template.render(inventory=self.get_filtered_inventory(group)))
            report_file.close()


    def get_filtered_inventory(self, group):
        inventory = {}
        if group:
            for g in self.inventory:
                if g == group:
                    inventory[group] = self.inventory[g]
        else:
            inventory = self.inventory
        return inventory

    def ping(self, target):

        if self.verbose:
            click.secho("{target}: Ping?".format(target=target), fg="yellow")
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments='-sP')

        if nm.all_hosts():
            if self.verbose:
                click.secho("{target}: Pong!".format(target=target), fg="yellow")
            return True
        else:
            click.secho("{target}: ICMP response timeout.".format(target=target), fg="red")
            return False

    def get_vmware_host_info(self, host, username, password):
        click.secho("{host}: Gathering informaton about VmWare host".format(host=host))
        managed_by = None
        virtual_machines = []
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            context.verify_mode = ssl.CERT_NONE

            service_instance = connect.SmartConnect(host=host,
                                                    user=username,
                                                    pwd=password,
                                                    sslContext=context,
                                                    )

            if not service_instance:
                print("Could not connect to the specified host using specified "
                      "username and password")
                return -1

            atexit.register(connect.Disconnect, service_instance)

            content = service_instance.RetrieveContent()

            object_view = content.viewManager.CreateContainerView(content.rootFolder,
                                                                  [vim.HostSystem],
                                                                  True)
            host_list = object_view.view

            for vm_host in host_list:
                if hasattr(vm_host, 'summary') and hasattr(vm_host.summary, 'managementServerIp'):
                    managed_by = vm_host.summary.managementServerIp

            container = content.rootFolder  # starting point to look into
            viewType = [vim.VirtualMachine]  # object types to look for
            recursive = True  # whether we should look into it recursively
            containerView = content.viewManager.CreateContainerView(
                    container, viewType, recursive)

            children = containerView.view

            for child in children:
                virtual_machines.append(self.get_vm_info(child))

            vmware_host_info = {
                'managed_by': managed_by,
                'virtual_machines': virtual_machines
            }

            click.secho("{host} Found {count} virtual machines".format(host=host, count=len(virtual_machines)), fg='green')

        except vmodl.MethodFault as error:
            if error.msg:
                if self.verbose:
                    click.secho("Caught vmodl fault : " + error.msg, fg='red')
            else:
                if self.verbose:
                    click.secho("Caught vmodl fault (unknown)", fg='red')
            click.secho("{host} Can't find any virtual machines".format(host=host, count=len(virtual_machines)), fg='magenta')
            return False
        return vmware_host_info

    def get_vm_info(self, virtual_machine):
        """
        Print information for a particular virtual machine or recurse into a
        folder with depth protection
        """
        summary = virtual_machine.summary

        if summary.config.annotation:
            annotation = summary.config.annotation

        if summary.guest:
            if summary.guest.ipAddress:
                ip_address = summary.guest.ipAddress
            else:
                ip_address = None

            if summary.guest.toolsStatus:
                tools_version = summary.guest.toolsStatus
            else:
                tools_version = None

        if summary.runtime.question:
            runtime_question = summary.runtime.question.text
        else:
            runtime_question = None

        vm_info = {
            'name': str(summary.config.name),
            'template': str(summary.config.template),
            'path': str(summary.config.vmPathName),
            'guest': str(summary.config.guestFullName),
            'instance_uuid': str(summary.config.instanceUuid),
            'bios_uuid': str(summary.config.uuid),
            'annotation': str(summary.config.annotation),
            'state': str(summary.runtime.powerState),
            'ip_address': str(ip_address),
            'tools_version': str(tools_version),
            'runtime_question': str(runtime_question)
        }
        return vm_info

    def ssh_exec(self, hostname, username, password, command):
        error = None
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.banner_timeout = 10
        try:
            conn = ssh.connect(hostname, username=username, password=password, timeout=10, look_for_keys=False)

        except paramiko.AuthenticationException:
            return False, None

        except (paramiko.BadHostKeyException, paramiko.SSHException, socket.error, socket.timeout) as error:
            return False, error

        except socket.timeout as error:
            return False, error

        except socket.error:
            return False, error

        except Exception as error:
            return False, 'Unknown'

        if conn is None:
            try:
                ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(command, timeout=2)

            except paramiko.AuthenticationException:
                return False, None

            except (paramiko.BadHostKeyException, paramiko.SSHException, socket.error, socket.timeout) as error:
                return False, error

            except socket.timeout as error:
                return False, error

            except socket.error:
                return False, error

            except Exception as error:
                return False, 'Unknown'
            return ssh_stdout.read(), ssh_stderr.read()
        else:
            return False, error

    def get_login_history(self, hostname, username, password):
        if self.verbose:
            click.secho("Trying to get login history")
        result, error = self.ssh_exec(hostname, username, password, 'last')

        if not error:
            lines = result.split("\n")
            # pprint(lines)
            for line in lines:
                if line and ('wtmp' not in line):
                    pass
                    # print(line)
                    # rx = re.compile(r'(?<=-)\s+(.*?\d{4}).*?(?<=\))\s+(\d{1,3}\.\d{1,3}.*)$')
                    #
                    # date, ip = rx.search(line).group(1, 2)
                    # epoch = int(time.mktime(time.strptime(date.strip(), "%a %b %d %H:%M:%S %Y")))
                    #
                    # print(ip, epoch)

    def set_inventory_file_names(self, target, report_name=None):
        # We need to set inventory file names separately, because we do it in multiple tasks and we want to be
        # consistent + don't duplicate code
        target_prefix = target.lower().replace('/', '-').replace('\\', '-')

        self.discovered_inventory_file = os.path.join(self.discovered_dir, '{target_prefix}-discovered.yml'.format(target_prefix=target_prefix))
        self.ansible_inventory_file = os.path.join(self.home, 'inventory/{report_name}-{target_prefix}-inventory-tamer'.format(target_prefix=target_prefix, report_name=report_name))
        self.csv_inventory_file = os.path.join(self.home, '{target_prefix}-{report_name}.csv'.format(target_prefix=target_prefix, report_name=report_name))
        self.md_inventory_file = os.path.join(self.home, '{target_prefix}-{report_name}.md'.format(target_prefix=target_prefix, report_name=report_name))


    def is_root(self):
        if os.getuid() != 0:
            click.secho("I need to run as root.", fg='red')
            return False
        else:
            return True

def __repr__(self):
        return '<InventoryTamer %r>' % self.home


pass_inventory_tamer = click.make_pass_decorator(InventoryTamer)
@click.group()
@click.option('--home', envvar='INVENTORY_HOME', default='.',
              metavar='PATH', help='Changes directory where inventory will be generated.')
@click.option('--verbose', '-v', is_flag=True,
              help='Enables verbose mode.')
@click.version_option('1.0')
@click.pass_context
def cli(ctx, home, verbose):
    """inventory-tamer is a command line tool to create ansible inventory from nmap scans.
    """
    ctx.obj = InventoryTamer(os.path.abspath(home))

    if verbose:
        ctx.obj.verbose = verbose
    ctx.obj.hosts_list = []


@cli.command('scan')
@click.option('--target', '-t', default=None)
@click.option('--host-list', '-l')
@click.option('--exclude-list', '-e')
@pass_inventory_tamer
def scan(tamer, target, host_list, exclude_list):
    """
    Runs tamer
    """

    exclude_hosts = []



    tamer.credentials = tamer.load_credentials()
    tamer.os_signatures = tamer.load_os_signatures()
    tamer.scan_target = target

    if not target and not host_list:
        click.secho("Target or Host list are not specified", fg='red')
        exit(1)
    if target:
        tamer.set_inventory_file_names(target)
    else:
        tamer.set_inventory_file_names(host_list)

    # If any hosts should be excluded
    if exclude_list:
        exclude_hosts = tamer.load_exclude_list()

    username = ''
    password = ''
    tcp_ports = []

    if tamer.is_root():
        gateway = tamer.default_gateway
        if tamer.ping(gateway):
            if tamer.verbose:
                click.secho("Network connection seems to exist", fg='green')
            nm = nmap.PortScanner()

            # If list has been provided
            if host_list:
                if os.path.isfile(host_list):
                    click.secho("Found {host_list}. Starting a network scan.".format(host_list=host_list), fg="yellow")
                    nm.scan(arguments="-iL {host_list} -p 22,3389,5900,443,5988,199,80 --open".format(host_list=host_list))
                else:
                    click.secho("Can't find {list}.".format(list=list), fg="red")
                    exit(1)
            else:
                click.secho("{target}: Starting a network scan.".format(target=target), fg="yellow")
                nm.scan(hosts=target, arguments='-p 22,3389,5900,443,5988,199,80 --open')
            # if nm:

            # nm.scan(hosts=target, arguments='-O -T4')

            hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]

            if hosts_list:
                for host, status in hosts_list:
                    tcp_ports = nm[host]['tcp']
                    for port in tcp_ports:
                        tcp_ports[port].pop("cpe")
                        tcp_ports[port].pop("reason")
                        tcp_ports[port].pop("version")
                        tcp_ports[port].pop("product")
                        tcp_ports[port].pop("extrainfo")
                        tcp_ports[port].pop("conf")

                    username = None
                    password = None
                    os_version = "Unknown"
                    os_family = "Unknown"
                    vmware_host_info = None

                    click.secho("---------------- {host} ----------------".format(host=host), fg="yellow")
                    if host in exclude_hosts:
                        click.secho("{host}: excluded.")
                        continue

                    if tamer.ping(host):
                        # SSH
                        if 22 in tcp_ports and tcp_ports[22]['state'] == 'open':
                            username, password = tamer.get_ssh_cred(host)
                            if username and password:
                                os_version, os_family = tamer.get_os(host, username, password)

                                if tamer.verbose:
                                    click.secho("{host}: OS family: {os_family} ({os_version})".format(host=host, os_family=os_family, os_version=os_version), fg="cyan")
                            # elif all(port in tcp_ports for port in (22, 5900, 443, 5988, 199, 80)):
                            #     os_family = "ilo"
                                if os_family == 'VmWare':
                                    vmware_host_info = tamer.get_vmware_host_info(host, username, password)


                        # RDP
                        elif 3389 in tcp_ports and tcp_ports[3389]['state'] == 'open':
                            if tamer.verbose:
                                click.secho("{host}: OS family: Windows".format(host=host), fg="cyan")
                            os_family = 'Windows'
                            os_version = 'Windows'

                        else:
                            click.secho("{host}: No ports opened".format(host=host), fg='red')

                        host_name = tamer.get_host_name(nm, host, username, password, os_family)
                        group_name = "inventory-{os_family}".format(os_family=os_family.lower())

                        if not host_name:
                            click.secho("{host}: can't find host_name.".format(host=host), fg='red')
                        else:
                            click.secho("{host}: Hostname: {host_name}".format(host=host, host_name=host_name), fg='yellow')

                        # tamer.get_login_history(host, username, password)

                        if group_name not in tamer.inventory:
                            tamer.inventory[group_name] = []

                        # Forming inventory object:
                        tamer.inventory[group_name].append({
                            'host_name': host_name,
                            'host_ip': host,
                            'tcp_ports': tcp_ports,
                            'os_family': os_family,
                            'os_version': os_version,
                            'group_name': group_name,
                            'username': username,
                            'password': password,
                            'vmware_host_info': vmware_host_info,
                        })

                    else:
                        click.secho("{host}: down.".format(host=host), fg='red')

                # Sort by host IP
                for group, host in tamer.inventory.iteritems():
                    # print(group)
                    tamer.inventory[group] = sorted(tamer.inventory[group], key=lambda k: socket.inet_aton(k['host_ip']))
                tamer.save_inventory()

            else:
                click.secho("{target} doesn't seem to have any hosts that are up".format(target=target), fg='red')
        else:
            click.secho("Network connection seems to be down", fg='red')
            exit(1)



@cli.command()
@click.option('--name', '-n')
@click.option('--group')
@click.option('--target', '-t', default=None)
@click.option('--host-list', '-l')
@pass_inventory_tamer
def report(tamer, name, group, target, host_list):
    """
    """
    if host_list:
        target = host_list

    if target:
        tamer.scan_target = target
    else:
        click.secho("Error: target or host-list is empty")

    tamer.set_inventory_file_names(target, name)


    if os.path.isfile(tamer.discovered_inventory_file):
        if not name:
            name = 'ansible'

        tamer.render_inventory(name, group)
    else:
        click.secho("Can't find inventory file: {inventory_file}. Run scan first.".format(inventory_file=tamer.discovered_inventory_file), fg='red')
        exit(1)

@cli.command()
@click.option('--force', '-f', is_flag=True,
              help='Forces init.')
@pass_inventory_tamer
def init(tamer, force):
    """
    """

    tamer.init_credentials(force)
    tamer.init_os_signatures(force)
    tamer.init_templates(force)

def audit(tamer, csv_file):
    """
    Audit exported csv and current hosts
    """

    # TODO: load csv file of current documented hosts and run comparison against them
    pass

