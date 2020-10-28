# -*- coding: utf-8 -*-
# Copyright 2019 Telefónica Soluciones de Informática y Comunicaciones de España, S.A.U.
# PROJECT: VCD Inventory
#
# This software and / or computer program has been developed by Telefónica Soluciones
# de Informática y Comunicaciones de España, S.A.U (hereinafter TSOL) and is protected
# as copyright by the applicable legislation on intellectual property.
#
# It belongs to TSOL, and / or its licensors, the exclusive rights of reproduction,
# distribution, public communication and transformation, and any economic right on it,
# all without prejudice of the moral rights of the authors mentioned above. It is expressly
# forbidden to decompile, disassemble, reverse engineer, sublicense or otherwise transmit
# by any means, translate or create derivative works of the software and / or computer
# programs, and perform with respect to all or part of such programs, any type of exploitation.
#
# Any use of all or part of the software and / or computer program will require the
# express written consent of TSOL. In all cases, it will be necessary to make
# an express reference to TSOL ownership in the software and / or computer
# program.
#
# Non-fulfillment of the provisions set forth herein and, in general, any violation of
# the peaceful possession and ownership of these rights will be prosecuted by the means
# provided in both Spanish and international law. TSOL reserves any civil or
# criminal actions it may exercise to protect its rights.
''' vCloud Director Inventory Source '''

from __future__ import (absolute_import, division, print_function)

#pylint: disable=invalid-name
__metaclass__ = type

DOCUMENTATION = '''
name: vcd
plugin_type: inventory
short_description: vCloud Director Inventory Source
author:
  - Rafael Rivero
description:
  - Get virtual machines as inventory hosts from vCloud Director environment.
  - Uses any file which ends with vcd.yml, vcd.yaml, vdc.yaml, or vdc.yaml as a YAML configuration file.
  - The inventory_hostname is always the 'vApp Name' and 'Name' of the virtual machine. vApp name is added as VMware allows virtual machines with the same name.
extends_documentation_fragment:
  - inventory_cache
  - constructed
requirements:
  - "Python >= 2.7"
  - "pyvcloud"
options:
  host:
    description: vCloud director Host server name.
    required: True
    env:
      - name: VCLOUD_HOST
  validate_certs:
    description:
      - Allows connection when SSL certificates are not valid. Set to C(false) when certificates are not trusted.
    default: True
    type: boolean
    env:
      - name: VCLOUD_VALIDATE_CERTS
  username:
    description: Name of vCloud user.
    required: True
    env:
      - name: VCLOUD_USERNAME
  password:
    description: Password of vCloud user.
    required: True
    env:
      - name: VCLOUD_PASSWORD
  org:
    description: Organization name.
    required: True
    env:
      - name: VCLOUD_ORG
  vdc:
    description: Name of the VDC.
    required: True
    env:
      - name: VCLOUD_VDC
  api_version:
    description: API version to use
    default: "30.0"
    env:
      - name: VCLOUD_API_VERSION
  mgmt_nic:
    description: Index of the management NIC (in case each VM has many NICs)
    type: int
    default: 0
    env:
      - name: VCLOUD_MGMT_NIC
  log_file:
    description: Name of log file.
    default: "pyvcloud.log"
    env:
      - name: VCLOUD_LOG_FILE
  only_on:
    description: Only return VMs that are on.
    type: bool
    default: False
    env:
      - name: VCLOUD_ONLY_ON
  only_prefix:
    description: Only read vApps starting with this prefix.
    type: string
    default: ""
    env:
      - name: VCLOUD_ONLY_PREFIX
  ansible_property:
    description:
    - Name of the guest_property used to store ansible group metadata.
    - This value takes precedence over ansible_meta.
    type: string
    default: ansible_host_groups
    env:
      - name: VCLOUD_ANSIBLE_PROPERTY
  ansible_meta:
    description:
    - Name of the metadata field used to store ansible group metadata.
    type: string
    default: ansible_host_groups
    env:
      - name: VCLOUD_ANSIBLE_META
  ansible_meta_vars:
    description:
    - Name of the metadata field used to store ansible host vars.
    type: string
    default: ansible_host_vars
    env:
      - name: VCLOUD_ANSIBLE_META_VARS
  check_dnat:
    description: True to scan edge routers for DNATs to port 22 of VMs
    type: bool
    default: True
    env:
      - name: VCLOUD_CHECK_DNAT
  compose_names:
    description: True if there might be several VMs with the same name in different vApps
    type: bool
    default: True
    env:
      - name: VCLOUD_COMPOSE_NAMES
  threads:
    description: Number of threads to collect info simultaneously
    type: int
    default: 16
    env:
      - name: VCLOUD_THREADS
  replace_dash:
    description: Replace dash with underscore in group names
    type: bool
    default: true
    env:
      - name: VCLOUD_REPLACE_DASH
'''

EXAMPLES = '''
# Sample configuration file for vCloud dynamic inventory
plugin: vcd
host: "vcd.host.name"
validate_certs: true
org: "my_org"
vdc: "my_vdc"
username: "my_username"
password: "my_password"    plugin: vmware_vm_inventory
api_version: "30.0"
mgmt_nic: 0
log_file: "pyvcloud.log"
check_dnat: true
threads: 16
replace_dash: false
ansible_meta: ansible_host_groups
ansible_meta_vars: ansible_host_vars
ansible_property: ansible_host_groups
'''

# pylint: disable=wrong-import-position
from multiprocessing.pool import ThreadPool
from itertools import chain
from collections import defaultdict, namedtuple

from ansible.plugins.inventory import BaseInventoryPlugin, Constructable, Cacheable
from ansible.errors import AnsibleParserError

try:
    from pyvcloud.vcd.client import FenceMode
    from pyvcloud.vcd.client import BasicLoginCredentials
    from pyvcloud.vcd.client import Client
    from pyvcloud.vcd.client import EntityType
    from pyvcloud.vcd.client import NSMAP
    from pyvcloud.vcd.org import Org
    from pyvcloud.vcd.vdc import VDC
    from pyvcloud.vcd.vapp import VApp
    from pyvcloud.vcd.vm import VM
    from pyvcloud.vcd.metadata import Metadata
    from pyvcloud.vcd.gateway import Gateway
    from pyvcloud.vcd.exceptions import AccessForbiddenException
    import urllib3
    HAS_PYVCLOUD = True
except ImportError:
    HAS_PYVCLOUD = False


class InventoryModule(BaseInventoryPlugin, Constructable, Cacheable):
    """Implements Ansible inventory module for vCD"""

    NAME = 'vcd'

    @staticmethod
    def check_requirements():
        ''' Check all requirements for this inventory are satisified '''
        if not HAS_PYVCLOUD:
            raise AnsibleParserError(
                'Please install "pyvcloud" Python module as this is required'
                ' for VMware vCloud dynamic inventory plugin.')

    def verify_file(self, path):
        ''' Return true/false if this is possibly a valid file for this plugin to consume '''
        valid = False
        if super(InventoryModule, self).verify_file(path):
            # base class verifies that file exists and is readable by current user
            if path.endswith(('vcd.yaml', 'vcd.yml', 'vdc.yaml', 'vdc.yml')):
                valid = True
        return valid

    def parse(self, inventory, loader, path, cache=True):
        ''' Parse the inventory file '''
        # call base method to ensure properties are available for use with other helper methods
        super(InventoryModule, self).parse(inventory, loader, path, cache)
        InventoryModule.check_requirements()

        self._consume_options(self._read_config_data(path))
        cache_key = self.get_cache_key(path)
        use_cache = self.get_option('cache') and cache

        # attempt to read the cache if inventory isn't being refreshed
        # and the user has caching enabled
        try:
            data = self._cache[cache_key] if use_cache else None
        except KeyError:
            # This occurs if the cache_key is not in the cache or if
            # the cache_key expired, so the cache needs to be updated
            data = None

        if data is None:
            data = self.get_inventory()
            if use_cache:
                self._cache[cache_key] = data

        self.populate(inventory, data)

    def populate(self, inventory, results):
        ''' Populate inventory from inventory or cache '''
        groups = results['groups']
        hosts = results['hosts']
        attribs = results['attribs']

        # We will do the dash-replacement here so that it can be changed
        # without reloading the cache
        replace_dash = self.get_option('replace_dash')

        for group in set(chain(groups.keys(), hosts.keys())):
            if group != 'all':
                if replace_dash:
                    group = group.replace('-', '_')
                inventory.add_group(group)

        for parent, children in groups.items():
            for child in children:
                if replace_dash:
                    parent = parent.replace('-', '_')
                    child = child.replace('-', '_')
                inventory.add_child(parent, child)

        for group, fullnames in hosts.items():
            for fullname in fullnames:
                if replace_dash:
                    group = group.replace('-', '_')
                inventory.add_host(fullname)
                for key, val in attribs[fullname].items():
                    inventory.set_variable(fullname, key, val)
                # Beware when group name matches host name...
                if group != fullname:
                    inventory.add_child(group, fullname)

    def get_inventory(self):
        ''' Get full inventory from vCD '''

        groups = defaultdict(dict)
        hosts = defaultdict(list)
        attribs = dict()

        compose_names = self.get_option('compose_names')
        #pylint: disable=invalid-name
        with ThreadPool(self.get_option('threads')) as pool:
            vms = self.get_vms(pool)

        for vm in vms:
            fullname, vappname = vm.inventory_name, vm.vapp_name
            if compose_names:
                fullname = "{}_{}".format(vm.vapp_name, vm.inventory_name)
            attribs[fullname] = {'vcd_vapp_name': vappname}

            # Group relationships, from comma-separated metadata
            glist = (x.strip() for x in (vm.groups or "").split(','))
            glist = tuple(x for x in glist if x != "")
            for parent, child in zip(('all', ) + glist, glist):
                groups[parent][child] = None

            # List of NICs of the Virtual Machine
            ip, port = vm.get_address(self.get_option('mgmt_nic'))
            if ip is None or ip == "":
                continue
          
            # If we found IP address info for this host, save it
            nic_ips = vm.get_nics()
            attribs[fullname].update({
                'ansible_host':       ip,
                'ansible_port':       port,
                'vcd_nic_fenced_ips': tuple(pair[1] for pair in nic_ips),
                'vcd_nic_ips':        tuple(pair[0] for pair in nic_ips),
                'vcd_nic_macs':       tuple(pair[2] for pair in nic_ips),
                'vcd_primary_nic':    'eth{}'.format(vm.primary_nic),
                # Map eth address to interface name
                'vcd_nic_ifnames': {
                    pair[2]: 'eth{}'.format(index)
                    for index, pair in enumerate(nic_ips)
                },
            })

            # If there are hostvars, append them.
            for kv in (vm.hostvars or "").split(","):
                parts = kv.split("=", 1)
                if len(parts) == 2:
                    k, v = parts
                    attribs[fullname][k.strip()] = v.strip()

            # Add the host to the last group in list
            lastg = glist[-1] if len(glist) > 0 else 'all'
            hosts[lastg].append(fullname)

        return {'groups': groups, 'hosts': hosts, 'attribs': attribs}

    def connect(self):
        ''' Connect to vCD, get client and Vdc '''

        validate_certs = self.get_option('validate_certs')
        if not validate_certs:
            urllib3.disable_warnings()

        client = Client(self.get_option('host'),
                        api_version=self.get_option('api_version'),
                        verify_ssl_certs=validate_certs,
                        log_file=self.get_option('log_file'),
                        log_requests=True,
                        log_headers=True,
                        log_bodies=True)
        client.set_credentials(
            BasicLoginCredentials(self.get_option('username'),
                                  self.get_option('org'),
                                  self.get_option('password')))

        org = Org(client, resource=client.get_org())
        vdc = VDC(client, resource=org.get_vdc(self.get_option('vdc')))

        return (client, vdc)

    def get_vms(self, pool):
        ''' Get list of VMs in the provided VDC '''

        client, vdc = self.connect()
        edge_rules = EdgeRules(pool, client,
                               vdc) if self.get_option('check_dnat') else None

        def _get_vapp_vms(vapp_name,
                          only_prefix=self.get_option('only_prefix')):
            ''' Enumerate all VMs in vApp '''
            try:
                vapp = VApp(client, resource=vdc.get_vapp(vapp_name))
            except:
                print("Failed to get information for vApp %s, skipping" %
                      vapp_name)
                return tuple()
            vapp_rules = VAppRules(vapp)
            return tuple(
                VMWrapper(vapp_name, resource, only_prefix, vapp_rules,
                          edge_rules) for resource in vapp.get_all_vms())

        def _get_vm_info(
                vm_item,
                only_on=self.get_option('only_on'),
                ansible_property=self.get_option('ansible_property').strip() or None,
                ansible_meta=self.get_option('ansible_meta').strip() or None,
                ansible_meta_vars=self.get_option('ansible_meta_vars').strip() or None):
            ''' Trigger query for VM metadata '''
            return vm_item.get_metadata(client, only_on, ansible_property,
                                        ansible_meta, ansible_meta_vars)

        vapp_names = [
            resource.get('name')
            for resource in vdc.list_resources(EntityType.VAPP)
        ]

        # If we get a prefix, filter the vapp list
        only_prefix = self.get_option('only_prefix')
        if only_prefix:
            vapp_names = [
                vapp_name for vapp_name in vapp_names
                if vapp_name.startswith(only_prefix)
            ]

        # This doesn't work, getting vapp VMs does not seem to be concurrent
        #vm_items = tuple(chain(*pool.map(_get_vapp_vms, vapp_names)))
        vm_items = tuple(chain(*map(_get_vapp_vms, vapp_names)))
        return tuple(vm for vm in pool.map(_get_vm_info, vm_items)
                     if vm is not None)


#pylint: disable=too-few-public-methods
class EdgeRules:
    ''' Map translated IP and port to original IP and port '''

    Rule = namedtuple('rule', ['orig_ip', 'orig_port', 'nat_ip', 'nat_port'])

    def __init__(self, pool, client, vdc):
        ''' Scan all gateways and build rule map '''
        gateways, mapping = vdc.list_edge_gateways(), defaultdict(dict)
        for rules in pool.map((lambda gw: EdgeRules._scan(client, gw)),
                              gateways):
            for rule in rules:
                mapping[rule.nat_ip][rule.nat_port] = (rule.orig_ip,
                                                       rule.orig_port)
        self.mapping = mapping

    @staticmethod
    def _scan(client, gw_resource):
        ''' Get NAT rules from a particular edge gateway '''
        gateway = Gateway(client, resource=gw_resource)
        nat_rules_resource = gateway.get_nat_rules()
        if not hasattr(nat_rules_resource.natRules, 'natRule'):
            return tuple()

        return tuple(
            EdgeRules.Rule(
                rule.originalAddress.text,
                int(rule.originalPort.text)
                    if all(x.isdigit() for x in rule.originalPort.text)
                    else rule.originalPort.text,
                rule.translatedAddress.text,
                int(rule.translatedPort.text)
                    if all(x.isdigit() for x in rule.translatedPort.text)
                    else rule.translatedPort.text
            ) for rule in nat_rules_resource.natRules.natRule
            if rule.protocol == 'tcp' and rule.action == 'dnat')

    def lookup(self, ip, port):
        ''' Lookup nat'ed IP and port, return original ip and port or None '''
        return self.mapping[ip].get(port, None)


class VAppRules:
    ''' Map VM name and nic number to nat'ed IP and port '''
    def __init__(self, vapp):
        ''' Return list of all VMs in vApp '''
        vmid_mappings = defaultdict(dict)
        resource = vapp.get_resource()

        # Explore the network config section for mappings from vmid to external IP
        network_config_section = resource.NetworkConfigSection
        for network_config in network_config_section.NetworkConfig:
            if not hasattr(network_config, 'Configuration') or not hasattr(
                    network_config.Configuration, 'FenceMode'
            ) or (network_config.Configuration.FenceMode !=
                  FenceMode.NAT_ROUTED.value) or not hasattr(
                      network_config.Configuration, 'Features') or not hasattr(
                          network_config.Configuration.Features, 'NatService'):
                # Skip bridged networks, or natRouted networks without NAT
                continue

            # Currently, only NatType == "ipTranslation" supported
            nat_service = network_config.Configuration.Features.NatService
            if nat_service.NatType.text != "ipTranslation":
                continue

            # Make sure there are translation rules
            if not hasattr(nat_service, 'NatRule'):
                continue

            for nat_rule in nat_service.NatRule:
                if not hasattr(nat_rule, "OneToOneVmRule"):
                    continue
                one_to_one = nat_rule.OneToOneVmRule
                vmid = one_to_one.VAppScopedVmId.text
                vnic = int(one_to_one.VmNicId.text)
                vmip = one_to_one.ExternalIpAddress.text
                vmid_mappings[vmid][vnic] = (vmip, 22)

        # Convert the local VM ids to VM names
        self.mapping = dict()
        if not hasattr(resource, 'Children') or not hasattr(resource.Children, 'Vm'):
            return

        for child in resource.Children.Vm:
            name = child.get('name')
            vmid = child.VAppScopedLocalId.text
            self.mapping[name] = vmid_mappings[vmid]

    def lookup(self, vm_name, nic):
        ''' Lookup nat'ed IP and port, return it or None '''
        return self.mapping[vm_name].get(nic, None)


class VMWrapper:
    ''' Wraps pyvcloud VM with some accesory methods '''
    def __init__(self, vapp_name, vm_resource, only_prefix, vapp_rules,
                 edge_rules):
        ''' Attach VM resource and NAT mappings from vApp and edges '''
        self.resource = vm_resource
        self.vapp_name = vapp_name
        #pylint: disable=invalid-name
        self.vm = vm_resource.get('name')
        # inventory_name es el nombre de la máquina sin prefijo!
        self.inventory_name = self.vm
        if only_prefix and self.vm.startswith(only_prefix):
            inventory_name = self.vm[len(only_prefix):]
            if inventory_name.startswith("-") or inventory_name.startswith(
                    "_"):
                inventory_name = inventory_name[1:]
            self.inventory_name = inventory_name
        self.vapp_nat = vapp_rules
        self.edge_nat = edge_rules
        self.nics = None
        self.primary_nic = 0
        self.groups = None
        self.hostvars = None

    @staticmethod
    def element(resource, namespace, prop):
        ''' Get a namespaced property from an XML resource '''
        attrib = '{' + NSMAP[namespace] + '}' + prop
        if hasattr(resource, attrib):
            return resource[attrib]
        return None

    @staticmethod
    def attribute(resource, namespace, attr):
        ''' Get a namespaced attribute from an XML resource '''
        return resource.get('{' + NSMAP[namespace] + '}' + attr,
                            "").strip() or None

    @staticmethod
    def subelements(resource, namespace, *path):
        ''' Get a namespaced list of properties from an XML resource '''
        prefix = '{' + NSMAP[namespace] + '}'
        for item in path:
            attrib = prefix + item
            if not hasattr(resource, attrib):
                return tuple()
            resource = resource[attrib]
        return resource

    def get_metadata(self, client, only_on, ansible_property, ansible_meta, ansible_meta_vars):
        ''' Get addresses, nats and metadata for the VM '''

        #pylint: disable=invalid-name
        vm = VM(client, resource=self.resource)
        if only_on and not vm.is_powered_on():
            return None

        try:
            self.nics = vm.list_nics()
        except:
            # The VM may not have NICs, and that causes an error in pyvcloud
            print("Failed to get NICs for VM %s in vApp %s" %
                  (self.vm, self.vapp_name))
            self.nics = tuple()
        self.groups = None

        if ansible_property is not None:
            for prop in VMWrapper.subelements(vm.get_resource(), 'ovf',
                                              'ProductSection', 'Property'):
                label = VMWrapper.element(prop, 'ovf', 'Label')
                value = VMWrapper.element(prop, 'ovf', 'Value')
                if label is not None and value is not None:
                    value_text = VMWrapper.attribute(value, "ovf", "value")
                    if label.text == ansible_property and value_text is not None:
                        self.groups = value_text
                        break

        if self.groups is not None or ansible_meta is None:
            return self

        metadata = Metadata(client, resource=vm.get_metadata())
        def get_meta(name):
            try:
                value = metadata.get_metadata_value(name)
                clean = value.TypedValue.Value.text.strip()
            except AttributeError:
                # no metadata for this host
                clean = None
            except AccessForbiddenException:
                # Couldn't read metadata! or not present
                clean = None
            return clean

        groups = get_meta(ansible_meta)
        if groups is not None and groups != "":
            self.groups = groups

        hostvars = get_meta(ansible_meta_vars)
        if hostvars is not None and hostvars != "":
            self.hostvars = hostvars

        return self

    def get_address(self, nic):
        ''' Return (ip, port) for remote access through the given NIC '''
        if len(self.nics) <= 0:
            return (None, None)

        # Check if any edge has a NAT to one of the external
        # Addresses of this VM, in the port mapped to 22

        if self.edge_nat is not None:
            for nic_idx, nic_info in enumerate(self.nics):
                ip, port = nic_info.get('ip_address', None), 22
                if ip is None:
                    continue

                local_nat = self.vapp_nat.lookup(self.vm, nic_idx)
                if local_nat is not None:
                    ip, port = local_nat

                rules_nat = self.edge_nat.lookup(ip, port)
                if rules_nat is not None:
                    return rules_nat

        # Otherwise, use the external IP address of the provided NIC

        if len(self.nics) == 1 or len(self.nics) <= nic:
            nic = 0

        ip = self.nics[nic].get('ip_address', None)
        if ip is None:
            return (None, None)

        local_nat = self.vapp_nat.lookup(self.vm, nic)
        if local_nat is not None:
            return local_nat

        # We only reach here if there is no NAT at all

        return (ip, 22)

    def get_nics(self):
        """ Return internal and fenced IP addresses for each NIC of the VM """
        result = []

        for nic_idx, nic_info in enumerate(self.nics):
            mac = nic_info.get('mac_address', None)
            ip = nic_info.get('ip_address', None)
            primary = nic_info.get('primary', False)
            fenced_ip = ip

            # Register which is the primary NIC.
            if primary:
                self.primary_nic = nic_idx

            if ip is not None:
                local_nat = self.vapp_nat.lookup(self.vm, nic_idx)
                if local_nat is not None:
                    fenced_ip = local_nat[0]

            result.append((ip, fenced_ip, mac))

        return result
