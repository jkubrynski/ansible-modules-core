#!/usr/bin/python
#
# Copyright (c) 2016 Jakub Kubrynski, <jk@devskiller.com>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#

DOCUMENTATION = '''
---
module: azure_rm_loadbalancer

version_added: "2.2"

short_description: Manage Azure Load Balancers.

description:
    - Create, update and delete a load balancer address. Allows setting and updating ip configurations,
      backend pools, probes and rules.

options:
    resource_group:
        description:
            - Name of resource group with which the load balancer is associated.
        required: true
    name:
        description:
            - Name of the load balancer.
        required: true
    frontend_ip_configurations:
        description:
            - Set of frontend IP configurations.
        required: false
        default: null
        contains:
            name:
                description: Unique name for the configuration
                required: true
            public_ip_allocation_method:
                description: Allocation method for creating public IP
                required: false
                default: null
                choices:
                  - Dynamic
                  - Static
            public_ip_address_name:
                description: Name of the existing public IP
                required: false
                default: null
            private_ip_allocation_method:
                description: Allocation method for creating private IP
                required: false
                default: null
                choices:
                  - Dynamic
                  - Static
            private_ip_network_name:
                description: Name of the existing network
                required: false
                default: null
            private_ip_subnet_name:
                description: Name of the existing subnet
                required: false
                default: null
    backend_address_pools:
       description:
            - Set of backend pools.
       required: false
       default: null
       contains:
            name:
                description: Unique name for the backend pool
                required: true
    probes:
        description:
            - Set of probes.
        required: false
        default: null
        contains:
            name:
                description: Unique name for the configuration
                required: true
            protocol:
                description: Protocol for the probe
                required: false
                default: null
                choices:
                  - Http
                  - Tcp
            port:
                description: Port number to probe
                required: false
                default: null
            interval_in_seconds:
                description: Interval in seconds
                required: false
                default: null
            number_of_probes:
                description: Number of probes
                required: false
                default: null
            request_path:
                description: Request path. Should be used only with protocol=Http
                required: false
                default: null
    load_balancing_rules:
        description:
            - Set of load balancer rules.
        required: false
        default: null
        contains:
            name:
                description: Unique name for the rule
                required: true
            protocol:
                description: Protocol for the rule
                required: false
                default: null
                choices:
                  - Tcp
                  - Udp
            frontend_port:
                description: Frontend port
                required: false
                default: null
            backend_port:
                description: Backend port
                required: false
                default: null
            idle_timeout_in_minutes:
                description: Idle timeout in minutes
                required: false
                default: 4
            load_distribution:
                description: Idle timeout in minutes
                required: false
                default: Default
                choices:
                  - Default
                  - SourceIP
                  - SourceIPProtocol
            enable_floating_ip:
                description: Enable floating IP
                required: false
                default: False
            frontend_ip_configuration_name:
                description: Name of the frontend IP configuration (created in frontend_ip_configurations)
                required: true
            backend_address_pool_name:
                description: Name of the backend pool configuration (created in backend_address_pools)
                required: true
            probe_name:
                description: Name of the probe (created in probes)
                required: true
    inbound_nat_rules:
        description:
            - Set of load balancer inbound NAT rules.
        required: false
        default: null
        contains:
            name:
                description: Unique name for the NAT rule
                required: true
            protocol:
                description: Protocol for the NAT rule
                required: false
                default: null
                choices:
                  - Tcp
                  - Udp
            frontend_port:
                description: Frontend port
                required: false
                default: null
            backend_port:
                description: Backend port
                required: false
                default: null
            idle_timeout_in_minutes:
                description: Idle timeout in minutes
                required: false
                default: 4
            enable_floating_ip:
                description: Enable floating IP
                required: false
                default: False
            frontend_ip_configuration_name:
                description: Name of the frontend IP configuration (created in frontend_ip_configurations)
                required: true

extends_documentation_fragment:
    - azure
    - azure_tags

author:
    - "Jakub Kubrynski (@jkubrynski)"
'''

EXAMPLES = '''
  - name: create a load balancer
    azure_rm_loadbalancer:
      resource_group: Testing
      name: test-lb
      frontend_ip_configurations:
        - name: frontend-ip-config
          public_ip_allocation_method: Dynamic
      backend_address_pools:
        - name: backend-pool
      probes:
        - name: probe-http
          protocol: Http
          port: 80
          interval_in_seconds: 15
          number_of_probes: 4
          request_path: /index
      load_balancing_rules:
        - name: lb-rule
          protocol: Tcp
          frontend_port: 81
          backend_port: 81
          idle_timeout_in_minutes: 4
          frontend_ip_configuration_name: frontend-ip-config
          backend_address_pool_name: backend-pool
          probe_name: probe-http
          load_distribution: SourceIP
      inbound_nat_rules:
        - name: lb-nat-rule
          protocol: Tcp
          frontend_port: 82
          backend_port: 82
          idle_timeout_in_minutes: 4
          frontend_ip_configuration_name: frontend-ip-config
          enable_floating_ip: False
      tags:
          env: testing
'''

RETURN = '''
state:
    description: Facts about the current state of the object.
    returned: always
    type: dict
    sample: {
        "backend_address_pools": [{ "name": "backend-pool" }],
        "etag": "W/xxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "frontend_ip_configurations": [{
            "etag": "W/xxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "id": "/subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxx/resourceGroups/Testing/providers/Microsoft.Network/loadBalancers/test-lb/frontendIPConfigurations/frontend-ip-config",
            "name": "frontend-ip-config",
            "private_ip_allocation_method": "Dynamic",
            "provisioning_state": "Succeeded",
            "public_ip_address": { "id": "/subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxx/resourceGroups/Testing/providers/Microsoft.Network/publicIPAddresses/test-lb01" }
        }],
        "location": "westeurope",
        "probes": [{
            "etag": "W/xxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "id": "/subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxx/resourceGroups/Testing/providers/Microsoft.Network/loadBalancers/test-lb/probes/probe-http",
            "interval_in_seconds": 15,
            "name": "probe-http",
            "number_of_probes": 4,
            "port": 80,
            "protocol": "Http",
            "provisioning_state": "Succeeded",
            "request_path": "/index"
         }],
         "provisioning_state": "Succeeded",
         "tags": { "env": "testing" }
    }
'''

from ansible.module_utils.azure_rm_common import *

try:
    from msrestazure.azure_exceptions import CloudError
    from azure.mgmt.network.models import LoadBalancer, FrontendIPConfiguration, \
        BackendAddressPool, Probe, LoadBalancingRule, SubResource, InboundNatRule
except ImportError:
    # This is handled in azure_rm_common
    pass


def ip_configuration_dict(ip_configuration):
    result = dict(
        id=ip_configuration.id,
        name=ip_configuration.name,
        provisioning_state=ip_configuration.provisioning_state,
        private_ip_allocation_method=ip_configuration.private_ip_allocation_method,
        etag=ip_configuration.etag
    )
    if ip_configuration.public_ip_address:
        result['public_ip_address'] = dict(
            id=ip_configuration.public_ip_address.id,
        )
    if ip_configuration.subnet:
        result['subnet'] = dict(
            id=ip_configuration.subnet.id,
            name=ip_configuration.subnet.name
        )

    return result


def probe_dict(probe):
    result = dict(
        id=probe.id,
        name=probe.name,
        protocol=probe.protocol,
        port=probe.port,
        interval_in_seconds=probe.interval_in_seconds,
        number_of_probes=probe.number_of_probes,
        request_path=probe.request_path,
        provisioning_state=probe.provisioning_state,
        etag=probe.etag
    )
    return result


def lb_rule_dict(lb_rule):
    result = dict(
        id=lb_rule.id,
        name=lb_rule.name,
        protocol=lb_rule.protocol,
        enable_floating_ip=lb_rule.enable_floating_ip,
        frontend_port=lb_rule.frontend_port,
        backend_port=lb_rule.backend_port,
        idle_timeout_in_minutes=lb_rule.idle_timeout_in_minutes,
        load_distribution=lb_rule.load_distribution,
        frontend_ip_configuration=dict(id=lb_rule.frontend_ip_configuration.id),
        backend_address_pool=dict(id=lb_rule.backend_address_pool.id),
        probe=dict(id=lb_rule.probe.id),
        provisioning_state=lb_rule.provisioning_state,
        etag=lb_rule.etag
    )
    return result


def nat_rule_dict(nat_rule):
    result = dict(
        id=nat_rule.id,
        name=nat_rule.name,
        protocol=nat_rule.protocol,
        enable_floating_ip=nat_rule.enable_floating_ip,
        frontend_port=nat_rule.frontend_port,
        backend_port=nat_rule.backend_port,
        idle_timeout_in_minutes=nat_rule.idle_timeout_in_minutes,
        frontend_ip_configuration=dict(id=nat_rule.frontend_ip_configuration.id),
        provisioning_state=nat_rule.provisioning_state,
        etag=nat_rule.etag
    )
    return result


def lb_to_dict(lb):
    result = dict(
        location=lb.location,
        tags=lb.tags,
        provisioning_state=lb.provisioning_state,
        etag=lb.etag
    )
    result['frontend_ip_configurations'] = []
    if lb.frontend_ip_configurations:
        for frontend_ip_configuration in lb.frontend_ip_configurations:
            result['frontend_ip_configurations'].append(ip_configuration_dict(frontend_ip_configuration))
    result['backend_address_pools'] = []
    for backend_address_pool in lb.backend_address_pools:
        result['backend_address_pools'].append(dict(
            name=backend_address_pool.name
        ))
    result['probes'] = []
    if lb.probes:
        for probe in lb.probes:
            result['probes'].append(probe_dict(probe))
    result['load_balancing_rules'] = []
    if lb.load_balancing_rules:
        for rule in lb.load_balancing_rules:
            result['load_balancing_rules'].append(lb_rule_dict(rule))
    result['inbound_nat_rules'] = []
    if lb.inbound_nat_rules:
        for nat_rule in lb.inbound_nat_rules:
            result['inbound_nat_rules'].append(nat_rule_dict(nat_rule))

    return result


class AzureRMLoadBalancer(AzureRMModuleBase):
    def __init__(self):

        self.module_arg_spec = dict(
            resource_group=dict(type='str', required=True),
            name=dict(type='str', required=True),
            state=dict(type='str', default='present', choices=['present', 'absent']),
            location=dict(type='str'),
            frontend_ip_configurations=dict(type='list'),
            backend_address_pools=dict(type='list'),
            probes=dict(type='list'),
            load_balancing_rules=dict(type='list'),
            inbound_nat_rules=dict(type='list')
        )

        self.resource_group = None
        self.name = None
        self.location = None
        self.state = None
        self.tags = None
        self.frontend_ip_configurations = None
        self.backend_address_pools = None
        self.probes = None
        self.load_balancing_rules = None
        self.inbound_nat_rules = None

        self.results = dict(
            changed=False,
            state=dict()
        )

        super(AzureRMLoadBalancer, self).__init__(derived_arg_spec=self.module_arg_spec,
                                                  supports_check_mode=True)

    def exec_module(self, **kwargs):

        for key in self.module_arg_spec.keys() + ['tags']:
            setattr(self, key, kwargs[key])

        results = dict()

        resource_group = self.get_resource_group(self.resource_group)
        if not self.location:
            # Set default location
            self.location = resource_group.location

        if self.frontend_ip_configurations:
            for conf_ip in self.frontend_ip_configurations:
                if not conf_ip.get('name'):
                    self.fail("name is required - {0}".format(conf_ip))

        try:
            self.log("Fetch load balancer {0}".format(self.name))
            lb = self.network_client.load_balancers.get(self.resource_group, self.name)
            self.check_provisioning_state(lb, self.state)
            self.log("LB {0} exists".format(self.name))
            if self.state == 'present':
                results = lb_to_dict(lb)
                self.results['state'] = results
            elif self.state == 'absent':
                self.log("CHANGED: load balancer {0} exists but requested state is 'absent'".format(self.name))
        except CloudError:
            self.log('Load balancer {0} does not exist'.format(self.name))
            if self.state == 'present':
                self.log("CHANGED: lb {0} does not exist but requested state is 'present'".format(self.name))

        changed = False
        if self.state == 'present':
            if not results:
                self.log("Create new load balancer {0}".format(self.name))
                changed = True

                lb = LoadBalancer(
                    location=self.location,
                    frontend_ip_configurations=[],
                    backend_address_pools=[],
                    load_balancing_rules=[],
                    probes=[],
                    inbound_nat_rules=[],
                    tags=self.tags
                )

                if self.frontend_ip_configurations:
                    for conf_ip in self.frontend_ip_configurations:
                        ip_configuration = FrontendIPConfiguration(name=conf_ip.get('name'))
                        public_ip_address_name = conf_ip.get('public_ip_address_name')
                        public_ip_allocation_method = conf_ip.get('public_ip_allocation_method')
                        private_ip_allocation_method = conf_ip.get('private_ip_allocation_method')

                        if public_ip_address_name:
                            ip_configuration.public_ip_address = self.network_client.public_ip_addresses.get(
                                self.resource_group, public_ip_address_name)
                        elif public_ip_allocation_method:
                            ip_configuration.public_ip_address = self.create_default_pip(self.resource_group,
                                                                                         self.location, self.name,
                                                                                         public_ip_allocation_method)
                        elif private_ip_allocation_method:
                            subnet = self.network_client.subnets.get(self.resource_group,
                                                                     conf_ip.get('private_ip_network_name'),
                                                                     conf_ip.get('private_ip_subnet_name'))

                            ip_configuration.private_ip_allocation_method = private_ip_allocation_method
                            ip_configuration.subnet = subnet

                        lb.frontend_ip_configurations.append(ip_configuration)

                if self.tags:
                    lb.tags = self.tags

                if self.backend_address_pools:
                    for pool in self.backend_address_pools:
                        lb.backend_address_pools.append(BackendAddressPool(name=pool.get('name')))

                if self.probes:
                    for probe in self.probes:
                        lb.probes.append(Probe(
                            name=probe.get('name'),
                            protocol=probe.get('protocol'),
                            port=probe.get('port'),
                            interval_in_seconds=probe.get('interval_in_seconds'),
                            number_of_probes=probe.get('number_of_probes'),
                            request_path=probe.get('request_path')
                        ))

                if self.load_balancing_rules:
                    for config_rule in self.load_balancing_rules:
                        lb.load_balancing_rules.append(LoadBalancingRule(
                            name=config_rule.get('name'),
                            protocol=config_rule.get('protocol'),
                            enable_floating_ip=config_rule.get('enable_floating_ip'),
                            frontend_port=config_rule.get('frontend_port'),
                            backend_port=config_rule.get('backend_port'),
                            idle_timeout_in_minutes=config_rule.get('idle_timeout_in_minutes'),
                            load_distribution=config_rule.get('load_distribution'),
                            frontend_ip_configuration=SubResource(
                                id=self.get_fronted_ip_config_id(config_rule.get('frontend_ip_configuration_name'))),
                            backend_address_pool=SubResource(
                                id=self.get_backend_pool_id(config_rule.get('backend_address_pool_name'))),
                            probe=SubResource(id=self.get_probe_id(config_rule.get('probe_name')))
                        ))

                if self.inbound_nat_rules:
                    for config_nat_rule in self.inbound_nat_rules:
                        lb.inbound_nat_rules.append(InboundNatRule(
                            name=config_nat_rule.get('name'),
                            protocol=config_nat_rule.get('protocol'),
                            enable_floating_ip=config_nat_rule.get('enable_floating_ip'),
                            frontend_port=config_nat_rule.get('frontend_port'),
                            backend_port=config_nat_rule.get('backend_port'),
                            idle_timeout_in_minutes=config_nat_rule.get('idle_timeout_in_minutes'),
                            frontend_ip_configuration=SubResource(
                                id=self.get_fronted_ip_config_id(config_nat_rule.get('frontend_ip_configuration_name')))
                        ))

            else:
                self.log("Update load balancer {0}".format(self.name))
                update_tags, results['tags'] = self.update_tags(results['tags'])
                if update_tags:
                    changed = True

                lb = LoadBalancer(
                    location=results['location'],
                    frontend_ip_configurations=results['frontend_ip_configurations'],
                    backend_address_pools=results['backend_address_pools'],
                    load_balancing_rules=results['load_balancing_rules'],
                    probes=results['probes'],
                    inbound_nat_rules=results['inbound_nat_rules'],
                    tags=results['tags'],
                )

                if self.frontend_ip_configurations:
                    for conf_ip in self.frontend_ip_configurations:
                        ip_conf_matched = False
                        for exist_ip in lb.frontend_ip_configurations:
                            match, change = self.compare_ip_confs(exist_ip, conf_ip)
                            if change:
                                changed = True
                            if match:
                                ip_conf_matched = True

                        if not ip_conf_matched:
                            changed = True
                            lb.frontend_ip_configurations.append(conf_ip)

                if self.backend_address_pools:
                    for pool in self.backend_address_pools:
                        matched = False
                        for exist_pool in lb.backend_address_pools:
                            if exist_pool.get('name') == pool.get('name'):
                                matched = True
                        if not matched:
                            changed = True
                            lb.backend_address_pools.append(BackendAddressPool(name=pool.get('name')))

                if self.probes:
                    for probe in self.probes:
                        matched = False
                        for exist_probe in lb.probes:
                            if probe.get('name') == exist_probe['name']:
                                matched = True
                                if self.compare_probe(exist_probe, probe):
                                    changed = True

                        if not matched:
                            changed = True
                            lb.probes.append(Probe(
                                name=probe.get('name'),
                                protocol=probe.get('protocol'),
                                port=probe.get('port'),
                                interval_in_seconds=probe.get('interval_in_seconds'),
                                number_of_probes=probe.get('number_of_probes'),
                                request_path=probe.get('request_path')
                            ))

                if self.load_balancing_rules:
                    for config_rule in self.load_balancing_rules:
                        matched = False
                        for exist_rule in lb.load_balancing_rules:
                            if config_rule.get('name') == exist_rule['name']:
                                matched = True
                                if self.compare_lb_rule(exist_rule, config_rule):
                                    changed = True

                        if not matched:
                            changed = True
                            lb.load_balancing_rules.append(
                                LoadBalancingRule(name=config_rule.get('name'),
                                                  protocol=config_rule.get('protocol'),
                                                  enable_floating_ip=config_rule.get('enable_floating_ip'),
                                                  frontend_port=config_rule.get('frontend_port'),
                                                  backend_port=config_rule.get('backend_port'),
                                                  idle_timeout_in_minutes=config_rule.get('idle_timeout_in_minutes'),
                                                  load_distribution=config_rule.get('load_distribution'),
                                                  frontend_ip_configuration=SubResource(
                                                      id=self.get_fronted_ip_config_id(
                                                          config_rule.get('frontend_ip_configuration_name'))),
                                                  backend_address_pool=SubResource(id=self.get_backend_pool_id(
                                                      config_rule.get('backend_address_pool_name'))),
                                                  probe=SubResource(
                                                      id=self.get_probe_id(config_rule.get('probe_name')))))

                if self.inbound_nat_rules:
                    for config_nat_rule in self.inbound_nat_rules:
                        matched = False
                        for exist_nat_rule in lb.inbound_nat_rules:
                            if config_nat_rule.get('name') == exist_nat_rule['name']:
                                matched = True
                                if self.compare_nat_rule(exist_nat_rule, config_nat_rule):
                                    changed = True
                        if not matched:
                            changed = True
                            lb.inbound_nat_rules.append(InboundNatRule(
                                name=config_nat_rule.get('name'),
                                protocol=config_nat_rule.get('protocol'),
                                enable_floating_ip=config_nat_rule.get('enable_floating_ip'),
                                frontend_port=config_nat_rule.get('frontend_port'),
                                backend_port=config_nat_rule.get('backend_port'),
                                idle_timeout_in_minutes=config_nat_rule.get('idle_timeout_in_minutes'),
                                frontend_ip_configuration=SubResource(
                                    id=self.get_fronted_ip_config_id(
                                        config_nat_rule.get('frontend_ip_configuration_name')))
                            ))

            if not self.check_mode and changed:
                self.results['state'] = self.create_or_update_lb(lb)
            elif changed:
                self.results['state'] = lb
        elif self.state == 'absent':
            self.log('Delete load balancer {0}'.format(self.name))
            if not self.check_mode:
                self.delete_lb()

        self.results['changed'] = changed
        return self.results

    def create_or_update_lb(self, lb_params):
        try:
            poller = self.network_client.load_balancers.create_or_update(self.resource_group, self.name, lb_params)
            new_lb = self.get_poller_result(poller)
        except Exception as exc:
            self.fail("Error creating or updating {0} - {1}".format(self.name, str(exc)))
        return lb_to_dict(new_lb)

    def delete_lb(self):
        try:
            poller = self.network_client.load_balancers.delete(self.resource_group, self.name)
            self.get_poller_result(poller)
        except Exception as exc:
            self.fail("Error deleting {0} - {1}".format(self.name, str(exc)))
        # Delete returns nada. If we get here, assume that all is well.
        self.results['state']['status'] = 'Deleted'
        return True

    def compare_ip_confs(self, exist_ip, conf_ip):
        matched = False
        changed = False
        if exist_ip['name'] == conf_ip['name']:
            matched = True
            if conf_ip.get('private_ip_allocation_method'):
                if conf_ip.get('private_ip_allocation_method') != exist_ip.get('private_ip_allocation_method', None):
                    self.log("changed by private_ip_allocation_method")
                    changed = True
                    exist_ip['private_ip_allocation_method'] = conf_ip.get('private_ip_allocation_method')
            if conf_ip.get('private_ip_subnet_name'):
                subnet = self.network_client.subnets.get(self.resource_group,
                                                         conf_ip.get('private_ip_network_name'),
                                                         conf_ip.get('private_ip_subnet_name'))
                if exist_ip.get('subnet'):
                    if exist_ip['subnet']['id'] != subnet.id:
                        self.log("changed by subnet")
                        changed = True
                        exist_ip['subnet'] = subnet
            if conf_ip.get('public_ip_address_name'):
                pip = self.network_client.public_ip_addresses.get(self.resource_group,
                                                                  conf_ip.get('public_ip_address_name'))
                if exist_ip.get('public_ip_address'):
                    if exist_ip['public_ip_address']['id'] != pip.id:
                        self.log("changed by ]")
                        changed = True
                        exist_ip['public_ip_address'] = pip
        return matched, changed

    def compare_probe(self, exist_probe, conf_probe):
        changed = False
        if conf_probe.get('protocol', None) != exist_probe.get('protocol', None):
            changed = True
            exist_probe['protocol'] = conf_probe.get('protocol')
        if conf_probe.get('port', None) != exist_probe.get('port', None):
            changed = True
            exist_probe['port'] = conf_probe.get('port')
        if conf_probe.get('interval_in_seconds', None) != exist_probe.get('interval_in_seconds', None):
            changed = True
            exist_probe['interval_in_seconds'] = conf_probe.get('interval_in_seconds')
        if conf_probe.get('number_of_probes', None) != exist_probe.get('number_of_probes', None):
            changed = True
            exist_probe['number_of_probes'] = conf_probe.get('number_of_probes')
        if conf_probe.get('request_path', None) != exist_probe.get('request_path', None):
            changed = True
            exist_probe['request_path'] = conf_probe.get('request_path')

        return changed

    def compare_lb_rule(self, exist_rule, config_rule):
        changed = False
        if config_rule.get('protocol', None) != exist_rule.get('protocol', None):
            changed = True
            exist_rule['protocol'] = config_rule.get('protocol')
        if config_rule.get('enable_floating_ip'):
            if config_rule.get('enable_floating_ip') != exist_rule.get('enable_floating_ip', None):
                changed = True
                exist_rule['enable_floating_ip'] = config_rule.get('enable_floating_ip')
        if config_rule.get('frontend_port', None) != exist_rule.get('frontend_port', None):
            changed = True
            exist_rule['frontend_port'] = config_rule.get('frontend_port')
        if config_rule.get('backend_port', None) != exist_rule.get('backend_port', None):
            changed = True
            exist_rule['backend_port'] = config_rule.get('backend_port')
        if config_rule.get('idle_timeout_in_minutes', None) != exist_rule.get('idle_timeout_in_minutes', None):
            changed = True
            exist_rule['idle_timeout_in_minutes'] = config_rule.get('idle_timeout_in_minutes')
        if config_rule.get('load_distribution', None) != exist_rule.get('load_distribution', None):
            changed = True
            exist_rule['load_distribution'] = config_rule.get('load_distribution')
        config_fic_id = self.get_fronted_ip_config_id(config_rule.get('frontend_ip_configuration_name'))
        if config_fic_id != exist_rule['frontend_ip_configuration']['id']:
            changed = True
            exist_rule['frontend_ip_configuration']['id'] = config_fic_id
        config_bp_id = self.get_backend_pool_id(config_rule.get('backend_address_pool_name'))
        if config_bp_id != exist_rule['backend_address_pool']['id']:
            changed = True
            exist_rule['backend_address_pool']['id'] = config_bp_id
        config_probe_id = self.get_probe_id(config_rule.get('probe_name'))
        if config_probe_id != exist_rule['probe']['id']:
            changed = True
            exist_rule['probe']['id'] = config_probe_id

        return changed

    def compare_nat_rule(self, exist_nat_rule, config_nat_rule):
        changed = False
        if config_nat_rule.get('protocol', None) != exist_nat_rule.get('protocol', None):
            changed = True
            exist_nat_rule['protocol'] = config_nat_rule.get('protocol')
        if config_nat_rule.get('enable_floating_ip'):
            if config_nat_rule.get('enable_floating_ip') != exist_nat_rule.get('enable_floating_ip', None):
                changed = True
                exist_nat_rule['enable_floating_ip'] = config_nat_rule.get('enable_floating_ip')
        if config_nat_rule.get('frontend_port', None) != exist_nat_rule.get('frontend_port', None):
            changed = True
            exist_nat_rule['frontend_port'] = config_nat_rule.get('frontend_port')
        if config_nat_rule.get('backend_port', None) != exist_nat_rule.get('backend_port', None):
            changed = True
            exist_nat_rule['backend_port'] = config_nat_rule.get('backend_port')
        if config_nat_rule.get('idle_timeout_in_minutes', None) != exist_nat_rule.get('idle_timeout_in_minutes', None):
            changed = True
            exist_nat_rule['idle_timeout_in_minutes'] = config_nat_rule.get('idle_timeout_in_minutes')
        config_fic_id = self.get_fronted_ip_config_id(config_nat_rule.get('frontend_ip_configuration_name'))
        if config_fic_id != exist_nat_rule['frontend_ip_configuration']['id']:
            changed = True
            exist_nat_rule['frontend_ip_configuration']['id'] = config_fic_id
        return changed

    def get_fronted_ip_config_id(self, fip_name):
        return ('/subscriptions/{}'
                '/resourceGroups/{}'
                '/providers/Microsoft.Network'
                '/loadBalancers/{}'
                '/frontendIPConfigurations/{}').format(
            self.subscription_id, self.resource_group, self.name, fip_name
        )

    def get_backend_pool_id(self, bap_name):
        return ('/subscriptions/{}'
                '/resourceGroups/{}'
                '/providers/Microsoft.Network'
                '/loadBalancers/{}'
                '/backendAddressPools/{}').format(
            self.subscription_id, self.resource_group, self.name, bap_name
        )

    def get_probe_id(self, probe_name):
        return ('/subscriptions/{}'
                '/resourceGroups/{}'
                '/providers/Microsoft.Network'
                '/loadBalancers/{}'
                '/probes/{}').format(
            self.subscription_id, self.resource_group, self.name, probe_name
        )


def main():
    AzureRMLoadBalancer()


if __name__ == '__main__':
    main()
