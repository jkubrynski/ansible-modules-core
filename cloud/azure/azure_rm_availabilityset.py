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
module: azure_rm_availabilityset
version_added: "2.2"
short_description: Manage Azure availability sets.
description:
    - Create, update and delete an availability set.
options:
    location:
        description:
            - Valid azure location. Defaults to location of the resource group.
        default: resource_group location
        required: false
    name:
        description:
            - Name of the availability set.
        required: true
    state:
        description:
            - Assert the state of the availability set. Use 'present' to create or update and 'absent' to delete.
        default: present
        choices:
            - absent
            - present
        required: false
    update_domains:
        description:
            - Number of update domains.
        default: 5
        required: false
    fault_domains:
        description:
            - Number of fault domains.
        default: 3
        required: false
extends_documentation_fragment:
    - azure
    - azure_tags

author:
    - "Jakub Kubrynski (@jkubrynski)"

'''

EXAMPLES = '''
    - name: Create an availability set
      azure_rm_availabilityset:
        name: testaset
        resource_group: Testing
        location: westus
        update_domains: 3
        fault_domains: 2
        tags:
            testing: testing
            delete: never

    - name: Delete an availability set
      azure_rm_availabilityset:
        name: testaset
        resource_group: Testing
        state: absent
'''
RETURN = '''
state:
    description: The current state of the availability set.
    returned: always
    type: dict
    sample: {
        "id": "/subscriptions/XXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXX/resourceGroups/Testing/providers/providers/Microsoft.Compute/availabilitySets/testaset",
        "location": "eastus2",
        "name": "testaset",
        "platform_fault_domain_count": 1,
        "platform_update_domain_count": 4,
        "tags": null,
        "type": "Microsoft.Network/networkInterfaces"
    }
'''
from ansible.module_utils.azure_rm_common import *


try:
    from msrestazure.azure_exceptions import CloudError
    from azure.mgmt.compute.models.availability_set import AvailabilitySet
except ImportError:
    pass


def availability_set_to_dict(aset):
    return dict(
        id=aset.id,
        name=aset.name,
        location=aset.location,
        tags=aset.tags,
        platform_update_domain_count=aset.platform_update_domain_count,
        platform_fault_domain_count=aset.platform_fault_domain_count
    )


class AzureRMAvailabilitySet(AzureRMModuleBase):

    def __init__(self):
        self.module_arg_spec = dict(
            name=dict(type='str', required=True),
            resource_group=dict(type='str', required=True),
            state=dict(type='str', default='present', choices=['present', 'absent']),
            location=dict(type='str'),
            update_domains=dict(type='int', default=5),
            fault_domains=dict(type='int', default=3)
        )

        self.name = None
        self.resource_group = None
        self.state = None
        self.location = None
        self.tags = None
        self.update_domains = None
        self.fault_domains = None

        self.results = dict(
            changed=False,
            state=dict(),
        )

        super(AzureRMAvailabilitySet, self).__init__(self.module_arg_spec,
                                                   supports_check_mode=True,
                                                   supports_tags=True)

    def exec_module(self, **kwargs):

        for key in self.module_arg_spec.keys() + ['tags']:
            setattr(self, key, kwargs[key])

        changed = False
        state = None
        results = None

        resource_group = self.get_resource_group(self.resource_group)
        if not self.location:
            # Set default location
            self.location = resource_group.location

        self.log('Fetching availability set {0}'.format(self.name))
        try:
            aset = self.compute_client.availability_sets.get(self.resource_group, self.name)
            self.log(self.serialize_obj(aset, 'AvailabilitySet'), pretty_print=True)
            results = availability_set_to_dict(aset)
        except CloudError:
            pass

        if self.state == 'present':
            if not results:
                # Create availability set
                self.log("Creating availability set {0}".format(self.name))
                params = AvailabilitySet(
                    location=self.location,
                    tags=self.tags,
                    platform_update_domain_count=self.update_domains,
                    platform_fault_domain_count=self.fault_domains
                )
                changed = True
            else:
                # Update availability set
                update_tags, results['tags'] = self.update_tags(results['tags'])
                if update_tags:
                    changed = True

                if self.update_domains != results['platform_update_domain_count']:
                    self.fail("Changing update_domains parameter is not allowed. Existing value is %s" % results['platform_update_domain_count'])

                if self.fault_domains != results['platform_fault_domain_count']:
                    self.fail("Changing fault_domains parameter is not allowed. Existing value is %s" % results['platform_fault_domain_count'])

                params = AvailabilitySet(
                    location=results['location'],
                    tags=results['tags'],
                    platform_update_domain_count=results['platform_update_domain_count'],
                    platform_fault_domain_count=results['platform_fault_domain_count']
                 )

            if changed and not self.check_mode:
                state = self.create_or_update_availability_set(params)
        elif self.state == 'absent':
            if results:
                self.log("Removing availability set")
                changed = True
                if not self.check_mode:
                    self.delete_availability_set()

        if not changed:
            state = results

        self.results['state'] = state
        self.results['changed'] = changed

        return self.results

    def create_or_update_availability_set(self, params):
        try:
            result = self.compute_client.availability_sets.create_or_update(self.resource_group, self.name, params)
        except Exception as exc:
            self.fail("Error creating or updating availability set {0} - {1}".format(self.name, str(exc)))
        return availability_set_to_dict(result)

    def delete_availability_set(self):
        try:
            self.compute_client.availability_sets.delete(self.resource_group, self.name)
        except Exception as exc:
            self.fail("Error delete availability set {0} - {1}".format(self.name, str(exc)))

        # The delete operation doesn't return anything.
        # If we got here, assume all is good
        self.results['state']['status'] = 'Deleted'
        return True

def main():
    AzureRMAvailabilitySet()

if __name__ == '__main__':
    main()

