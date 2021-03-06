# Copyright 2014
# The Cloudscaling Group, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import base64
import collections
import copy
import itertools
import random
import re

from novaclient import exceptions as nova_exception
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import timeutils

from ec2api.api import clients
from ec2api.api import common
from ec2api.api import ec2utils
from ec2api.api import network_interface as network_interface_api
from ec2api.api import security_group as security_group_api
from ec2api import context as ec2_context
from ec2api.db import api as db_api
from ec2api import exception
from ec2api.i18n import _, _LE

LOG = logging.getLogger(__name__)

ec2_opts = [
    cfg.BoolOpt('ec2_private_dns_show_ip',
                default=False,
                help='Return the IP address as private dns hostname in '
                     'describe instances'),
    cfg.StrOpt('default_flavor',
           default='m1.small',
           help='A flavor to use as a default instance type')
]

CONF = cfg.CONF
CONF.register_opts(ec2_opts)

DEFAULT_BLOCK_VOLUME_SIZE = 8
DEFAULT_ROOT_DEVICE_NAME = "/dev/sda1"

"""Instance related API implementation
"""


class Validator(common.Validator):

    def i_id_or_ids(self, value):
        # NOTE(ft): boto specifies an instance id to GetConsoleOutput as
        # a list with the id. This is an AWS undocumented feature for all (?)
        # parameters, but ec2api will support it in certain operations only.
        if type(value) is list:
            if len(value) != 1:
                msg = (
                    _("The parameter 'InstanceId' may only be specified once.")
                    if len(value) else
                    _('No instanceId specified'))
                raise exception.InvalidParameterCombination(msg)
            value = value[0]
        self.i_id(value)


def get_instance_engine():
    if CONF.full_vpc_support:
        return InstanceEngineNeutron()
    else:
        return InstanceEngineNova()


def run_instances(context, image_id, instance_count=1,
                  key_name=None, security_group_id=None,
                  instance_type_id=None,
                  block_device_mapping=None,
                  subnet_id=None,
                  private_ip_address=None):

    #_check_min_max_count(min_count, max_count)

    # [varun] Keeping these parameters anyways for future
    # but not exposing it to user
    security_group=None
    user_data=None
    ebs_optimized=None
    iam_instance_profile=None
    client_token=None
    instance_initiated_shutdown_behavior=None
    placement=None
    disable_api_termination=None
    monitoring=None
    kernel_id=None
    ramdisk_id=None
    network_interface=None

    print "Run Instances"
    _check_instance_count(instance_count)

    if client_token:
        reservations = describe_instances(context,
                                          filter=[{'name': 'client-token',
                                                   'value': [client_token]}])
        if reservations['reservationSet']:
            if len(reservations['reservationSet']) > 1:
                LOG.error(_LE('describe_instances has returned %s '
                              'reservations, but 1 is expected.') %
                          len(reservations['reservationSet']))
                LOG.error(_LE('Requested instances client token: %s') %
                          client_token)
                LOG.error(_LE('Result: %s') % reservations)
            return reservations['reservationSet'][0]

    os_image, os_kernel_id, os_ramdisk_id = _parse_image_parameters(
            context, image_id, kernel_id, ramdisk_id)

    nova = clients.nova(context)
    print "Instance type ID"
    print instance_type_id
    print "flavour list"
    print  nova.flavors.list()
    print "default instance"
    print CONF.default_flavor
    try:
        if instance_type_id is None:
            instance_type_id = CONF.default_flavor
        os_flavor = next(f for f in nova.flavors.list()
                         if f.name == instance_type_id)
    except StopIteration:
        raise exception.InvalidParameterValue(value=instance_type_id,
                                              parameter='InstanceTypeId')

    #bdm = _parse_block_device_mapping_v2(context, block_device_mapping,
    #                                     os_image, os_kernel_id,
    #                                     os_ramdisk_id)
    availability_zone = (placement or {}).get('availability_zone')
    if user_data:
        user_data = base64.b64decode(user_data)

    vpc_id, launch_context = instance_engine.get_vpc_and_build_launch_context(
        context, security_group,
        subnet_id, private_ip_address, security_group_id, network_interface,
        multiple_instances=instance_count > 1)

    ec2_reservation_id = _generate_reservation_id()
    instance_ids = []
    with common.OnCrashCleaner() as cleaner:
        # NOTE(ft): create Neutron's ports manually and run instances one
        # by one to have a chance to:
        # process individual network interface options like security_group
        # or private_ip_addresses (Nova's create_instances receives only
        # one fixed_ip for subnet)
        # set dhcp options to port
        # add corresponding OS ids of network interfaces to our DB
        # TODO(ft): we should lock created network interfaces to prevent
        # their usage or deleting

        # TODO(ft): do correct error messages on create failures. For
        # example, overlimit, ip lack, ip overlapping, etc
        for launch_index in range(instance_count):
            if launch_index >= instance_count:
                cleaner.approveChanges()

            extra_params = (
                instance_engine.get_launch_extra_parameters(
                    context, cleaner, launch_context))

            print launch_context['network_data'][0]['network_interface']['os_id']
            net_id = launch_context['network_data'][0]['network_interface']['os_id']
            print ec2_reservation_id
            #os_instance = nova.servers.create(
            #    name="test", nics = [{'net-id': net_id} ],
            #    image = os_image.id, flavor = os_flavor,
            #    min_count=1, max_count=1,
            #    kernel_id=os_kernel_id, ramdisk_id=os_ramdisk_id,
            #    availability_zone=availability_zone,
            #    key_name=key_name)



            os_instance = nova.servers.create(
                '%s-%s' % (ec2_reservation_id, launch_index),
                os_image.id, os_flavor,
                min_count=1, max_count=1,
                kernel_id=os_kernel_id, ramdisk_id=os_ramdisk_id,
                availability_zone=availability_zone,
                key_name=key_name,
                userdata=user_data,
                **extra_params)
            cleaner.addCleanup(nova.servers.delete, os_instance.id)

            instance = {'os_id': os_instance.id,
                        'vpc_id': vpc_id,
                        'reservation_id': ec2_reservation_id,
                        'launch_index': launch_index}
            if client_token:
                instance['client_token'] = client_token

            instance = db_api.add_item(context, 'i', instance)
            cleaner.addCleanup(db_api.delete_item, context, instance['id'])
            instance_ids.append(instance['id'])

            nova.servers.update(os_instance, name=instance['id'])

            instance_engine.post_launch_action(
                context, cleaner, launch_context, instance['id'])

    ec2_reservations = describe_instances(context, instance_ids)
    # reservation_count = len(ec2_reservations['reservationSet'])
    # if reservation_count != 1:
    #     LOG.error(_LE('describe_instances has returned %s reservations, '
    #                   'but 1 is expected.') % reservation_count)
    #     LOG.error(_LE('Requested instances IDs: %s') % instance_ids)
    #     LOG.error(_LE('Result: %s') % ec2_reservations)
    # return (ec2_reservations['reservationSet'][0]
    #         if reservation_count else None)
    return ec2_reservations


def terminate_instances(context, instance_id):
    instance_ids = set(instance_id)
    instances = ec2utils.get_db_items(context, 'i', instance_ids)

    nova = clients.nova(context)
    state_changes = []
    prev_state = None
    for instance in instances:
        try:
            os_instance = nova.servers.get(instance['os_id'])
            prev_state = getattr(os_instance, 'OS-EXT-STS:vm_state')
        except nova_exception.NotFound:
            os_instance = None
        else:
            os_instance.delete()
        state_change = _format_state_change(instance, prev_state)
        state_changes.append(state_change)

    # NOTE(ft): don't delete items from DB until they disappear from OS.
    # They will be auto deleted by a describe operation
    return {'instancesSet': state_changes}


class InstanceDescriber(common.TaggableItemsDescriber):

    KIND = 'i'
    FILTER_MAP = {
        'availability-zone': ('placement', 'availabilityZone'),
        'block-device-mapping.delete-on-termination': [
            'blockDeviceMapping', ('ebs', 'deleteOnTermination')],
        'block-device-mapping.device-name': ['blockDeviceMapping',
                                             'deviceName'],
        'block-device-mapping.status': ['blockDeviceMapping',
                                        ('ebs', 'status')],
        'block-device-mapping.volume-id': ['blockDeviceMapping',
                                           ('ebs', 'volumeId')],
        'client-token': 'clientToken',
        'dns-name': 'dnsName',
        'group-id': ['groupSet', 'groupId'],
        'group-name': ['groupSet', 'groupName'],
        'image-id': 'imageId',
        'instance-id': 'instanceId',
        'instance-state-code': ('instanceState', 'code'),
        'instance-state-name': ('instanceState', 'name'),
        'instance-type': 'instanceType',
        'instance.group-id': ['groupSet', 'groupId'],
        'instance.group-name': ['groupSet', 'groupName'],
        'ip-address': 'ipAddress',
        'kernel-id': 'kernelId',
        'key-name': 'keyName',
        'launch-index': 'launchIndex',
        'launch-time': 'launchTime',
        'private-dns-name': 'privateDnsName',
        'private-ip-address': 'privateIpAddress',
        'ramdisk-id': 'ramdiskId',
        'root-device-name': 'rootDeviceName',
        'root-device-type': 'rootDeviceType',
        'subnet-id': ['networkInterfaceSet', 'subnetId'],
        'vpc-id': ['networkInterfaceSet', 'vpcId'],
        'network-interface.description': ['networkInterfaceSet',
                                          'description'],
        'network-interface.subnet-id': ['networkInterfaceSet', 'subnetId'],
        'network-interface.vpc-id': ['networkInterfaceSet', 'vpcId'],
        'network-interface.network-interface.id': ['networkInterfaceSet',
                                                   'networkInterfaceId'],
        'network-interface.owner-id': ['networkInterfaceSet', 'ownerId'],
        'network-interface.requester-managed': ['networkInterfaceSet',
                                                'requesterManaged'],
        'network-interface.status': ['networkInterfaceSet', 'status'],
        'network-interface.mac-address': ['networkInterfaceSet',
                                          'macAddress'],
        'network-interface.source-destination-check': ['networkInterfaceSet',
                                                       'sourceDestCheck'],
        'network-interface.group-id': ['networkInterfaceSet',
                                       ['groupSet', 'groupId']],
        'network-interface.group-name': ['networkInterfaceSet',
                                         ['groupSet', 'groupName']],
        'network-interface.attachment.attachment-id':
            ['networkInterfaceSet', ('attachment', 'attachmentId')],
        'network-interface.attachment.instance-id': 'instanceId',
        'network-interface.addresses.private-ip-address':
            ['networkInterfaceSet', ['privateIpAddressesSet',
                                     'privateIpAddress']],
        'network-interface.attachment.device-index':
            ['networkInterfaceSet', ('attachment', 'deviceIndex')],
        'network-interface.attachment.status':
            ['networkInterfaceSet', ('attachment', 'status')],
        'network-interface.attachment.attach-time':
            ['networkInterfaceSet', ('attachment', 'attachTime')],
        'network-interface.attachment.delete-on-termination':
            ['networkInterfaceSet', ('attachment', 'deleteOnTermination')],
        'network-interface.addresses.primary':
            ['networkInterfaceSet', ['privateIpAddressesSet', 'primary']],
        'network-interface.addresses.association.public-ip':
            ['networkInterfaceSet', ['privateIpAddressesSet',
                                     ('association', 'publicIp')]],
        'network-interface.addresses.association.ip-owner-id':
            ['networkInterfaceSet', ['privateIpAddressesSet',
                                     ('association', 'ipOwnerId')]],
        'association.public-ip': ['networkInterfaceSet',
                                  ('association', 'publicIp')],
        'association.ip-owner-id': ['networkInterfaceSet',
                                    ('association', 'ipOwnerId')]}

    def __init__(self):
        super(InstanceDescriber, self).__init__()
        self.reservations = {}
        self.reservation_instances = collections.defaultdict(list)
        self.reservation_os_groups = {}
        self.obsolete_instances = []

    def format(self, instance, os_instance):
        self.volumes = None
        self.os_volumes = None
        self.os_flavors= None
        formatted_instance = _format_instance(
                self.context, instance, os_instance,
                self.ec2_network_interfaces.get(instance['id']),
                self.image_ids, self.volumes, self.os_volumes,
                self.os_flavors)

        reservation_id = instance['reservation_id']
        if reservation_id in self.reservations:
            reservation = self.reservations[reservation_id]
        else:
            reservation = {'id': reservation_id,
                           'owner_id': os_instance.tenant_id}
            self.reservations[reservation_id] = reservation
            if not instance['vpc_id']:
                self.reservation_os_groups[reservation_id] = (
                    getattr(os_instance, 'security_groups', []))

        self.reservation_instances[
                reservation['id']].append(formatted_instance)

        return formatted_instance

    def get_db_items(self):
        instances = super(InstanceDescriber, self).get_db_items()
        self.ec2_network_interfaces = (
            instance_engine.get_ec2_network_interfaces(
                self.context, self.ids))
        self.volumes = {v['os_id']: v
                        for v in db_api.get_items(self.context, 'vol')}
        self.image_ids = {i['os_id']: i['id']
                          for i in itertools.chain(
                              db_api.get_items(self.context, 'ami'),
                              db_api.get_public_items(self.context, 'ami'))}
        return instances

    def get_os_items(self):
        #self.os_volumes = _get_os_volumes(self.context)
        #self.os_flavors = _get_os_flavors(self.context)
        nova = clients.nova(self.context)
        print "----------------------------------"
        ###Self ids are empty
        if self.ids == 1 and len(self.items) == 1:
            try:
                return [nova.servers.get(self.items[0]['os_id'])]
            except nova_exception.NotFound:
                return []
        else:
            print "In else"
            print self.context.project_id
            return nova.servers.list(
                search_opts={'all_tenants': True,
                             'project_id': self.context.project_id})

    def auto_update_db(self, instance, os_instance):
        if not instance:
            instance = ec2utils.get_db_item_by_os_id(
                    self.context, 'i', os_instance.id,
                    os_instance=os_instance)
        return instance

    def get_name(self, os_item):
        return ''

    def delete_obsolete_item(self, instance):
        self.obsolete_instances.append(instance)


class ReservationDescriber(common.NonOpenstackItemsDescriber):

    KIND = 'r'
    FILTER_MAP = {
        'reservation-id': 'reservationId',
        'owner-id': 'ownerId',
        'network-interface.attachment.instance-owner-id': 'ownerId',
    }

    def format(self, reservation):
        formatted_instances = [i for i in self.instances[reservation['id']]
                               if i['instanceId'] in self.suitable_instances]
        if not formatted_instances:
            return None
        return _format_reservation(self.context, reservation,
                                   formatted_instances,
                                   self.os_groups.get(reservation['id']))

    def get_db_items(self):
        return self.reservations

    def describe(self, context, ids=None, names=None, filter=None):
        reservation_filters = []
        instance_filters = []
        for f in filter or []:
            if f.get('name') in self.FILTER_MAP:
                reservation_filters.append(f)
            else:
                instance_filters.append(f)
        # NOTE(ft): set empty filter sets to None because Describer
        # requires None for no filter case
        if not instance_filters:
            instance_filters = None
        if not reservation_filters:
            reservation_filters = None

        try:
            instance_describer = InstanceDescriber()
            formatted_instances = instance_describer.describe(
                    context, ids=ids, filter=instance_filters)
        except exception.InvalidInstanceIDNotFound:
            _remove_instances(context, instance_describer.obsolete_instances)
            raise

        _remove_instances(context, instance_describer.obsolete_instances)

        self.reservations = instance_describer.reservations.values()
        self.instances = instance_describer.reservation_instances
        self.os_groups = instance_describer.reservation_os_groups
        self.suitable_instances = set(i['instanceId']
                                      for i in formatted_instances)

        return super(ReservationDescriber, self).describe(
                context, filter=reservation_filters)

def _convert_ram_from_mb_to_gb(value):
    if value is not None:
        return float(value)/1024
    else:
        return value

def describe_instance_types(context, instance_type_id=None):
    flavors = _get_os_flavors(context)
    formatted_flavors = []
    if instance_type_id is None:
        instance_type_id = list(flavors.keys())
    else:
        flavors = dict((value, key) for key, value in flavors.iteritems())
        instance_type_id_copy = instance_type_id
        instance_type_id = []
        for type_id in instance_type_id_copy:
            key = flavors.get(type_id)
            if key is None:
                _msg = ("No InstanceType found with name \""
                        + str(type_id) + "\".")
                raise exception.InvalidParameterValue(_msg)
            instance_type_id.append(key)
    for key in instance_type_id:
        os_flavors = clients.nova(context).flavors.get(key)
        entry = dict()
        #entry['name'] = os_flavors.name
        entry['id'] = os_flavors.name
        entry['ram'] = _convert_ram_from_mb_to_gb(os_flavors.ram)
        entry['vcpus'] = os_flavors.vcpus
        # [varun] There is no significance of disk for now as it is applicable
        # to ephemeral storage. Commenting it out for now.
        # entry['disk'] = os_flavors.disk
        formatted_flavors.append(entry)
    return {'instanceTypes': formatted_flavors}


def describe_instances(context, instance_id=None, filter=None):
    formatted_reservations = ReservationDescriber().describe(
            context, ids=instance_id, filter=filter)
    instances = []
    for reservation in formatted_reservations:
        for instance in reservation:
            instances.append(instance)
    return {'instancesSet': instances}


def reboot_instances(context, instance_id):
    return _foreach_instance(context, instance_id,
                             (vm_states_ALLOW_SOFT_REBOOT +
                              vm_states_ALLOW_HARD_REBOOT),
                             lambda instance: instance.reboot(),
                             vm_states_ACTIVE)


def stop_instances(context, instance_id, force=False):
    return _foreach_instance(context, instance_id,
                             [vm_states_ACTIVE, vm_states_RESCUED,
                              vm_states_ERROR],
                             lambda instance: instance.stop(),
                             vm_states_STOPPED)


def start_instances(context, instance_id):
    return _foreach_instance(context, instance_id, [vm_states_STOPPED],
                             lambda instance: instance.start(),
                             vm_states_ACTIVE)


def get_password_data(context, instance_id):
    if type(instance_id) is list:
        instance_id = instance_id[0]
    instance = ec2utils.get_db_item(context, instance_id)
    nova = clients.nova(context)
    os_instance = nova.servers.get(instance['os_id'])
    password = os_instance.get_password()
    # NOTE(vish): this should be timestamp from the metadata fields
    #             but it isn't important enough to implement properly
    now = timeutils.utcnow()
    return {"instanceId": instance_id,
            "timestamp": now,
            "passwordData": base64.b64encode(password)}


def get_console_output(context, instance_id):
    if type(instance_id) is list:
        instance_id = instance_id[0]
    instance = ec2utils.get_db_item(context, instance_id)
    nova = clients.nova(context)
    os_instance = nova.servers.get(instance['os_id'])
    console_output = os_instance.get_console_output()
    now = timeutils.utcnow()
    return {"instanceId": instance_id,
            "timestamp": now,
            "output": base64.b64encode(console_output)}


def describe_instance_attribute(context, instance_id, attribute):
    instance = ec2utils.get_db_item(context, instance_id)
    nova = clients.nova(context)
    os_instance = nova.servers.get(instance['os_id'])

    def _format_attr_block_device_mapping(result):
        # TODO(ft): next call add 'rootDeviceType' to result,
        # but AWS doesn't. This is legacy behavior of Nova EC2
        _cloud_format_instance_bdm(context, os_instance, result)

    def _format_attr_group_set(result):
        result['groupSet'] = _format_group_set(
            context, getattr(os_instance, 'security_groups', []))

    def _format_attr_instance_type(result):
        result['instanceType'] = {'value': _cloud_format_instance_type(
                                                       context, os_instance)}

    def _format_attr_kernel(result):
        value = _cloud_format_kernel_id(context, os_instance)
        result['kernel'] = {'value': value}

    def _format_attr_ramdisk(result):
        value = _cloud_format_ramdisk_id(context, os_instance)
        result['ramdisk'] = {'value': value}

    def _format_attr_root_device_name(result):
        result['rootDeviceName'] = {
                'value': getattr(os_instance,
                                 'OS-EXT-SRV-ATTR:root_device_name', None)}

    def _format_attr_user_data(result):
        user_data = getattr(os_instance, 'OS-EXT-SRV-ATTR:user_data', None)
        if user_data:
            result['userData'] = {'value': user_data}

    def _format_attr_disable_api_termination(result):
        result['disableApiTermination'] = {'value': False}

    attribute_formatter = {
        'blockDeviceMapping': _format_attr_block_device_mapping,
        # 'disableApiTermination': _format_attr_disable_api_termination,
        'groupSet': _format_attr_group_set,
        'instanceType': _format_attr_instance_type,
        # 'kernel': _format_attr_kernel,
        # 'ramdisk': _format_attr_ramdisk,
        # 'rootDeviceName': _format_attr_root_device_name,
        # 'userData': _format_attr_user_data,
    }

    fn = attribute_formatter.get(attribute)
    if fn is None:
        # TODO(ft): clarify an exact AWS error
        raise exception.InvalidAttribute(attr=attribute)

    result = {'instance_id': instance_id}
    fn(result)
    return result


def _format_reservation(context, reservation, formatted_instances, os_groups):
    # Commenting out this group set because it is related to classic instances

    #return {
        # 'ownerId': reservation['owner_id'],
   #     'instancesSet': sorted(formatted_instances,
   #                            key=lambda i: i['launchIndex'])
        # 'groupSet': (_format_group_set(context, os_groups)
        #             if os_groups is not None else [])
    #}
    return sorted(formatted_instances, key=lambda i: i['launchTime'])


def _format_instance(context, instance, os_instance, ec2_network_interfaces,
                     image_ids, volumes=None, os_volumes=None,
                     os_flavors=None):
    ec2_instance = {
        #'launchIndex': instance['launch_index'],
        'imageId': (ec2utils.os_id_to_ec2_id(context, 'ami',
                                             os_instance.image['id'],
                                             ids_by_os_id=image_ids)
                    if os_instance.image else None),
        'instanceId': instance['id'],
        #'instanceType': os_flavors.get(os_instance.flavor['id'], 'unknown'),
        'keyName': os_instance.key_name,
        'launchTime': os_instance.created,
#        'placement': {
#            'availabilityZone': getattr(os_instance,
#                                        'OS-EXT-AZ:availability_zone')},
#        'instanceState': _cloud_state_description(
#                                getattr(os_instance, 'OS-EXT-STS:vm_state')),
         'instanceState': _cloud_state_find(os_instance),
    }
    root_device_name = getattr(os_instance,
                               'OS-EXT-SRV-ATTR:root_device_name', None)
    #if root_device_name:
    #    ec2_instance['rootDeviceName'] = root_device_name
    #_cloud_format_instance_bdm(context, os_instance, ec2_instance,
    #                           volumes, os_volumes)
    kernel_id = _cloud_format_kernel_id(context, os_instance, image_ids)
    if kernel_id:
        ec2_instance['kernelId'] = kernel_id
    ramdisk_id = _cloud_format_ramdisk_id(context, os_instance, image_ids)
    if ramdisk_id:
        ec2_instance['ramdiskId'] = ramdisk_id

    if 'client_token' in instance:
        ec2_instance['clientToken'] = instance['client_token']

    if not ec2_network_interfaces:
        fixed_ip, fixed_ip6, floating_ip = (
            _get_ip_info_for_instance(os_instance))
        if fixed_ip6:
            ec2_instance['dnsNameV6'] = fixed_ip6
        dns_name = floating_ip
        # TODO(ft): euca2ools require groupId for an instance security group.
        # But ec2-api doesn't store IDs for EC2 Classic groups.
        #print "-------------------------Harsh Says------------------"
        #print os_instance
        #ec2_instance['groupSet'] = _format_group_set(
        #        context, os_instance.security_groups)
    else:
        primary_ec2_network_interface = None
        for ec2_network_interface in ec2_network_interfaces:
            ec2_network_interface['attachment'].pop('instanceId')
            ec2_network_interface['attachment'].pop('instanceOwnerId')
            ec2_network_interface.pop('tagSet')
            ec2_addresses = ec2_network_interface['privateIpAddressesSet']
            for ec2_address in ec2_addresses:
                association = ec2_address.get('association')
                if association:
                    association.pop('associationId')
                    association.pop('allocationId')
            association = ec2_network_interface.get('association')
            if association:
                association.pop('associationId', None)
                association.pop('allocationId', None)
            if ec2_network_interface['attachment']['deviceIndex'] == 0:
                primary_ec2_network_interface = ec2_network_interface
        # ec2_instance.update({'vpcId': ec2_network_interface['vpcId'],
        #                     'networkInterfaceSet': ec2_network_interfaces})
        ec2_instance.update({'vpcId': ec2_network_interface['vpcId']})
        fixed_ip = floating_ip = dns_name = None
        if primary_ec2_network_interface:
            ec2_instance.update({
               'subnetId': primary_ec2_network_interface['subnetId'],
               'groupSet': primary_ec2_network_interface['groupSet']})
            fixed_ip = primary_ec2_network_interface['privateIpAddress']
            if 'association' in primary_ec2_network_interface:
                association = primary_ec2_network_interface['association']
                floating_ip = association['publicIp']
                dns_name = association['publicDnsName']
    ec2_instance.update({
        'privateIpAddress': fixed_ip,
        'privateDnsName': (fixed_ip if CONF.ec2_private_dns_show_ip else
                           getattr(os_instance, 'OS-EXT-SRV-ATTR:hostname',
                                   None)),
        'dnsName': dns_name,
    })
    if floating_ip is not None:
        ec2_instance['ipAddress'] = floating_ip

    if context.is_admin:
        ec2_instance['keyName'] = '%s (%s, %s)' % (
            ec2_instance['keyName'],
            os_instance.tenant_id,
            getattr(os_instance, 'OS-EXT-SRV-ATTR:host'))
    return ec2_instance


def _format_state_change(instance, prev_state=None, current_state=None):
    # Changing this function to receive the current and previous state
    # parameters
    if prev_state is None:
        prev_state = vm_states_WIPED_OUT
    if current_state is None:
        current_state = vm_states_WIPED_OUT
    return {
        'instanceId': instance['id'],
        'previousState': _cloud_state_description(prev_state),
        'currentState': _cloud_state_description(current_state)
    }


def _remove_instances(context, instances):
    if not instances:
        return
    ids = set([i['id'] for i in instances])
    network_interfaces = collections.defaultdict(list)

    # TODO(ft): implement search db items by os_id in DB layer
    for eni in db_api.get_items(context, 'eni'):
        if 'instance_id' in eni and eni['instance_id'] in ids:
            network_interfaces[eni['instance_id']].append(eni)

    for instance_id in ids:
        for eni in network_interfaces[instance_id]:
            delete_on_termination = eni['delete_on_termination']
            network_interface_api._detach_network_interface_item(context,
                                                                 eni)
            if delete_on_termination:
                network_interface_api.delete_network_interface(context,
                                                               eni['id'])
        db_api.delete_item(context, instance_id)

def _check_instance_count(instance_count):
    instance_count = int(instance_count)
    # TODO: figure out appropriate aws message and use them
    # This method is not checking if instance count is more
    # than the quota. We need to make sure that it is happen-
    # -ing somewhere.
    if instance_count < 1:
        msg = _('Instance count must be greater than zero')
        raise exception.InvalidParameterValue(msg)

# TODO: Remove this method once requirements are finalized
# def _check_min_max_count(min_count, max_count):
#    # TODO(ft): figure out appropriate aws message and use them
#    min_count = int(min_count)
#    max_count = int(max_count)

#    if min_count < 1:
#        msg = _('Minimum instance count must be greater than zero')
#        raise exception.InvalidParameterValue(msg)
#    elif max_count < 1:
#        msg = _('Maximum instance count must be greater than zero')
#        raise exception.InvalidParameterValue(msg)
#    elif min_count > max_count:
#        msg = _('Maximum instance count must not be smaller than '
#                'minimum instance count')
#        raise exception.InvalidParameterValue(msg)


def _parse_image_parameters(context, image_id, kernel_id, ramdisk_id):
    os_kernel_id = (ec2utils.get_os_image(context, kernel_id).id
                    if kernel_id else None)
    os_ramdisk_id = (ec2utils.get_os_image(context, ramdisk_id).id
                     if ramdisk_id else None)
    os_image = ec2utils.get_os_image(context, image_id)

    if _cloud_get_image_state(os_image) != 'available':
        # TODO(ft): Change the message with the real AWS message
        msg = _('Image must be available')
        raise exception.InvalidAMIIDUnavailable(message=msg)

    return os_image, os_kernel_id, os_ramdisk_id


def _is_this_root_volume(context, item, root_device, root_snapshot_id):
    result = False
    # Two things will determine if this is root volume
    # device name reserved for root volumes and
    # snapshot id reserved for AMI's
    if item.has_key("device_name") and item["device_name"] == root_device:
        if item.has_key("snapshot_id") and item["snapshot_id"] != root_snapshot_id:
            msg = ('Incosistent device name and snapshot id')
            raise exception.InvalidParameterValue(msg)

        # This block device mapping is for root device/volume
        result = True
    return result


def _process_block_device_mapping_entry(context, item,
                                        root_device,
                                        root_snapshot_id,
                                        os_image):
    result = {}
    root_device_found = False

    # Unless we support ephemeral devices the destination_type will be
    # volume
    result["destination_type"] = "volume"

    # This parameter is applicable to all types of block devices
    if item.has_key("volume_size"):
        result["volume_size"] = item["volume_size"]
    else:
        # TODO: We can put it in config. But this should rarely be used.
        result["volume_size"] = DEFAULT_BLOCK_VOLUME_SIZE

    # This flag is applicable to all types of block devices
    if item.has_key("delete_on_termination"):
        result["delete_on_termination"] = item["delete_on_termination"]
    else:
        # TODO: We can put it in config but for now default behavior is false
        result["delete_on_termination"] = False

    if _is_this_root_volume(context, item, root_device, root_snapshot_id):
        result["device_name"] = root_device
        result["boot_index"] = "0"
        result["source_type"] = "image"
        result["uuid"] = str(os_image.id)
        root_device_found = True
    else:

        if item.has_key("snapshot_id"):
            result["snapshot_id"] = item["snapshot_id"]
            result["source_type"] = "snapshot"
        else:
            result["source_type"] = "blank"

        if item.has_key("device_name"):
            result["device_name"] = item["device_name"]

        result["boot_index"] = "-1"
    return root_device_found, result


def _create_root_bdm_from_image(context, os_image):
    # Start with some default values and fill as required
    root_bdm = {
        "boot_index": "0",
        "source_type": "image",
        "destination_type": "volume",
        "volume_size": str(DEFAULT_BLOCK_VOLUME_SIZE),
        "delete_on_termination": False,
        "device_name": DEFAULT_ROOT_DEVICE_NAME
    }

    if os_image != None:
        root_bdm["uuid"] = str(os_image.id)

        if os_image.min_disk > 0:
            root_bdm["volume_size"] = str(os_image.min_disk)

        if os_image.properties != None and os_image.properties.has_key("root_device"):
            root_bdm["device_name"] = str(os_image.properties["root_device"])

    # Fix for https://jira.ril.com/browse/JCC-109
    # Root BDM was not mounting
    if root_bdm.has_key("device_name"):
        root_bdm.pop("device_name")

    return root_bdm


def _parse_block_device_mapping_v2(context, block_device_mapping,
                                   os_image = None,
                                   os_kernel_id = None,
                                   os_ramdisk_id = None):
    if block_device_mapping is None:
        # No block device mapping is supplied. We still need to
        # boot from volume. Let us figure out the information we
        # need
        bdm = _create_root_bdm_from_image(context, os_image)
        # Need to return array of dict
        return [bdm]

    # We have one or more items in block device mapping.
    bdm_list = []

    # We need to figure out block device mapping paramaters for root volume
    root_device = DEFAULT_ROOT_DEVICE_NAME
    root_snapshot_id = None

    if os_image != None and os_image.properties != None:
        if os_image.properties.has_key("root_device"):
            root_device = os_image.properties["root_device"]
        if os_image.properties.has_key("snapshot_id"):
            root_snapshot_id = os_image.properties["snapshot_id"]

    bdm_has_root_device = False
    # Now we are ready to process block device mapping enteries
    for item in block_device_mapping:
        is_root_dev, result = _process_block_device_mapping_entry(context,
                                                                 item,
                                                                 root_device,
                                                                 root_snapshot_id,
                                                                 os_image)

        # Fix for https://jira.ril.com/browse/JCC-109
        # BDM was not mounting
        if result.has_key("device_name"):
            result.pop("device_name")

        bdm_list.append(result)
        if is_root_dev:
            bdm_has_root_device = True

    if bdm_has_root_device == False:
        bdm = _create_root_bdm_from_image(context, os_image)
        bdm_list.append(bdm)

    return bdm_list


# TODO: [varun] This function needs to be deprecated
def _parse_block_device_mapping(context, block_device_mapping):
    # TODO(ft): check block_device_mapping structure
    bdm = {}
    for args_bd in (block_device_mapping or []):
        _cloud_parse_block_device_mapping(context, args_bd)
        bdm[args_bd['device_name']] = ':'.join(
            [args_bd.get('snapshot_id', args_bd.get('volume_id', '')),
             ('snap' if 'snapshot_id' in args_bd else
              'vol' if 'volume_id' in args_bd else ''),
             str(args_bd.get('volume_size', '')),
             str(args_bd.get('delete_on_termination', ''))])
    return bdm


def _format_group_set(context, os_security_groups):
    if not os_security_groups:
        return None
    # TODO(ft): Euca tools uses 2010-08-31 AWS protocol version which doesn't
    # contain groupId in groupSet of an instance structure
    # Euca crashes if groupId is present here
    return [{'groupName': sg['name']} for sg in os_security_groups]


def _get_ip_info_for_instance(os_instance):
    addresses = list(itertools.chain(*os_instance.addresses.itervalues()))
    fixed_ip = next((addr['addr'] for addr in addresses
                     if (addr['version'] == 4 and
                         addr['OS-EXT-IPS:type'] == 'fixed')), None)
    fixed_ip6 = next((addr['addr'] for addr in addresses
                      if (addr['version'] == 6 and
                          addr['OS-EXT-IPS:type'] == 'fixed')), None)
    floating_ip = next((addr['addr'] for addr in addresses
                        if addr['OS-EXT-IPS:type'] == 'floating'), None)
    return fixed_ip, fixed_ip6, floating_ip


def _foreach_instance(context, instance_ids, valid_states, func,
                      final_state=None):
    instances = ec2utils.get_db_items(context, 'i', instance_ids)
    os_instances = _get_os_instances_by_instances(context, instances,
                                                  exactly=True)
    for os_instance in os_instances:
        if getattr(os_instance, 'OS-EXT-STS:vm_state') not in valid_states:
            raise exception.IncorrectInstanceState(
                instance_id=next(inst['id'] for inst in instances
                                 if inst['os_id'] == os_instance.id))
    state_changes = []
    for os_instance, ec2_instance in zip(os_instances, instances):
        prev_state = getattr(os_instance, 'OS-EXT-STS:vm_state')
        func(os_instance)
        state_change = _format_state_change(ec2_instance, prev_state,
                                            final_state)
        state_changes.append(state_change)
    return {"instancesSet": state_changes}


def _get_os_instances_by_instances(context, instances, exactly=False,
                                   nova=None):
    nova = nova or clients.nova(context)
    os_instances = []
    obsolete_instances = []
    for instance in instances:
        try:
            os_instances.append(nova.servers.get(instance['os_id']))
        except nova_exception.NotFound:
            obsolete_instances.append(instance)
    if obsolete_instances:
        _remove_instances(context, obsolete_instances)
        if exactly:
            raise exception.InvalidInstanceIDNotFound(
                                id=obsolete_instances[0]['id'])

    return os_instances


def _get_os_flavors(context):
    os_flavors = clients.nova(context).flavors.list()
    return dict((f.id, f.name) for f in os_flavors)


def _get_os_volumes(context):
    search_opts = ({'all_tenants': True,
                    'project_id': context.project_id}
                   if context.is_os_admin else None)
    os_volumes = collections.defaultdict(list)
    cinder = clients.cinder(context)
    for os_volume in cinder.volumes.list(search_opts=search_opts):
        os_attachment = next(iter(os_volume.attachments), {})
        os_instance_id = os_attachment.get('server_id')
        if os_instance_id:
            os_volumes[os_instance_id].append(os_volume)
    return os_volumes


def _is_ebs_instance(context, os_instance_id):
    nova = clients.nova(context)
    os_instance = nova.servers.get(os_instance_id)
    root_device_name = getattr(os_instance,
                               'OS-EXT-SRV-ATTR:root_device_name', None)
    if not root_device_name:
        return False
    root_device_short_name = _block_device_strip_dev(root_device_name)
    if root_device_name == root_device_short_name:
        root_device_name = _block_device_prepend_dev(root_device_name)
    for os_volume in _get_os_volumes(context)[os_instance_id]:
        os_attachment = next(iter(os_volume.attachments), {})
        device_name = os_attachment.get('device')
        if (device_name == root_device_name or
                device_name == root_device_short_name):
            return True
    return False


def _generate_reservation_id():
    return _utils_generate_uid('r')


class InstanceEngineNeutron(object):

    def get_vpc_and_build_launch_context(
            self, context, security_group,
            subnet_id, private_ip_address, security_group_id,
            network_interface, multiple_instances):
        # TODO(ft): support auto_assign_floating_ip

        print "----------------------Coming in VPC ENgine--------------------"
        vpc_network_parameters = self.merge_network_interface_parameters(
            security_group,
            subnet_id, private_ip_address, security_group_id,
            network_interface)

        self.check_network_interface_parameters(vpc_network_parameters,
                                                multiple_instances)

        (vpc_id, network_data) = self.parse_network_interface_parameters(
                context, vpc_network_parameters)
        launch_context = {'vpc_id': vpc_id,
                          'network_data': network_data,
                          'security_groups': security_group}

        # NOTE(ft): workaround for Launchpad Bug #1384347 in Icehouse
        if not security_group and vpc_network_parameters:
            launch_context['security_groups'] = (
                self.get_vpc_default_security_group_id(context, vpc_id))

        if not vpc_id:
            neutron = clients.neutron(context)
            launch_context['ec2_classic_nics'] = [
                {'net-id': self.get_ec2_classic_os_network(context,
                                                           neutron)['id']}]

        return vpc_id, launch_context

    def get_launch_extra_parameters(self, context, cleaner, launch_context):
        if 'ec2_classic_nics' in launch_context:
            nics = launch_context['ec2_classic_nics']
        else:
            network_data = launch_context['network_data']
            self.create_network_interfaces(context, cleaner, network_data)
            nics = [{'port-id': data['network_interface']['os_id']}
                    for data in network_data]
        return {'security_groups': launch_context['security_groups'],
                'nics': nics}

    def post_launch_action(self, context, cleaner, launch_context,
                           instance_id):
        for data in launch_context['network_data']:
            # TODO(ft): implement update items in DB layer to prevent
            # record by record modification
            # Alternatively a create_network_interface sub-function can
            # set attach_time  at once
            network_interface_api._attach_network_interface_item(
                context, data['network_interface'], instance_id,
                data['device_index'],
                delete_on_termination=data['delete_on_termination'])
            cleaner.addCleanup(
                network_interface_api._detach_network_interface_item,
                context, data['network_interface'])

    def get_ec2_network_interfaces(self, context, instance_ids=None):
        # NOTE(ft): we would be glad to use filters with this describe
        # operation, but:
        # 1. A selective filter by network interface IDs is improper because
        # it leads to rising NotFound exception if at least one of specified
        # network interfaces is obsolete. This is the legal case of describing
        # an instance after its terminating.
        # 2. A general filter by instance ID is unsupported now.
        # 3. A general filter by network interface IDs leads to additional
        # call of DB here to get corresponding network interfaces, but doesn't
        # lead to decrease DB and OS throughtput in called describe operation.
        enis = network_interface_api.describe_network_interfaces(
                context)['networkInterfaceSet']
        ec2_network_interfaces = collections.defaultdict(list)
        for eni in enis:
            if (eni['status'] == 'in-use' and
                    (not instance_ids or
                     eni['attachment']['instanceId'] in instance_ids)):
                ec2_network_interfaces[
                    eni['attachment']['instanceId']].append(eni)
        return ec2_network_interfaces

    def merge_network_interface_parameters(self,
                                           security_group_names,
                                           subnet_id,
                                           private_ip_address,
                                           security_group_ids,
                                           network_interfaces):
        network_interfaces = network_interfaces or []

        if ((subnet_id or private_ip_address or security_group_ids or
                security_group_names) and
                (len(network_interfaces) > 1 or
                 # NOTE(ft): the only case in AWS when simple subnet_id
                 # and/or private_ip_address parameters are compatible with
                 # network_interface parameter is default behavior change of
                 # public IP association for passed subnet_id by specifying
                 # the only element in network_interfaces:
                 # {"device_index": 0,
                 #  "associate_public_ip_address": <boolean>}
                 # Both keys must be in the dict, and no other keys
                 # are allowed
                 # We should support such combination of parameters for
                 # compatibility purposes, even if we ignore
                 # associate_public_ip_address in all other code
                 len(network_interfaces) == 1 and
                 (len(network_interfaces[0]) != 2 or
                     'associate_public_ip_address' not in network_interfaces[0]
                     or network_interfaces[0].get('device_index') != 0))):
            msg = _(' Network interfaces and an instance-level subnet ID or '
                    'private IP address or security groups may not be '
                    'specified on the same request')
            raise exception.InvalidParameterCombination(msg)

        if subnet_id:
            if security_group_names:
                msg = _('The parameter groupName cannot be used with '
                        'the parameter subnet')
                raise exception.InvalidParameterCombination(msg)
            param = {'device_index': 0,
                     'subnet_id': subnet_id}
            if private_ip_address:
                param['private_ip_address'] = private_ip_address
            if security_group_ids:
                param['security_group_id'] = security_group_ids
            return [param]
        elif private_ip_address:
            msg = _('Specifying an IP address is only valid for VPC instances '
                    'and thus requires a subnet in which to launch')
            raise exception.InvalidParameterCombination(msg)
        elif security_group_ids:
            msg = _('VPC security groups may not be used for a non-VPC launch')
            raise exception.InvalidParameterCombination(msg)
        else:
            # NOTE(ft): only one of this variables is not empty
            return network_interfaces

    def check_network_interface_parameters(self, params, multiple_instances):
        # NOTE(ft): we ignore associate_public_ip_address
        device_indexes = set()
        for param in params:
            if 'device_index' not in param:
                msg = _('Each network interface requires a device index.')
                raise exception.InvalidParameterValue(msg)
            elif param['device_index'] in device_indexes:
                msg = _('Each network interface requires a unique '
                        'device index.')
                raise exception.InvalidParameterValue(msg)
            device_indexes.add(param['device_index'])
            ni_exists = 'network_interface_id' in param
            subnet_exists = 'subnet_id' in param
            ip_exists = 'private_ip_address' in param
            if not ni_exists and not subnet_exists:
                msg = _('Each network interface requires either a subnet or '
                        'a network interface ID.')
                raise exception.InvalidParameterValue(msg)
            if ni_exists and (subnet_exists or ip_exists or
                              param.get('security_group_id') or
                              param.get('delete_on_termination')):
                param = (_('a subnet') if subnet_exists else
                         _('a private IP address') if ip_exists else
                         _('security groups') if param.get('security_group_id')
                         else _('delete on termination as true'))
                msg = _('A network interface may not specify both a network '
                        'interface ID and %(param)s') % {'param': param}
                raise exception.InvalidParameterCombination(msg)
            if multiple_instances and (ni_exists or ip_exists):
                msg = _('Multiple instances creation is not compatible with '
                        'private IP address or network interface ID '
                        'parameters.')
                raise exception.InvalidParameterCombination(msg)
        if params and 0 not in device_indexes:
            msg = _('When specifying network interfaces, you must include '
                    'a device at index 0.')
            raise exception.UnsupportedOperation(msg)

    def parse_network_interface_parameters(self, context, params):
        vpc_ids = set()
        network_interface_ids = set()
        busy_network_interfaces = []
        network_data = []
        for param in params:
            # TODO(ft): OpenStack doesn't support more than one port in a
            # subnet for an instance, but AWS does it.
            # We should check this before creating any object in OpenStack
            if 'network_interface_id' in param:
                ec2_eni_id = param['network_interface_id']
                if ec2_eni_id in network_interface_ids:
                    msg = _("Network interface ID '%(id)s' "
                            "may not be specified on multiple interfaces.")
                    msg = msg % {'id': ec2_eni_id}
                    raise exception.InvalidParameterValue(msg)
                network_interface = ec2utils.get_db_item(context, ec2_eni_id,
                                                         'eni')
                if 'instance_id' in network_interface:
                    busy_network_interfaces.append(ec2_eni_id)
                vpc_ids.add(network_interface['vpc_id'])
                network_interface_ids.add(ec2_eni_id)
                network_data.append({'device_index': param['device_index'],
                                     'network_interface': network_interface,
                                     'delete_on_termination': False})
            else:
                subnet = ec2utils.get_db_item(context, param['subnet_id'],
                                              'subnet')
                vpc_ids.add(subnet['vpc_id'])
                args = copy.deepcopy(param)
                delete_on_termination = args.pop('delete_on_termination', True)
                args.pop('associate_public_ip_address', None)
                network_data.append(
                    {'device_index': args.pop('device_index'),
                     'create_args': (args.pop('subnet_id'), args),
                     'delete_on_termination': delete_on_termination})

        if busy_network_interfaces:
            raise exception.InvalidNetworkInterfaceInUse(
                    interface_ids=busy_network_interfaces)

        if len(vpc_ids) > 1:
            msg = _('Network interface attachments may not cross '
                    'VPC boundaries.')
            raise exception.InvalidParameterValue(msg)

        # TODO(ft): a race condition can occure like using a network
        # interface for an instance in parallel run_instances, or even
        # deleting a network interface. We should lock such operations

        network_data.sort(key=lambda data: data['device_index'])
        return (next(iter(vpc_ids), None), network_data)

    def create_network_interfaces(self, context, cleaner, network_data):
        for data in network_data:
            if 'create_args' not in data:
                continue
            (subnet_id, args) = data['create_args']
            ec2_network_interface = (
                network_interface_api.create_network_interface(
                    context, subnet_id, **args)['networkInterface'])
            ec2_network_interface_id = (
                ec2_network_interface['networkInterfaceId'])
            cleaner.addCleanup(network_interface_api.delete_network_interface,
                               context,
                               network_interface_id=ec2_network_interface_id)
            # TODO(ft): receive network_interface from a
            # create_network_interface sub-function
            network_interface = db_api.get_item_by_id(context,
                                                      ec2_network_interface_id)
            data['network_interface'] = network_interface

    def get_vpc_default_security_group_id(self, context, vpc_id):
        default_groups = security_group_api.describe_security_groups(
            context,
            filter=[{'name': 'vpc-id', 'value': [vpc_id]},
                    {'name': 'group-name', 'value': ['default']}]
        )['securityGroupInfo']
        security_groups = db_api.get_items_by_ids(
            context, [sg['groupId'] for sg in default_groups])
        return [sg['os_id'] for sg in security_groups]

    def get_ec2_classic_os_network(self, context, neutron):
        os_subnet_ids = [eni['os_id']
                         for eni in db_api.get_items(context, 'subnet')]
        if os_subnet_ids:
            os_subnets = neutron.list_subnets(id=os_subnet_ids,
                fields=['network_id'], tenant_id=context.project_id)['subnets']
            vpc_os_network_ids = set(sn['network_id'] for sn in os_subnets)
        else:
            vpc_os_network_ids = []
        os_networks = neutron.list_networks(**{'router:external': False,
            'fields': ['id'], 'tenant_id': context.project_id})['networks']
        ec2_classic_os_networks = [n for n in os_networks
                                   if n['id'] not in vpc_os_network_ids]
        if len(ec2_classic_os_networks) == 0:
            raise exception.Unsupported(
                    reason=_('There are no available networks '
                             'for EC2 Classic mode'))
        if len(ec2_classic_os_networks) > 1:
            raise exception.Unsupported(
                    reason=_('There is more than one available network '
                             'for EC2 Classic mode'))
        return ec2_classic_os_networks[0]


class InstanceEngineNova(object):

    def get_vpc_and_build_launch_context(
            self, context, security_group,
            subnet_id, private_ip_address, security_group_id,
            network_interface, multiple_instances):
        # TODO(ft): check emptiness of vpc related parameters

        return None, {'security_groups': security_group}

    def get_launch_extra_parameters(self, context, cleaner, launch_context):
        return {'security_groups': launch_context['security_groups']}

    def post_launch_action(self, context, cleaner, launch_context,
                           instance_id):
        pass

    def get_ec2_network_interfaces(self, context, instance_ids=None):
        return {}


instance_engine = get_instance_engine()


def _auto_create_instance_extension(context, instance, os_instance=None):
    if not os_instance:
        nova = clients.nova(context)
        os_instance = nova.servers.get(instance['os_id'])
    if hasattr(os_instance, 'OS-EXT-SRV-ATTR:reservation_id'):
        instance['reservation_id'] = getattr(os_instance,
                                             'OS-EXT-SRV-ATTR:reservation_id')
        instance['launch_index'] = getattr(os_instance,
                                           'OS-EXT-SRV-ATTR:launch_index')
    else:
        # NOTE(ft): partial compatibility with pre Kilo OS releases
        instance['reservation_id'] = _generate_reservation_id()
        instance['launch_index'] = 0


ec2utils.register_auto_create_db_item_extension(
    'i', _auto_create_instance_extension)


# NOTE(ft): following functions are copied from various parts of Nova
# TODO: [varun] This function needs to be deprecated
def _cloud_parse_block_device_mapping(context, bdm):
    """Parse BlockDeviceMappingItemType into flat hash

    BlockDevicedMapping.<N>.DeviceName
    BlockDevicedMapping.<N>.Ebs.SnapshotId
    BlockDevicedMapping.<N>.Ebs.VolumeSize
    BlockDevicedMapping.<N>.Ebs.DeleteOnTermination
    BlockDevicedMapping.<N>.Ebs.NoDevice
    BlockDevicedMapping.<N>.VirtualName
    => remove .Ebs and allow volume id in SnapshotId
    """
    ebs = bdm.pop('ebs', None)
    if ebs:
        ec2_id = ebs.pop('snapshot_id', None)
        if ec2_id:
            if ec2_id.startswith('snap-'):
                snapshot = ec2utils.get_db_item(context, ec2_id)
                bdm['snapshot_id'] = snapshot['os_id']
            elif ec2_id.startswith('vol-'):
                volume = ec2utils.get_db_item(context, ec2_id)
                bdm['volume_id'] = volume['os_id']
            else:
                # NOTE(ft): AWS returns undocumented InvalidSnapshotID.NotFound
                raise exception.InvalidSnapshotIDMalformed(snapshot_id=ec2_id)
            ebs.setdefault('delete_on_termination', True)
        bdm.update(ebs)
    return bdm


def _cloud_get_image_state(image):
    state = image.status
    if state == 'active':
        state = 'available'
    return image.properties.get('image_state', state)


def _cloud_format_kernel_id(context, os_instance, image_ids=None):
    os_kernel_id = getattr(os_instance, 'OS-EXT-SRV-ATTR:kernel_id', None)
    if os_kernel_id is None or os_kernel_id == '':
        return
    return ec2utils.os_id_to_ec2_id(context, 'aki', os_kernel_id,
                                    ids_by_os_id=image_ids)


def _cloud_format_ramdisk_id(context, os_instance, image_ids=None):
    os_ramdisk_id = getattr(os_instance, 'OS-EXT-SRV-ATTR:ramdisk_id', None)
    if os_ramdisk_id is None or os_ramdisk_id == '':
        return
    return ec2utils.os_id_to_ec2_id(context, 'ari', os_ramdisk_id,
                                    ids_by_os_id=image_ids)

def _cloud_state_find(os_instance):
    vm_state=getattr(os_instance, 'OS-EXT-STS:vm_state')
    task_state=getattr(os_instance,'OS-EXT-STS:task_state')
    try: 
        old_task_state=getattr(os_instance,'old_task_state')
    except AttributeError:
        LOG.warning("Unable to find attribute old_task_state in instance \
                   info from NOVA")
        old_task_state=None

    if task_state is not None:
        name = _TASK_STATE_TO_EC2_STATE.get(task_state)
    elif vm_state !="error":
        if vm_state==inst_state_STOPPED and  \
           old_task_state==inst_task_state_powering_on:
            name = _TASK_STATE_TO_EC2_STATE.get(old_task_state)
        else:
            name = _STATE_DESCRIPTION_MAP.get(vm_state, vm_state)
    elif old_task_state is not None:
        name = _TASK_STATE_TO_EC2_STATE.get(old_task_state)
    else:
        name = _STATE_DESCRIPTION_MAP.get(vm_state,vm_state)
             
    return {'code': inst_state_name_to_code(name),
            'name': name}


def _cloud_format_instance_type(context, os_instance):
    return clients.nova(context).flavors.get(os_instance.flavor['id']).name

def _cloud_state_description(vm_state):
    """Map the vm state to the server status string."""
    # Note(maoy): We do not provide EC2 compatibility
    # in shutdown_terminate flag behavior. So we ignore
    # it here.
    name = _STATE_DESCRIPTION_MAP.get(vm_state, vm_state)
    return name
    # [varun]
    # For now we will only return name of the state and not the code
    # This is as per the JCS API for compute
    # TODO: Remove the following code after testing
    # return {'code': inst_state_name_to_code(name),
    #        'name': name}


def _cloud_format_instance_bdm(context, os_instance, result,
                               volumes=None, os_volumes=None):
    """Format InstanceBlockDeviceMappingResponseItemType."""
    root_device_name = getattr(os_instance,
                               'OS-EXT-SRV-ATTR:root_device_name', None)
    if not root_device_name:
        root_device_short_name = root_device_type = None
    else:
        root_device_type = 'instance-store'
        root_device_short_name = _block_device_strip_dev(root_device_name)
        if root_device_name == root_device_short_name:
            root_device_name = _block_device_prepend_dev(root_device_name)
    mapping = []
    if os_volumes is None:
        os_volumes = _get_os_volumes(context)
    # NOTE(ft): Attaching volumes are not reported, because Cinder
    # volume doesn't yet contain attachment info at this stage, but Nova v2.3
    # instance volumes_attached doesn't contain a device name.
    # But a bdm must contain the last one.
    volumes_attached = getattr(os_instance,
                               'os-extended-volumes:volumes_attached', [])
    for os_volume in os_volumes[os_instance.id]:
        os_attachment = next(iter(os_volume.attachments), {})
        bdm_entry = {}
        device_name = os_attachment.get('device')
        if not device_name:
            continue
        else:
            bdm_entry['deviceName'] = device_name
        if (device_name == root_device_name or
                device_name == root_device_short_name):
            root_device_type = 'ebs'

        #volume = ec2utils.get_db_item_by_os_id(context, 'vol', os_volume.id,
        #                                       volumes)
        # TODO(yamahata): volume attach time
        bdm_entry['volumeId'] = os_volume.id
        bdm_entry['status'] = _cloud_get_volume_attach_status(os_volume)
        volume_attached = next((va for va in volumes_attached
                                if va['id'] == os_volume.id), None)
        if volume_attached and 'delete_on_termination' in volume_attached:
            bdm_entry['deleteOnTermination'] = (
                volume_attached['delete_on_termination'])
        mapping.append(bdm_entry)

    if mapping:
        result['blockDeviceMapping'] = mapping
    if root_device_type:
        result['rootDeviceType'] = root_device_type


def _cloud_get_volume_attach_status(volume):
    if volume.status in ('attaching', 'detaching'):
        return volume.status
    elif volume.attachments:
        return 'attached'
    else:
        return 'detached'


_dev = re.compile('^/dev/')


def _block_device_strip_dev(device_name):
    """remove leading '/dev/'."""
    return _dev.sub('', device_name) if device_name else device_name


def _block_device_prepend_dev(device_name):
    """Make sure there is a leading '/dev/'."""
    return device_name and '/dev/' + _block_device_strip_dev(device_name)


def _utils_generate_uid(topic, size=8):
    characters = '01234567890abcdefghijklmnopqrstuvwxyz'
    choices = [random.choice(characters) for _x in xrange(size)]
    return '%s-%s' % (topic, ''.join(choices))


# NOTE(ft): nova/compute/vm_states.py

"""Possible vm states for instances.

Compute instance vm states represent the state of an instance as it pertains to
a user or administrator.

vm_state describes a VM's current stable (not transition) state. That is, if
there is no ongoing compute API calls (running tasks), vm_state should reflect
what the customer expect the VM to be. When combined with task states
(task_states.py), a better picture can be formed regarding the instance's
health and progress.

See http://wiki.openstack.org/VMState
"""

vm_states_ACTIVE = 'active'  # VM is running
vm_states_BUILDING = 'building'  # VM only exists in DB
vm_states_PAUSED = 'paused'
vm_states_SUSPENDED = 'suspended'  # VM is suspended to disk.
vm_states_STOPPED = 'stopped'  # VM is powered off, the disk image is still
# there.
vm_states_RESCUED = 'rescued'  # A rescue image is running with the original VM
# image attached.
vm_states_RESIZED = 'resized'  # a VM with the new size is active. The user is
# expected to manually confirm or revert.

vm_states_SOFT_DELETED = 'soft-delete'  # VM is marked as deleted but the disk
# images are still available to restore.
vm_states_DELETED = 'deleted'  # VM is permanently deleted.

vm_states_ERROR = 'error'

vm_states_SHELVED = 'shelved'  # VM is powered off, resources still on
# hypervisor
vm_states_SHELVED_OFFLOADED = 'shelved_offloaded'  # VM and associated
# resources are not on hypervisor

vm_states_WIPED_OUT = 'wiped_out'  # Artificial state, added for state
# of VM which was just deleted and is not reported by OpenStack anymore.

vm_states_ALLOW_SOFT_REBOOT = [vm_states_ACTIVE]  # states we can soft reboot
# from
vm_states_ALLOW_HARD_REBOOT = (
    vm_states_ALLOW_SOFT_REBOOT +
    [vm_states_STOPPED, vm_states_PAUSED, vm_states_SUSPENDED,
     vm_states_ERROR])
# states we allow hard reboot from

# NOTE(ft): end of nova/compute/vm_states.py

# NOTE(ft): nova/api/ec2/inst_states.py

inst_state_PENDING_CODE = 0
inst_state_RUNNING_CODE = 16
inst_state_SHUTTING_DOWN_CODE = 32
inst_state_TERMINATED_CODE = 48
inst_state_STOPPING_CODE = 64
inst_state_STOPPED_CODE = 80

inst_state_PENDING = 'pending'
inst_state_RUNNING = 'running'
inst_state_SHUTTING_DOWN = 'shutting-down'
inst_state_TERMINATED = 'terminated'
inst_state_STOPPING = 'stopping'
inst_state_STOPPED = 'stopped'

# non-ec2 value
inst_state_MIGRATE = 'migrate'
inst_state_RESIZE = 'resize'
inst_state_PAUSE = 'pause'
inst_state_SUSPEND = 'suspend'
inst_state_RESCUE = 'rescue'

inst_task_state_scheduling = 'scheduling'
inst_task_state_networking = 'networking'
inst_task_state_bdm = 'block_device_mapping'
inst_task_state_spawning = 'spawning'
inst_task_state_powering_off = 'powering-off'
inst_task_state_powering_on = 'powering-on'
inst_task_state_deleting = 'deleting'

_TASK_STATE_TO_EC2_STATE = {
    inst_task_state_scheduling: inst_state_PENDING,
    inst_task_state_networking: inst_state_PENDING,
    inst_task_state_bdm: inst_state_PENDING,
    inst_task_state_spawning: inst_state_PENDING,
    inst_task_state_powering_off: inst_state_STOPPING,
    inst_task_state_powering_on: inst_state_PENDING,
    inst_task_state_deleting: inst_state_SHUTTING_DOWN,
}

# EC2 API instance status code
_NAME_TO_CODE = {
    inst_state_PENDING: inst_state_PENDING_CODE,
    inst_state_RUNNING: inst_state_RUNNING_CODE,
    inst_state_SHUTTING_DOWN: inst_state_SHUTTING_DOWN_CODE,
    inst_state_TERMINATED: inst_state_TERMINATED_CODE,
    inst_state_STOPPING: inst_state_STOPPING_CODE,
    inst_state_STOPPED: inst_state_STOPPED_CODE,

    # approximation
    inst_state_MIGRATE: inst_state_RUNNING_CODE,
    inst_state_RESIZE: inst_state_RUNNING_CODE,
    inst_state_PAUSE: inst_state_STOPPED_CODE,
    inst_state_SUSPEND: inst_state_STOPPED_CODE,
    inst_state_RESCUE: inst_state_RUNNING_CODE,
}
_CODE_TO_NAMES = {code: [item[0] for item in _NAME_TO_CODE.iteritems()
                         if item[1] == code]
                  for code in set(_NAME_TO_CODE.itervalues())}


def inst_state_name_to_code(name):
    return _NAME_TO_CODE.get(name, inst_state_PENDING_CODE)


# NOTE(ft): end of nova/api/ec2/inst_state.py

# EC2 API can return the following values as documented in the EC2 API
# http://docs.amazonwebservices.com/AWSEC2/latest/APIReference/
#    ApiReference-ItemType-InstanceStateType.html
# pending 0 | running 16 | shutting-down 32 | terminated 48 | stopping 64 |
# stopped 80
_STATE_DESCRIPTION_MAP = {
    None: inst_state_PENDING,
    vm_states_ACTIVE: inst_state_RUNNING,
    vm_states_BUILDING: inst_state_PENDING,
    vm_states_DELETED: inst_state_SHUTTING_DOWN,
    vm_states_SOFT_DELETED: inst_state_SHUTTING_DOWN,
    vm_states_STOPPED: inst_state_STOPPED,
    vm_states_PAUSED: inst_state_PAUSE,
    vm_states_SUSPENDED: inst_state_SUSPEND,
    vm_states_RESCUED: inst_state_RESCUE,
    vm_states_RESIZED: inst_state_RESIZE,
    vm_states_WIPED_OUT: inst_state_TERMINATED
}
