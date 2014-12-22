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

import re

import netaddr

from ec2api import context
from ec2api.db import api as db_api
from ec2api import exception
from ec2api import novadb
from ec2api.openstack.common.gettextutils import _
from ec2api.openstack.common import log as logging
from ec2api.openstack.common import timeutils
from ec2api.openstack.common import uuidutils

LOG = logging.getLogger(__name__)


def image_type(image_type):
    """Converts to a three letter image type.

    aki, kernel => aki
    ari, ramdisk => ari
    anything else => ami

    """
    if image_type == 'kernel':
        return 'aki'
    if image_type == 'ramdisk':
        return 'ari'
    if image_type not in ['aki', 'ari']:
        return 'ami'
    return image_type


_c2u = re.compile('(((?<=[a-z])[A-Z])|([A-Z](?![A-Z]|$)))')


def camelcase_to_underscore(str):
    return _c2u.sub(r'_\1', str).lower().strip('_')


def _try_convert(value):
    """Return a non-string from a string or unicode, if possible.

    ============= =====================================================
    When value is returns
    ============= =====================================================
    zero-length   ''
    'None'        None
    'True'        True case insensitive
    'False'       False case insensitive
    '0', '-0'     0
    0xN, -0xN     int from hex (positive) (N is any number)
    0bN, -0bN     int from binary (positive) (N is any number)
    *             try conversion to int, float, complex, fallback value

    """
    def _negative_zero(value):
        epsilon = 1e-7
        return 0 if abs(value) < epsilon else value

    if len(value) == 0:
        return ''
    if value == 'None':
        return None
    lowered_value = value.lower()
    if lowered_value == 'true':
        return True
    if lowered_value == 'false':
        return False
    for prefix, base in [('0x', 16), ('0b', 2), ('0', 8), ('', 10)]:
        try:
            if lowered_value.startswith((prefix, "-" + prefix)):
                return int(lowered_value, base)
        except ValueError:
            pass
    try:
        return _negative_zero(float(value))
    except ValueError:
        return value


def dict_from_dotted_str(items):
    """parse multi dot-separated argument into dict.

    EBS boot uses multi dot-separated arguments like
    BlockDeviceMapping.1.DeviceName=snap-id
    Convert the above into
    {'block_device_mapping': {'1': {'device_name': snap-id}}}
    """
    args = {}
    for key, value in items:
        parts = key.split(".")
        key = str(camelcase_to_underscore(parts[0]))
        if isinstance(value, str) or isinstance(value, unicode):
            # NOTE(vish): Automatically convert strings back
            #             into their respective values
            value = _try_convert(value)

            if len(parts) > 1:
                d = args.get(key, {})
                args[key] = d
                for k in parts[1:-1]:
                    k = camelcase_to_underscore(k)
                    v = d.get(k, {})
                    d[k] = v
                    d = v
                d[camelcase_to_underscore(parts[-1])] = value
            else:
                args[key] = value

    return args


_ms_time_regex = re.compile('^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3,6}Z$')


def is_ec2_timestamp_expired(request, expires=None):
    """Checks the timestamp or expiry time included in an EC2 request

    and returns true if the request is expired
    """
    query_time = None
    timestamp = request.get('Timestamp')
    expiry_time = request.get('Expires')

    def parse_strtime(strtime):
        if _ms_time_regex.match(strtime):
            # NOTE(MotoKen): time format for aws-sdk-java contains millisecond
            time_format = "%Y-%m-%dT%H:%M:%S.%fZ"
        else:
            time_format = "%Y-%m-%dT%H:%M:%SZ"
        return timeutils.parse_strtime(strtime, time_format)

    try:
        if timestamp and expiry_time:
            msg = _("Request must include either Timestamp or Expires,"
                    " but cannot contain both")
            LOG.error(msg)
            raise exception.InvalidRequest(msg)
        elif expiry_time:
            query_time = parse_strtime(expiry_time)
            return timeutils.is_older_than(query_time, -1)
        elif timestamp:
            query_time = parse_strtime(timestamp)

            # Check if the difference between the timestamp in the request
            # and the time on our servers is larger than 5 minutes, the
            # request is too old (or too new).
            if query_time and expires:
                return (timeutils.is_older_than(query_time, expires) or
                        timeutils.is_newer_than(query_time, expires))
        return False
    except ValueError:
        LOG.audit(_("Timestamp is invalid."))
        return True


def id_to_glance_id(context, image_id):
    """Convert an internal (db) id to a glance id."""
    return novadb.s3_image_get(context, image_id)['uuid']


def glance_id_to_id(context, glance_id):
    """Convert a glance id to an internal (db) id."""
    if glance_id is None:
        return
    try:
        return novadb.s3_image_get_by_uuid(context, glance_id)['id']
    except exception.NotFound:
        return novadb.s3_image_create(context, glance_id)['id']


def ec2_id_to_glance_id(context, ec2_id):
    image_id = ec2_id_to_id(ec2_id)
    return id_to_glance_id(context, image_id)


def glance_id_to_ec2_id(context, glance_id, image_type='ami'):
    image_id = glance_id_to_id(context, glance_id)
    return image_ec2_id(image_id, image_type=image_type)


# TODO(Alex) This function is copied as is from original cloud.py. It doesn't
# check for the prefix which allows any prefix used for any object.
def ec2_id_to_id(ec2_id):
    """Convert an ec2 ID (i-[base 16 number]) to an instance id (int)."""
    try:
        return int(ec2_id.split('-')[-1], 16)
    except ValueError:
        raise exception.InvalidId(id=ec2_id)


def image_ec2_id(image_id, image_type='ami'):
    """Returns image ec2_id using id and three letter type."""
    template = image_type + '-%08x'
    return id_to_ec2_id(image_id, template=template)


def id_to_ec2_id(instance_id, template='i-%08x'):
    """Convert an instance ID (int) to an ec2 ID (i-[base 16 number])."""
    return template % int(instance_id)


def id_to_ec2_inst_id(instance_id):
    """Get or create an ec2 instance ID (i-[base 16 number]) from uuid."""
    if instance_id is None:
        return None
    elif uuidutils.is_uuid_like(instance_id):
        ctxt = context.get_admin_context()
        int_id = get_int_id_from_instance_uuid(ctxt, instance_id)
        return id_to_ec2_id(int_id)
    else:
        return id_to_ec2_id(instance_id)


def ec2_inst_id_to_uuid(context, ec2_id):
    """"Convert an instance id to uuid."""
    int_id = ec2_id_to_id(ec2_id)
    return get_instance_uuid_from_int_id(context, int_id)


def get_instance_uuid_from_int_id(context, int_id):
    return novadb.get_instance_uuid_by_ec2_id(context, int_id)


def get_int_id_from_instance_uuid(context, instance_uuid):
    if instance_uuid is None:
        return
    try:
        return novadb.get_ec2_instance_id_by_uuid(context, instance_uuid)
    except exception.NotFound:
        return novadb.ec2_instance_create(context, instance_uuid)['id']


def get_volume_uuid_from_int_id(context, int_id):
    return novadb.get_volume_uuid_by_ec2_id(context, int_id)


def id_to_ec2_snap_id(snapshot_id):
    """Get or create an ec2 volume ID (vol-[base 16 number]) from uuid."""
    if uuidutils.is_uuid_like(snapshot_id):
        ctxt = context.get_admin_context()
        int_id = get_int_id_from_snapshot_uuid(ctxt, snapshot_id)
        return id_to_ec2_id(int_id, 'snap-%08x')
    else:
        return id_to_ec2_id(snapshot_id, 'snap-%08x')


def id_to_ec2_vol_id(volume_id):
    """Get or create an ec2 volume ID (vol-[base 16 number]) from uuid."""
    if uuidutils.is_uuid_like(volume_id):
        ctxt = context.get_admin_context()
        int_id = get_int_id_from_volume_uuid(ctxt, volume_id)
        return id_to_ec2_id(int_id, 'vol-%08x')
    else:
        return id_to_ec2_id(volume_id, 'vol-%08x')


def get_int_id_from_volume_uuid(context, volume_uuid):
    if volume_uuid is None:
        return
    try:
        return novadb.get_ec2_volume_id_by_uuid(context, volume_uuid)
    except exception.NotFound:
        return novadb.ec2_volume_create(context, volume_uuid)['id']


def ec2_vol_id_to_uuid(ec2_id):
    """Get the corresponding UUID for the given ec2-id."""
    ctxt = context.get_admin_context()

    # NOTE(jgriffith) first strip prefix to get just the numeric
    int_id = ec2_id_to_id(ec2_id)
    return get_volume_uuid_from_int_id(ctxt, int_id)


def get_snapshot_uuid_from_int_id(context, int_id):
    return novadb.get_snapshot_uuid_by_ec2_id(context, int_id)


def ec2_snap_id_to_uuid(ec2_id):
    """Get the corresponding UUID for the given ec2-id."""
    ctxt = context.get_admin_context()

    # NOTE(jgriffith) first strip prefix to get just the numeric
    int_id = ec2_id_to_id(ec2_id)
    return get_snapshot_uuid_from_int_id(ctxt, int_id)


def get_int_id_from_snapshot_uuid(context, snapshot_uuid):
    if snapshot_uuid is None:
        return
    try:
        return novadb.get_ec2_snapshot_id_by_uuid(context, snapshot_uuid)
    except exception.NotFound:
        return novadb.ec2_snapshot_create(context, snapshot_uuid)['id']

# NOTE(ft): extra functions to use in vpc specific code or instead of
# malformed existed functions


def change_ec2_id_kind(obj_id, new_kind):
    return '%(kind)s-%(id)s' % {'kind': new_kind,
                                'id': obj_id.split('-')[-1]}

_NOT_FOUND_EXCEPTION_MAP = {
    'vpc': exception.InvalidVpcIDNotFound,
    'igw': exception.InvalidInternetGatewayIDNotFound,
    'subnet': exception.InvalidSubnetIDNotFound,
    'eni': exception.InvalidNetworkInterfaceIDNotFound,
    'dopt': exception.InvalidDhcpOptionsIDNotFound,
    'eipalloc': exception.InvalidAllocationIDNotFound,
    'sg': exception.InvalidGroupNotFound,
    'rtb': exception.InvalidRouteTableIDNotFound,
    'i': exception.InvalidInstanceIDNotFound,
    'kp': exception.InvalidKeypairNotFound,
    'az': exception.InvalidAvailabilityZoneNotFound,
    'vol': exception.InvalidVolumeNotFound,
    'snap': exception.InvalidSnapshotNotFound,
    'ami': exception.InvalidAMIIDNotFound,
}


def get_db_item(context, kind, ec2_id):
    item = db_api.get_item_by_id(context, kind, ec2_id)
    if item is None:
        params = {'id': ec2_id}
        raise _NOT_FOUND_EXCEPTION_MAP[kind](**params)
    return item


def get_db_items(context, kind, ec2_ids):
    if not ec2_ids:
        return db_api.get_items(context, kind)

    if not isinstance(ec2_ids, set):
        ec2_ids = set(ec2_ids)
    items = db_api.get_items_by_ids(context, kind, ec2_ids)
    if len(items) < len(ec2_ids):
        missed_ids = ec2_ids - set((item['id'] for item in items))
        params = {'id': next(iter(missed_ids))}
        raise _NOT_FOUND_EXCEPTION_MAP[kind](**params)
    return items


_auto_create_db_item_extensions = {}


def register_auto_create_db_item_extension(kind, extension):
    _auto_create_db_item_extensions[kind] = extension


def auto_create_db_item(context, kind, os_id, **extension_kwargs):
    item = {'os_id': os_id}
    extension = _auto_create_db_item_extensions.get(kind)
    if extension:
        extension(context, item, **extension_kwargs)
    return db_api.add_item(context, kind, item)


def get_db_item_by_os_id(context, kind, os_id, items_by_os_id=None,
                         **extension_kwargs):
    """Get DB item by OS id (create if it doesn't exist).

        Args:
            context (RequestContext): The request context.
            kind (str): The kind of item.
            os_id (str): OS id of an object.
            items_by_os_id (dict of items): The dict of known DB items,
                OS id is used as a key.
            extension_kwargs (dict): Additional parameters passed to
                a registered extension at creating item.

        Returns:
            A found or created item.

        Search item in passed dict. If it's not found - create a new item, and
        add it to the dict (if it's passed).
        If an extension is registered on corresponding item kind, call it
        passing extension_kwargs to it.
    """
    if os_id is None:
        return None
    if items_by_os_id is not None:
        item = items_by_os_id.get(os_id)
        if item:
            return item
    else:
        item = next((i for i in db_api.get_items(context, kind)
                     if i['os_id'] == os_id), None)
    if not item:
        item = auto_create_db_item(context, kind, os_id, **extension_kwargs)
    else:
        pass
    if items_by_os_id is not None:
        items_by_os_id[os_id] = item
    return item


def os_id_to_ec2_id(context, kind, os_id, items_by_os_id=None,
                    ids_by_os_id=None):
    if os_id is None:
        return None
    if ids_by_os_id is not None:
        item_id = ids_by_os_id.get(os_id)
        if item_id:
            return item_id
    if items_by_os_id is not None:
        item = items_by_os_id.get(os_id)
        if item:
            return item['id']
    ids = db_api.get_item_ids(context, kind, (os_id,))
    if len(ids):
        item_id, _os_id = ids[0]
    else:
        item_id = db_api.add_item_id(context, kind, os_id)
    if ids_by_os_id is not None:
        ids_by_os_id[os_id] = item_id
    return item_id


def _is_valid_cidr(address):
    """Check if address is valid

    The provided address can be a IPv6 or a IPv4
    CIDR address.
    """
    try:
        # Validate the correct CIDR Address
        netaddr.IPNetwork(address)
    except netaddr.core.AddrFormatError:
        return False
    except UnboundLocalError:
        # NOTE(MotoKen): work around bug in netaddr 0.7.5 (see detail in
        # https://github.com/drkjam/netaddr/issues/2)
        return False

    # Prior validation partially verify /xx part
    # Verify it here
    ip_segment = address.split('/')

    if (len(ip_segment) <= 1 or
            ip_segment[1] == ''):
        return False

    return True


def validate_cidr_with_ipv6(cidr, parameter_name):
    invalid_format_exception = exception.InvalidParameterValue(
        value=cidr,
        parameter=parameter_name,
        reason='This is not a valid CIDR block.')
    if not _is_valid_cidr(cidr):
        raise invalid_format_exception


_cidr_re = re.compile("^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$")


def validate_cidr(cidr, parameter_name):
    invalid_format_exception = exception.InvalidParameterValue(
        value=cidr,
        parameter=parameter_name,
        reason='This is not a valid CIDR block.')
    if not _cidr_re.match(cidr):
        raise invalid_format_exception
    address, size = cidr.split("/")
    octets = address.split(".")
    if any(int(octet) > 255 for octet in octets):
        raise invalid_format_exception
    size = int(size)
    if size > 32:
        raise invalid_format_exception


def validate_vpc_cidr(cidr, invalid_cidr_exception_class):
    validate_cidr(cidr, 'cidrBlock')
    size = int(cidr.split("/")[-1])
    if size > 28 or size < 16:
        raise invalid_cidr_exception_class(cidr_block=cidr)
