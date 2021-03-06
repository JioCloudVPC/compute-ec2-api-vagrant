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

from novaclient import exceptions as nova_exception
from oslo_config import cfg
from oslo_log import log as logging

from ec2api.api import clients
from ec2api.api import common
from ec2api import exception
from ec2api.i18n import _


CONF = cfg.CONF
LOG = logging.getLogger(__name__)


"""Keypair-object related API implementation
"""


Validator = common.Validator


class KeyPairDescriber(common.UniversalDescriber):

    KIND = 'kp'
    FILTER_MAP = {'fingerprint': 'keyFingerprint',
                  'key-name': 'keyName'}

    def format(self, _item, key_pair):
        return _format_key_pair(key_pair)

    def get_db_items(self):
        return []

    def get_os_items(self):
        # Original EC2 in nova filters out vpn keys for admin user.
        # We're not filtering out the vpn keys for now.
        # In order to implement this we'd have to configure vpn_key_suffix
        # in our config which we consider an overkill.
        # suffix = CONF.vpn_key_suffix
        # if context.is_admin or not key_pair['name'].endswith(suffix):
        nova = clients.nova(self.context)
        return nova.keypairs.list()

    def auto_update_db(self, item, os_item):
        pass

    def get_id(self, os_item):
        return ''

    def get_name(self, key_pair):
        return key_pair.name


def describe_key_pairs(context, key_name=None, filter=None):
    formatted_key_pairs = KeyPairDescriber().describe(context, names=key_name,
                                                      filter=filter)
    return {'keySet': formatted_key_pairs}


def _validate_name(name):
    if len(name) > 255:
        raise exception.InvalidParameterValue(
            value=name,
            parameter='KeyName',
            reason='lenght is exceeds maximum of 255')


def create_key_pair(context, key_name):
    _validate_name(key_name)
    nova = clients.nova(context)
    try:
        key_pair = nova.keypairs.create(key_name)
    except nova_exception.OverLimit:
        raise exception.ResourceLimitExceeded(resource='keypairs')
    except nova_exception.Conflict:
        raise exception.InvalidKeyPairDuplicate(key_name=key_name)
    formatted_key_pair = _format_key_pair(key_pair)
    formatted_key_pair['keyMaterial'] = key_pair.private_key
    return formatted_key_pair


def import_key_pair(context, key_name, public_key_material):
    _validate_name(key_name)
    if not public_key_material:
        raise exception.MissingParameter(
            _('The request must contain the parameter PublicKeyMaterial'))
    nova = clients.nova(context)
    public_key = base64.b64decode(public_key_material)
    try:
        key_pair = nova.keypairs.create(key_name, public_key)
    except nova_exception.OverLimit:
        raise exception.ResourceLimitExceeded(resource='keypairs')
    except nova_exception.Conflict:
        raise exception.InvalidKeyPairDuplicate(key_name=key_name)
    return _format_key_pair(key_pair)


def delete_key_pair(context, key_name):
    nova = clients.nova(context)
    try:
        nova.keypairs.delete(key_name)
    except nova_exception.NotFound:
        # aws returns true even if the key doesn't exist
        # AK - but we are not aws
        raise exception.InvalidKeypairNotFound(id=key_name)
    return True


def _format_key_pair(key_pair):
    return {'keyName': key_pair.name,
            'keyFingerprint': key_pair.fingerprint
            }
