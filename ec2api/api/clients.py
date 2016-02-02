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


from novaclient import client as novaclient
from novaclient import exceptions as nova_exception
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging as messaging

from ec2api import context as ec2_context
from ec2api.i18n import _, _LW

logger = logging.getLogger(__name__)

ec2_opts = [
  cfg.StrOpt('cinder_service_type',
  	      default='volumev2',
              help='Service type of Cinder Volume API, registered in Keystone catalog.'),
  cfg.StrOpt('volume_api_version',
              default='2',
              help='volume api version'),
]
service_catalog_opts = [
    cfg.StrOpt('compute',
               default='http://localhost:8774/v2/TENANT_ID',
               help='Endpoint for Compute Service '),
    cfg.StrOpt('image',
               default='http://localhost:9292',
               help='Endpoint for Image Service '),
    cfg.StrOpt('volumev2',
               default='http://localhost:8776/v2/TENANT_ID',
               help='Endpoint for Volume Service '),
    cfg.StrOpt('network',
               default='http://localhost:9696',
               help='Endpoint for Network Service '),
    ]


SERVICE_CATALOG_GROUP = 'service_catalog'

CONF = cfg.CONF
CONF.register_opts(service_catalog_opts, SERVICE_CATALOG_GROUP)
CONF.register_opts(ec2_opts)

try:
    from neutronclient.v2_0 import client as neutronclient
except ImportError:
    neutronclient = None
    logger.info(_('neutronclient not available'))
try:
    from cinderclient import client as cinderclient
except ImportError:
    cinderclient = None
    logger.info(_('cinderclient not available'))
try:
    from glanceclient import client as glanceclient
except ImportError:
    glanceclient = None
    logger.info(_('glanceclient not available'))


# Nova API's 2.3 microversion provides additional EC2 compliant instance
# properties
_novaclient_vertion = '2.3'
_nova_service_type = 'compute'


def nova(context):
    args = {
        'auth_url': CONF.keystone_url,
        'auth_token': context.auth_token,
        # NOTE(ft): These parameters are not used for authentification,
        # but are required by novaclient < v2.18 which may be installed in
        # Icehouse deployment
        'username': None,
        'api_key': None,
        'project_id': None,
        'insecure': CONF.ssl_insecure,
        'cacert': CONF.ssl_ca_file
    }
    global _novaclient_vertion, _nova_service_type
    bypass_url = _url_for(context, service_type=_nova_service_type)
    if not bypass_url and _nova_service_type == 'computev21':
        # NOTE(ft): partial compatibility with pre Kilo OS releases:
        # if computev21 isn't provided by Nova, use compute instead
        logger.warning(_LW("Nova server doesn't support v2.1, use v2 instead. "
                           "A lot of useful EC2 compliant instance properties "
                           "will be unavailable."))
        _nova_service_type = 'compute'
        return nova(context)
    try:
        return novaclient.Client(_novaclient_vertion, bypass_url=bypass_url,
                                 **args)
    except nova_exception.UnsupportedVersion:
        if _novaclient_vertion == '2':
            raise
        # NOTE(ft): partial compatibility with Nova client w/o microversion
        # support
        logger.warning(_LW("Nova client doesn't support v2.3, use v2 instead. "
                           "A lot of useful EC2 compliant instance properties "
                           "will be unavailable."))
        _novaclient_vertion = '2'
        return nova(context)


def neutron(context):
    if neutronclient is None:
        return None

    args = {
        'auth_url': CONF.keystone_url,
        'service_type': 'network',
        'token': context.auth_token,
        'endpoint_url': _url_for(context, service_type='network'),
        'insecure': CONF.ssl_insecure,
        'cacert': CONF.ssl_ca_file
    }

    return neutronclient.Client(**args)


def glance(context):
    if glanceclient is None:
        return None

    args = {
        'auth_url': CONF.keystone_url,
        'service_type': 'image',
        'token': context.auth_token,
        'insecure': CONF.ssl_insecure,
        'cacert': CONF.ssl_ca_file
    }

    return glanceclient.Client(
        "1", endpoint=_url_for(context, service_type='image'), **args)


def cinder(context):
    if cinderclient is None:
        return nova(context, CONF.cinder_service_type)

    args = {
        'service_type': CONF.cinder_service_type,
        'auth_url': CONF.keystone_url,
        'username': None,
        'api_key': None,
        'insecure': CONF.ssl_insecure,
        'cacert': CONF.ssl_ca_file
    }

    _cinder = cinderclient.Client(CONF.volume_api_version, **args)
    management_url = _url_for(context, service_type=CONF.cinder_service_type)
    _cinder.client.auth_token = context.auth_token
    _cinder.client.management_url = management_url

    return _cinder


def keystone(context):
    keystone_client_class = ec2_context.get_keystone_client_class()
    return keystone_client_class(
        token=context.auth_token,
        project_id=context.project_id,
        tenant_id=context.project_id,
        auth_url=CONF.keystone_url,
        insecure=CONF.ssl_insecure,
        cacert=CONF.ssl_ca_file)


def nova_cert(context):
    _cert_api = _rpcapi_CertAPI(context)
    return _cert_api


def _url_for(context, **kwargs):
    service_type = kwargs['service_type']
    if service_type == 'compute':
        url = CONF.service_catalog.compute
        url = url.replace('TENANT_ID', context.project_id)
    elif service_type == 'image':
        url = CONF.service_catalog.image
    elif service_type == 'network':
        url = CONF.service_catalog.network
    elif service_type == 'volumev2':
        url = CONF.service_catalog.volumev2
        url = url.replace('TENANT_ID', context.project_id)
    else:
        logger.warning(_LW("Unknown service type in JCS Layer."))
    return url


class _rpcapi_CertAPI(object):
    '''Client side of the cert rpc API.'''

    def __init__(self, context):
        super(_rpcapi_CertAPI, self).__init__()
        target = messaging.Target(topic=CONF.cert_topic, version='2.0')
        self.client = _rpc_get_client(target)
        self.context = context

    def decrypt_text(self, text):
        cctxt = self.client.prepare()
        return cctxt.call(self.context, 'decrypt_text',
                          project_id=self.context.project_id,
                          text=text)


_rpc_TRANSPORT = None


def _rpc_init(conf):
    global _rpc_TRANSPORT
    # NOTE(ft): set control_exchange parameter to use Nova cert topic
    messaging.set_transport_defaults('nova')
    _rpc_TRANSPORT = messaging.get_transport(conf)


def _rpc_get_client(target):
    if not _rpc_TRANSPORT:
        _rpc_init(CONF)
    assert _rpc_TRANSPORT is not None
    serializer = _rpc_RequestContextSerializer()
    return messaging.RPCClient(_rpc_TRANSPORT,
                               target,
                               serializer=serializer)


class _rpc_RequestContextSerializer(messaging.NoOpSerializer):

    def serialize_context(self, context):
        return context.to_dict()

    def deserialize_context(self, context):
        return ec2_context.RequestContext.from_dict(context)
