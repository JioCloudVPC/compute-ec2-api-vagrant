# Copyright 2014 OpenStack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import time

from tempest_lib.openstack.common import log

from ec2api.tests.functional import base

LOG = log.getLogger(__name__)


class DhcpOptionsTest(base.EC2TestCase):

    VPC_CIDR = '10.12.0.0/24'
    vpc_id = None

    def test_create_delete_dhcp_options(self):
        kwargs = {
            'DhcpConfigurations': [
                {'Key': 'domain-name',
                 'Values': ['my.com', 'it.com']},
                {'Key': 'domain-name-servers',
                 'Values': ['8.8.8.8', '8.8.4.4']},
                {'Key': 'ntp-servers',
                 'Values': ['1.2.3.4']},
                {'Key': 'netbios-name-servers',
                 'Values': ['4.3.2.1']},
                {'Key': 'netbios-node-type',
                 'Values': ['2']},
            ],
        }
        resp, data = self.client.CreateDhcpOptions(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        options = data['DhcpOptions']
        id = options['DhcpOptionsId']
        res_clean = self.addResourceCleanUp(self.client.DeleteDhcpOptions,
                                            DhcpOptionsId=id)
        self.assertEqual(5, len(options['DhcpConfigurations']))
        for cfg in options['DhcpConfigurations']:
            self.assertEqual(2, len(cfg))
            if cfg['Key'] == 'domain-name':
                self.assertEqual(2, len(cfg['Values']))
                values = [i['Value'] for i in cfg['Values']]
                self.assertIn('my.com', values)
                self.assertIn('it.com', values)
            elif cfg['Key'] == 'domain-name-servers':
                self.assertEqual(2, len(cfg['Values']))
                values = [i['Value'] for i in cfg['Values']]
                self.assertIn('8.8.8.8', values)
                self.assertIn('8.8.4.4', values)
            elif cfg['Key'] == 'ntp-servers':
                self.assertEqual(1, len(cfg['Values']))
                self.assertEqual('1.2.3.4', cfg['Values'][0]['Value'])
            elif cfg['Key'] == 'netbios-name-servers':
                self.assertEqual(1, len(cfg['Values']))
                self.assertEqual('4.3.2.1', cfg['Values'][0]['Value'])
            elif cfg['Key'] == 'netbios-node-type':
                self.assertEqual(1, len(cfg['Values']))
                self.assertEqual('2', cfg['Values'][0]['Value'])
            else:
                self.fail('Unknown key name in result - %s' % cfg['Key'])

        resp, data = self.client.DeleteDhcpOptions(DhcpOptionsId=id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)

    def test_invalid_create_delete(self):
        kwargs = {
            'DhcpConfigurations': [
            ],
        }
        resp, data = self.client.CreateDhcpOptions(*[], **kwargs)
        self.assertEqual(400, resp.status_code)
        self.assertEqual('MissingParameter', data['Error']['Code'])

        kwargs = {
            'DhcpConfigurations': [{'Key': 'aaa', 'Values': []}],
        }
        resp, data = self.client.CreateDhcpOptions(*[], **kwargs)
        if resp.status_code == 200:
            self.addResourceCleanUp(self.client.DeleteDhcpOptions,
                DhcpOptionsId=data['DhcpOptions']['DhcpOptionsId'])
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidParameterValue', data['Error']['Code'])

        kwargs = {
            'DhcpConfigurations': [{'Key': 'domain-name', 'Values': []}],
        }
        resp, data = self.client.CreateDhcpOptions(*[], **kwargs)
        if resp.status_code == 200:
            self.addResourceCleanUp(self.client.DeleteDhcpOptions,
                DhcpOptionsId=data['DhcpOptions']['DhcpOptionsId'])
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidParameterValue', data['Error']['Code'])

    def test_describe_dhcp_options(self):
        kwargs = {
            'DhcpConfigurations': [
                {'Key': 'domain-name',
                 'Values': ['my.com']},
            ],
        }
        resp, data = self.client.CreateDhcpOptions(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        options = data['DhcpOptions']
        id = options['DhcpOptionsId']
        res_clean = self.addResourceCleanUp(self.client.DeleteDhcpOptions,
                                            DhcpOptionsId=id)

        time.sleep(10)

        kwargs = {
            'DhcpOptionsIds': [id],
        }
        resp, data = self.client.DescribeDhcpOptions(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(1, len(data['DhcpOptions']))
        options = data['DhcpOptions'][0]
        self.assertEqual(id, options['DhcpOptionsId'])
        self.assertEqual(1, len(options['DhcpConfigurations']))
        cfg = options['DhcpConfigurations'][0]
        self.assertEqual(2, len(cfg))
        self.assertEqual('domain-name', cfg['Key'])
        self.assertEqual(1, len(cfg['Values']))
        self.assertIn('my.com', cfg['Values'][0]['Value'])

        resp, data = self.client.DeleteDhcpOptions(DhcpOptionsId=id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)

    def test_associate_dhcp_options(self):
        kwargs = {
            'DhcpConfigurations': [
                {'Key': 'domain-name',
                 'Values': ['my.com']},
            ],
        }
        resp, data = self.client.CreateDhcpOptions(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        options = data['DhcpOptions']
        id = options['DhcpOptionsId']
        res_clean = self.addResourceCleanUp(self.client.DeleteDhcpOptions,
                                            DhcpOptionsId=id)

        cidr = '10.0.0.0/24'
        resp, data = self.client.CreateVpc(CidrBlock=cidr)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        vpc_id = data['Vpc']['VpcId']
        dv_clean = self.addResourceCleanUp(self.client.DeleteVpc, VpcId=vpc_id)

        kwargs = {
            'DhcpOptionsId': id,
            'VpcId': vpc_id,
        }
        resp, data = self.client.AssociateDhcpOptions(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))

        resp, data = self.client.DeleteDhcpOptions(DhcpOptionsId=id)
        self.assertEqual(400, resp.status_code)
        self.assertEqual('DependencyViolation', data['Error']['Code'])

        resp, data = self.client.DeleteVpc(VpcId=vpc_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(dv_clean)
        self.get_vpc_waiter().wait_delete(vpc_id)

        resp, data = self.client.DeleteDhcpOptions(DhcpOptionsId=id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)
