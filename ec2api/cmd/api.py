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

"""
EC2api API Server
"""

import sys

from oslo_config import cfg
from oslo_log import log as logging

from ec2api import config
from ec2api import service

main_opts = [ 
    cfg.IntOpt('ec2_workers',
               default=1,
               help='Number of workers for EC2 API service. The value '
                    'will come from conf.'),
]
CONF = cfg.CONF
CONF.register_opts(main_opts)


def main():
    config.parse_args(sys.argv)
    logging.setup(CONF, 'ec2api')

    server = service.WSGIService('ec2api', max_url_len=16384)
    service.serve(server, CONF.ec2_workers)
    service.wait()


if __name__ == '__main__':
    main()
