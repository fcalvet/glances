# -*- coding: utf-8 -*-
#
# This file is part of Glances.
#
# Copyright (C) 2019 Nicolargo <nicolas@nicolargo.com>
#
# Glances is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Glances is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

"""Wireguard plugin."""

import os
import time

from glances.logger import logger
from glances.compat import iterkeys, itervalues, nativestr
from glances.timer import getTimeSinceLastUpdate
from glances.plugins.glances_plugin import GlancesPlugin
from glances.processes import sort_stats as sort_stats_processes, weighted, glances_processes

# Define the items history list (list of items to add to history)
# TODO: For the moment limited to the CPU. Had to change the graph exports
#       method to display one graph per container.
# items_history_list = [{'name': 'cpu_percent',
#                        'description': 'Container CPU consumption in %',
#                        'y_unit': '%'},
#                       {'name': 'memory_usage',
#                        'description': 'Container memory usage in bytes',
#                        'y_unit': 'B'},
#                       {'name': 'network_rx',
#                        'description': 'Container network RX bitrate in bits per second',
#                        'y_unit': 'bps'},
#                       {'name': 'network_tx',
#                        'description': 'Container network TX bitrate in bits per second',
#                        'y_unit': 'bps'},
#                       {'name': 'io_r',
#                        'description': 'Container IO bytes read per second',
#                        'y_unit': 'Bps'},
#                       {'name': 'io_w',
#                        'description': 'Container IO bytes write per second',
#                        'y_unit': 'Bps'}]
items_history_list = [{'name': 'cpu_percent',
                       'description': 'Container CPU consumption in %',
                       'y_unit': '%'}]


class Plugin(GlancesPlugin):
    """Glances Wireguard plugin.

    stats is a dict: {'interface': {...}, 'peers': [{}, {}]}
    """

    def __init__(self, args=None, config=None):
        """Init the plugin."""
        super(Plugin, self).__init__(args=args,
                                     config=config,
                                     items_history_list=items_history_list)

        # The plugin can be disable using: args.disable_docker
        self.args = args

        # We want to display the stat in the curse interface
        self.display_curse = True
        
        # We want the the interface parameter
        self.interface = self.get_conf_value('interface')
        
        

    def get_export(self):
        """Overwrite the default export method.

        - Only exports containers
        - The key is the first container name
        """
        ret = []
        try:
            ret = self.stats['containers']
        except KeyError as e:
            logger.debug("docker plugin - Docker export error {}".format(e))
        return ret

    @GlancesPlugin._check_decorator
    @GlancesPlugin._log_result_decorator
    def update(self):
        """Update Wireguard stats using the input method."""
        # Init new stats
        stats = self.get_init_value()

        # By storing time data we enable Rx/s and Tx/s calculations in the
        # XML/RPC API, which would otherwise be overly difficult work
        # for users of the API
        time_since_update = getTimeSinceLastUpdate('wireguard')

        if self.input_method == 'local':
            # Update stats

            # Sample output of wg shows INTERFACE dump
            # PUBKEYSERVER\tPRIVKEY\tLISTENINGPORT\toff\tfwmark\n
            # PUBKEYPEER1\t(none)\tENDPOINT\tALLOWEP_IPS\tlatest-handshake\ttransfer-rx\ttransfer-tx\tpersistent-keepalive\n
            try:
                wg_dump = os.popen("wg show {} dump".format(self.interface))
            except Exception as e:
                logger.error("{} plugin - Cannot open wireguard interface {} ({})".format(self.plugin_name, self.interface, e))
                self.stats = []
                return self.stats
            
            interface_line = wg_dump.readline().split('\t')
            stats["interface"] = {"name": self.interface,
                                  "pubkey": interface_line[0],
                                  "listening_port": interface_line[2],
                                  'time_since_update': time_since_update
                                 }                                  
              
            # Get stats for all peers
            stats['peers'] = []
            for lines in wg_dump.readlines():
              peer_line = lines.split('\t')
              peer={"pubkey": peer_line[0],
                    "preshared-key": peer_line[1],
                    "endpoint": peer_line[2],
                    "allowed-ips": peer_line[3],
                    "latest_handshake": peer_line[4],
                    "transfer-rx": peer_line[5],
                    "transfer-tx": peer_line[6],
                    "persistent-keepalive": peer_line[7]
              }
              try:
                peer['rx'] = (peer["transfer-rx"] - self.peers_old[peer['pubkey']]["transfer-rx"])//time_since_update
                peer['tx'] = (peer["transfer-tx"] - self.peers_old[peer['pubkey']]["transfer-tx"])//time_since_update
              except KeyError:
                  continue
              stats['peers'][peer["pubkey"]]=peer
        elif self.input_method == 'snmp':
            # Update stats using SNMP
            # Not available
            pass

        self.peers_old = stats['peers']
        
        # Update the stats
        self.stats = stats

        return self.stats

    def get_stats_action(self):
        """Return stats for the action.

        Docker will return self.stats['containers']
        """
        return self.stats['containers']

    def update_views(self):
        """Update stats views."""
        # Call the father's method
        super(Plugin, self).update_views()

        if 'peers' not in self.stats:
            return False
          
        for peers in self.stats[peers]
            # Convert rate in bps ( to be able to compare to interface speed)
            bps_rx = int(i['rx'] // i['time_since_update'] * 8)
            bps_tx = int(i['tx'] // i['time_since_update'] * 8)
            # Decorate the bitrate with the configuration file thresolds
            alert_rx = self.get_alert(bps_rx, header=ifrealname + '_rx')
            alert_tx = self.get_alert(bps_tx, header=ifrealname + '_tx')
        # Add specifics informations
        # Alert
        for i in self.stats['peers']:
            # Init the views for the current container (key = container name)
            self.views[i[self.get_key()]] = {'cpu': {}, 'mem': {}}
            # Handshake alert
            if 'cpu' in i and 'total' in i['cpu']:
                # Looking for specific CPU container threasold in the conf file
                alert = self.get_alert(i['cpu']['total'],
                                       header=i['name'] + '_cpu',
                                       action_key=i['name'])
                if alert == 'DEFAULT':
                    # Not found ? Get back to default CPU threasold value
                    alert = self.get_alert(i['cpu']['total'], header='cpu')
                self.views[i[self.get_key()]]['cpu']['decoration'] = alert
            # Transfer alert
            if 'memory' in i and 'usage' in i['memory']:
                # Looking for specific MEM container threasold in the conf file
                alert = self.get_alert(i['memory']['usage'],
                                       maximum=i['memory']['limit'],
                                       header=i['name'] + '_mem',
                                       action_key=i['name'])
                if alert == 'DEFAULT':
                    # Not found ? Get back to default MEM threasold value
                    alert = self.get_alert(i['memory']['usage'],
                                           maximum=i['memory']['limit'],
                                           header='mem')
                self.views[i[self.get_key()]]['mem']['decoration'] = alert

        return True

    def msg_curse(self, args=None, max_width=None):
        """Return the dict to display in the curse interface."""
        # Init the return message
        ret = []

        # Only process if stats exist (and non null) and display plugin enable...
        if not self.stats \
           or 'containers' not in self.stats or len(self.stats['containers']) == 0 \
           or self.is_disable():
            return ret

        # Build the string message
        # Title
        msg = '{}'.format('CONTAINERS')
        ret.append(self.curse_add_line(msg, "TITLE"))
        msg = ' {}'.format(len(self.stats['containers']))
        ret.append(self.curse_add_line(msg))
        msg = ' (served by Docker {})'.format(self.stats['version']["Version"])
        ret.append(self.curse_add_line(msg))
        ret.append(self.curse_new_line())
        # Header
        ret.append(self.curse_new_line())
        # Get the maximum containers name (cutted to 20 char max)
        name_max_width = min(20, len(max(self.stats['containers'], key=lambda x: len(x['name']))['name']))
        msg = ' {:{width}}'.format('Name', width=name_max_width)
        ret.append(self.curse_add_line(msg))
        msg = '{:>10}'.format('Status')
        ret.append(self.curse_add_line(msg))
        msg = '{:>6}'.format('CPU%')
        ret.append(self.curse_add_line(msg))
        msg = '{:>7}'.format('MEM')
        ret.append(self.curse_add_line(msg))
        msg = '{:>7}'.format('/MAX')
        ret.append(self.curse_add_line(msg))
        msg = '{:>7}'.format('IOR/s')
        ret.append(self.curse_add_line(msg))
        msg = '{:>7}'.format('IOW/s')
        ret.append(self.curse_add_line(msg))
        msg = '{:>7}'.format('Rx/s')
        ret.append(self.curse_add_line(msg))
        msg = '{:>7}'.format('Tx/s')
        ret.append(self.curse_add_line(msg))
        msg = ' {:8}'.format('Command')
        ret.append(self.curse_add_line(msg))
        # Data
        for container in self.stats['containers']:
            ret.append(self.curse_new_line())
            # Name
            ret.append(self.curse_add_line(self._msg_name(container=container,
                                                          max_width=name_max_width)))
            # Status
            status = self.container_alert(container['Status'])
            msg = '{:>10}'.format(container['Status'][0:10])
            ret.append(self.curse_add_line(msg, status))
            # CPU
            try:
                msg = '{:>6.1f}'.format(container['cpu']['total'])
            except KeyError:
                msg = '{:>6}'.format('_')
            ret.append(self.curse_add_line(msg, self.get_views(item=container['name'],
                                                               key='cpu',
                                                               option='decoration')))
            # MEM
            try:
                msg = '{:>7}'.format(self.auto_unit(container['memory']['usage']))
            except KeyError:
                msg = '{:>7}'.format('_')
            ret.append(self.curse_add_line(msg, self.get_views(item=container['name'],
                                                               key='mem',
                                                               option='decoration')))
            try:
                msg = '{:>7}'.format(self.auto_unit(container['memory']['limit']))
            except KeyError:
                msg = '{:>7}'.format('_')
            ret.append(self.curse_add_line(msg))
            # IO R/W
            unit = 'B'
            for r in ['ior', 'iow']:
                try:
                    value = self.auto_unit(int(container['io'][r] // container['io']['time_since_update'])) + unit
                    msg = '{:>7}'.format(value)
                except KeyError:
                    msg = '{:>7}'.format('_')
                ret.append(self.curse_add_line(msg))
            # NET RX/TX
            if args.byte:
                # Bytes per second (for dummy)
                to_bit = 1
                unit = ''
            else:
                # Bits per second (for real network administrator | Default)
                to_bit = 8
                unit = 'b'
            for r in ['rx', 'tx']:
                try:
                    value = self.auto_unit(int(container['network'][r] // container['network']['time_since_update'] * to_bit)) + unit
                    msg = '{:>7}'.format(value)
                except KeyError:
                    msg = '{:>7}'.format('_')
                ret.append(self.curse_add_line(msg))
            # Command
            if container['Command'] is not None:
                msg = ' {}'.format(' '.join(container['Command']))
            else:
                msg = ' {}'.format('_')
            ret.append(self.curse_add_line(msg, splittable=True))

        return ret

    def _msg_name(self, container, max_width):
        """Build the peer name."""
        name = peer['pubkey']
        if len(name) > max_width:
            name = '_' + name[-max_width + 1:]
        else:
            name = name[:max_width]
        return ' {:{width}}'.format(name, width=max_width)

    def container_alert(self, status):
        """Analyse the container status."""
        if status in ('running'):
            return 'OK'
        elif status in ('exited'):
            return 'WARNING'
        elif status in ('dead'):
            return 'CRITICAL'
        else:
            return 'CAREFUL'
