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
from glances.compat import iterkeys, itervalues, nativestr, is_admin
from glances.timer import getTimeSinceLastUpdate
from glances.plugins.glances_plugin import GlancesPlugin
from glances.processes import sort_stats as sort_stats_processes, weighted, glances_processes

# Define the items history list (list of items to add to history)
# TODO: For the moment limited to the CPU. Had to change the graph exports
#       method to display one graph per container.
items_history_list = [{'name': 'cpu_percent',
                       'description': 'Container CPU consumption in %',
                       'y_unit': '%'}]


class Plugin(GlancesPlugin):
    """Glances Wireguard plugin.

    stats is a dict: {'interface': {...}, 'peers': [{}, {}]}
    """

    def __init__(self, args=None, config=None):
        """Init the plugin."""
        # check if user is admin
        if not is_admin():
            disable(args, "wireguard")
            logger.debug("Current user is not admin, WireGuard plugin disabled.")
        super(Plugin, self).__init__(args=args,
                                     config=config,
                                     items_history_list=items_history_list)

        # We want to display the stat in the curse interface
        self.display_curse = True
        
        # We want the the interface parameter
        self.interface = self.get_conf_value('interface')
        

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

    def update_views(self):
        """Update stats views."""
        # Call the father's method
        super(Plugin, self).update_views()

        if 'peers' not in self.stats:
            return False
          
        for peer in self.stats[peers]:
            # Convert rate in bps ( to be able to compare to interface speed)
            bps_rx = int(peer['rx'] * 8)
            bps_tx = int(peer['tx'] * 8)
            # Decorate the bitrate with the configuration file thresolds
            alert_rx = self.get_alert(bps_rx, header= peer["pubkey"] + '_rx')
            alert_tx = self.get_alert(bps_tx, header= peer["pubkey"] + '_tx')
        # Add specifics informations
        # Alert
        for i in self.stats['peers']:
            

        return True

        def msg_curse(self, args=None, max_width=None):
        """Return the dict to display in the curse interface."""
        # Init the return message
        ret = []

        # Only process if stats exist and display plugin enable...
        if not self.stats or self.is_disable():
            return ret

        # Max size for the interface name
        name_max_width = max_width - 12

        # Header
        msg = '{:{width}}'.format('WG: {}'.format(self.interface), width=name_max_width)
        ret.append(self.curse_add_line(msg, "TITLE"))
        if args.network_cumul:
            # Cumulative stats
            if args.network_sum:
                # Sum stats
                msg = '{:>14}'.format('Rx+Tx')
                ret.append(self.curse_add_line(msg))
            else:
                # Rx/Tx stats
                msg = '{:>7}'.format('Rx')
                ret.append(self.curse_add_line(msg))
                msg = '{:>7}'.format('Tx')
                ret.append(self.curse_add_line(msg))
        else:
            # Bitrate stats
            if args.network_sum:
                # Sum stats
                msg = '{:>14}'.format('Rx+Tx/s')
                ret.append(self.curse_add_line(msg))
            else:
                msg = '{:>7}'.format('Rx/s')
                ret.append(self.curse_add_line(msg))
                msg = '{:>7}'.format('Tx/s')
                ret.append(self.curse_add_line(msg))
        # Interface list (sorted by name)
        for i in self.stats["peers"]:
            # Format stats
            # Is there an alias for the interface name ?
            ifrealname = i['interface_name'].split(':')[0]
            if len(ifname) > name_max_width:
                # Cut interface name if it is too long
                ifname = '_' + ifname[-name_max_width + 1:]

            if args.byte:
                # Bytes per second (for dummy)
                to_bit = 1
                unit = ''
            else:
                # Bits per second (for real network administrator | Default)
                to_bit = 8
                unit = 'b'

            if args.network_cumul:
                rx = self.auto_unit(int(i['transfer-rx'] * to_bit)) + unit
                tx = self.auto_unit(int(i['transfer-tx'] * to_bit)) + unit
                sx = self.auto_unit(int(i['transfer-rx'] * to_bit) +
                                    int(i['transfer-tx'] * to_bit)) + unit
            else:
                rx = self.auto_unit(int(i['rx'] * to_bit)) + unit
                tx = self.auto_unit(int(i['tx'] * to_bit)) + unit
                sx = self.auto_unit(int(i['rx'] * to_bit) +
                                    int(i['tx'] * to_bit)) + unit

            # New line
            ret.append(self.curse_new_line())
            msg = '{:{width}}'.format(ifname, width=name_max_width)
            ret.append(self.curse_add_line(msg))
            if args.network_sum:
                msg = '{:>14}'.format(sx)
                ret.append(self.curse_add_line(msg))
            else:
                msg = '{:>7}'.format(rx)
                ret.append(self.curse_add_line(
                    msg, self.get_views(item=i[self.get_key()], key='rx', option='decoration')))
                msg = '{:>7}'.format(tx)
                ret.append(self.curse_add_line(
                    msg, self.get_views(item=i[self.get_key()], key='tx', option='decoration')))

        return ret

    def _msg_name(self, peer, max_width):
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
