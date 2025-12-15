from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import ethernet, ipv4

log = core.getLogger()

HNOTRUST_IP = "172.16.10.100"
SERV1_IP = "10.0.4.10"

class Part3Controller(object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)

        # Detect core switch by number of ports
        if len(connection.ports) != 5:
            self._install_flood_rule()
        else:
            self._install_core_rules()

    def _install_flood_rule(self):
        msg = of.ofp_flow_mod()
        msg.priority = 1
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)

    def _install_core_rules(self):
        # ---------- SECURITY POLICIES ----------

        # Block ICMP from hnotrust to internal + server
        internal_subnets = [
            "10.0.1.0/24",
            "10.0.2.0/24",
            "10.0.3.0/24",
            "10.0.4.10/32"
        ]

        for dst in internal_subnets:
            msg = of.ofp_flow_mod()
            msg.priority = 200
            msg.match.dl_type = ethernet.IP_TYPE
            msg.match.nw_proto = ipv4.ICMP_PROTOCOL
            msg.match.nw_src = HNOTRUST_IP
            msg.match.nw_dst = dst
            self.connection.send(msg)

        # Block all IP from hnotrust to serv1
        msg = of.ofp_flow_mod()
        msg.priority = 190
        msg.match.dl_type = ethernet.IP_TYPE
        msg.match.nw_src = HNOTRUST_IP
        msg.match.nw_dst = SERV1_IP
        self.connection.send(msg)

        # ---------- STATIC ROUTING ----------

        routes = {
            "10.0.1.0/24": 1,
            "10.0.2.0/24": 2,
            "10.0.3.0/24": 3,
            "10.0.4.0/24": 4,
            "172.16.10.0/24": 5
        }

        for subnet, port in routes.items():
            msg = of.ofp_flow_mod()
            msg.priority = 10
            msg.match.dl_type = ethernet.IP_TYPE
            msg.match.nw_dst = subnet
            msg.actions.append(of.ofp_action_output(port=port))
            self.connection.send(msg)

def launch():
    def start_switch(event):
        Part3Controller(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
