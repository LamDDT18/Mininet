from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import ethernet, ipv4

log = core.getLogger()

CORE_DPID = 21

class Part3Controller(object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)

        dpid = connection.dpid

        # Non-core switches: flood everything
        if dpid != CORE_DPID:
            msg = of.ofp_flow_mod()
            msg.priority = 1
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            connection.send(msg)
            return

        # ---------- CORE SWITCH (cores21) ----------

        # Block ICMP from hnotrust1 to internal + server
        for dst in ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24", "10.0.4.10/32"]:
            msg = of.ofp_flow_mod()
            msg.priority = 200
            msg.match.dl_type = ethernet.IP_TYPE
            msg.match.nw_proto = ipv4.ICMP_PROTOCOL
            msg.match.nw_src = "172.16.10.100"
            msg.match.nw_dst = dst
            connection.send(msg)

        # Block all IP from hnotrust1 to serv1
        msg = of.ofp_flow_mod()
        msg.priority = 190
        msg.match.dl_type = ethernet.IP_TYPE
        msg.match.nw_src = "172.16.10.100"
        msg.match.nw_dst = "10.0.4.10"
        connection.send(msg)

        # Forwarding rules (static)
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
            connection.send(msg)

def launch():
    def start_switch(event):
        Part3Controller(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
