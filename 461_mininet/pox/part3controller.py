from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import ethernet, ipv4

log = core.getLogger()

# ---- CONSTANTS ----
CORE_DPID = 5

HNOTRUST_IP = "172.16.10.100"
SERV1_IP = "10.0.4.10"

class Part3Controller(object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)

        dpid = connection.dpid
        log.info("Switch %s connected", dpid)

        if dpid == CORE_DPID:
            log.info("Configuring CORE switch")
            self.install_core_rules()
        else:
            log.info("Configuring ACCESS switch (flood)")
            self.install_flood_rule()

    # ---------------- ACCESS SWITCH ----------------
    def install_flood_rule(self):
        msg = of.ofp_flow_mod()
        msg.priority = 1
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)

    # ---------------- CORE SWITCH ----------------
    def install_core_rules(self):

        # ---- SECURITY RULES ----

        # Block ICMP from hnotrust to internal + server
        internal_targets = [
            "10.0.1.0/24",
            "10.0.2.0/24",
            "10.0.3.0/24",
            "10.0.4.10/32"
        ]

        for dst in internal_targets:
            msg = of.ofp_flow_mod()
            msg.priority = 300
            msg.match.dl_type = ethernet.IP_TYPE
            msg.match.nw_proto = ipv4.ICMP_PROTOCOL
            msg.match.nw_src = HNOTRUST_IP
            msg.match.nw_dst = dst
            self.connection.send(msg)

        # Block ALL IP from hnotrust to serv1
        msg = of.ofp_flow_mod()
        msg.priority = 250
        msg.match.dl_type = ethernet.IP_TYPE
        msg.match.nw_src = HNOTRUST_IP
        msg.match.nw_dst = SERV1_IP
        self.connection.send(msg)

        # ---- ROUTING RULES ----
        # Ports on core:
        # 1 → s1 (10.0.1.0/24)
        # 2 → s2 (10.0.2.0/24)
        # 3 → s3 (10.0.3.0/24)
        # 4 → dcs31 (10.0.4.0/24)
        # 5 → hnotrust subnet (172.16.10.0/24)

        routes = {
            "10.0.1.0/24": 1,
            "10.0.2.0/24": 2,
            "10.0.3.0/24": 3,
            "10.0.4.0/24": 4,
            "172.16.10.0/24": 5
        }

        for subnet, out_port in routes.items():
            msg = of.ofp_flow_mod()
            msg.priority = 100
            msg.match.dl_type = ethernet.IP_TYPE
            msg.match.nw_dst = subnet
            msg.actions.append(of.ofp_action_output(port=out_port))
            self.connection.send(msg)


def launch():
    def start_switch(event):
        Part3Controller(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
