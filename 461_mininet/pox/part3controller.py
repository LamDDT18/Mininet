from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import ethernet, ipv4

log = core.getLogger()

# ===== CONFIG =====
# cores21 has 5 ports in topo
CORE_PORT_COUNT = 5

HNOTRUST_IP = "172.16.10.100"
SERV1_IP = "10.0.4.10"

class Part3Controller(object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)

        if len(connection.ports) == CORE_PORT_COUNT:
            log.info("Configuring CORE switch")
            self.setup_core()
        else:
            log.info("Configuring ACCESS switch (FLOOD)")
            self.setup_access()

    # ================= ACCESS SWITCH =================
    def setup_access(self):
        msg = of.ofp_flow_mod()
        msg.priority = 1
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)

    # ================= CORE SWITCH =================
    def setup_core(self):

        # ---- BLOCK ICMP from hnotrust to internal + server ----
        blocked_icmp_dsts = [
            "10.0.1.0/24",
            "10.0.2.0/24",
            "10.0.3.0/24",
            "10.0.4.10/32"
        ]

        for dst in blocked_icmp_dsts:
            msg = of.ofp_flow_mod()
            msg.priority = 300
            msg.match.dl_type = ethernet.IP_TYPE
            msg.match.nw_proto = ipv4.ICMP_PROTOCOL
            msg.match.nw_src = HNOTRUST_IP
            msg.match.nw_dst = dst
            # no action = DROP
            self.connection.send(msg)

        # ---- BLOCK ALL IP from hnotrust to serv1 ----
        msg = of.ofp_flow_mod()
        msg.priority = 250
        msg.match.dl_type = ethernet.IP_TYPE
        msg.match.nw_src = HNOTRUST_IP
        msg.match.nw_dst = SERV1_IP
        self.connection.send(msg)

        # ---- STATIC ROUTING RULES ----
        # Core ports (from topo):
        # 1 -> s1 (10.0.1.0/24)
        # 2 -> s2 (10.0.2.0/24)
        # 3 -> s3 (10.0.3.0/24)
        # 4 -> dcs31 (10.0.4.0/24)
        # 5 -> hnotrust (172.16.10.0/24)

        routes = {
            "10.0.1.0/24": 1,
            "10.0.2.0/24": 2,
            "10.0.3.0/24": 3,
            "10.0.4.0/24": 4,
            "172.16.10.0/24": 5
        }

        for subnet, port in routes.items():
            msg = of.ofp_flow_mod()
            msg.priority = 100
            msg.match.dl_type = ethernet.IP_TYPE
            msg.match.nw_dst = subnet
            msg.actions.append(of.ofp_action_output(port=port))
            self.connection.send(msg)

def launch():
    def start(event):
        Part3Controller(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start)
