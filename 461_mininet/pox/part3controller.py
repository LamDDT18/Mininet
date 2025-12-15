from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import ethernet, ipv4

log = core.getLogger()

# ---- IP CONSTANTS ----
HNOTRUST_IP = "172.16.10.100"
SERV1_IP    = "10.0.4.10"

class Part3Controller(object):

    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)

        dpid = connection.dpid
        log.info("Switch %s connected", dpid)

        # CORE switch
        if dpid == 21:
            self.setup_core()
        # ACCESS switches
        else:
            self.setup_access()

    # -------------------------------------------------
    # ACCESS SWITCH: simple L2 flooding
    # -------------------------------------------------
    def setup_access(self):
        fm = of.ofp_flow_mod()
        fm.priority = 1
        fm.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(fm)

    # -------------------------------------------------
    # CORE SWITCH: firewall + static routing
    # -------------------------------------------------
    def setup_core(self):

        # ---------- FIREWALL RULES ----------

        # Block ICMP from hnotrust to internal + server
        internal_targets = [
            "10.0.1.0/24",
            "10.0.2.0/24",
            "10.0.3.0/24",
            "10.0.4.10/32"
        ]

        for dst in internal_targets:
            fm = of.ofp_flow_mod()
            fm.priority = 300
            fm.match.dl_type = ethernet.IP_TYPE
            fm.match.nw_proto = ipv4.ICMP_PROTOCOL
            fm.match.nw_src = HNOTRUST_IP
            fm.match.nw_dst = dst
            self.connection.send(fm)

        # Block ALL IP from hnotrust to serv1
        fm = of.ofp_flow_mod()
        fm.priority = 250
        fm.match.dl_type = ethernet.IP_TYPE
        fm.match.nw_src = HNOTRUST_IP
        fm.match.nw_dst = SERV1_IP
        self.connection.send(fm)

        # ---------- ROUTING RULES ----------
        # cores21 ports:
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

        for subnet, port in routes.items():
            fm = of.ofp_flow_mod()
            fm.priority = 100
            fm.match.dl_type = ethernet.IP_TYPE
            fm.match.nw_dst = subnet
            fm.actions.append(of.ofp_action_output(port=port))
            self.connection.send(fm)

def launch():
    def start_switch(event):
        Part3Controller(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
