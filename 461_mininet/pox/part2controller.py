from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import ethernet, ipv4

log = core.getLogger()

class Part2Firewall(object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)

        log.info("Installing Part2 firewall rules")

        # Allow ARP
        msg = of.ofp_flow_mod()
        msg.priority = 100
        msg.match.dl_type = ethernet.ARP_TYPE
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        connection.send(msg)

        # Allow ICMP
        msg = of.ofp_flow_mod()
        msg.priority = 90
        msg.match.dl_type = ethernet.IP_TYPE
        msg.match.nw_proto = ipv4.ICMP_PROTOCOL
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        connection.send(msg)

        # Drop all other IPv4
        msg = of.ofp_flow_mod()
        msg.priority = 10
        msg.match.dl_type = ethernet.IP_TYPE
        connection.send(msg)

def launch():
    def start_switch(event):
        Part2Firewall(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
