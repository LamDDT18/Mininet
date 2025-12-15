from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import ethernet, arp, ipv4

log = core.getLogger()
CORE_DPID = 21

class Part4Router(object):
    def __init__(self, connection):
        self.connection = connection
        self.arp_table = {}  # ip -> (mac, port)
        connection.addListeners(self)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        in_port = event.port

        if packet.type == ethernet.ARP_TYPE:
            a = packet.payload
            self.arp_table[a.protosrc] = (packet.src, in_port)

            if a.opcode == arp.REQUEST:
                reply = arp()
                reply.opcode = arp.REPLY
                reply.hwsrc = packet.src
                reply.hwdst = packet.src
                reply.protosrc = a.protodst
                reply.protodst = a.protosrc

                eth = ethernet(type=ethernet.ARP_TYPE,
                               src=packet.src,
                               dst=packet.src,
                               payload=reply)

                msg = of.ofp_packet_out()
                msg.data = eth.pack()
                msg.actions.append(of.ofp_action_output(port=in_port))
                self.connection.send(msg)
            return

        if packet.type == ethernet.IP_TYPE:
            ip = packet.payload

            # Security policies
            if ip.srcip == "172.16.10.100" and ip.dstip == "10.0.4.10":
                return
            if ip.srcip == "172.16.10.100" and packet.payload.protocol == ipv4.ICMP_PROTOCOL:
                return

            if ip.dstip in self.arp_table:
                dst_mac, out_port = self.arp_table[ip.dstip]

                msg = of.ofp_flow_mod()
                msg.priority = 10
                msg.match.dl_type = ethernet.IP_TYPE
                msg.match.nw_dst = ip.dstip
                msg.actions.append(of.ofp_action_output(port=out_port))
                self.connection.send(msg)

                pkt_out = of.ofp_packet_out()
                pkt_out.data = event.ofp
                pkt_out.actions.append(of.ofp_action_output(port=out_port))
                self.connection.send(pkt_out)

def launch():
    def start_switch(event):
        if event.connection.dpid == CORE_DPID:
            Part4Router(event.connection)
        else:
            msg = of.ofp_flow_mod()
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            event.connection.send(msg)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
