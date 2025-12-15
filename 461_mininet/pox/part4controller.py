from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import ethernet, arp, ipv4
from pox.lib.addresses import EthAddr, IPAddr

log = core.getLogger()

HNOTRUST_IP = IPAddr("172.16.10.100")
SERV1_IP = IPAddr("10.0.4.10")

ROUTER_MAC = EthAddr("00:00:00:aa:bb:cc")

GATEWAYS = {
    IPAddr("10.0.1.1"),
    IPAddr("10.0.2.1"),
    IPAddr("10.0.3.1"),
    IPAddr("10.0.4.1"),
    IPAddr("172.16.10.1")
}

class Part4Router(object):
    def __init__(self, connection):
        self.connection = connection
        self.arp_table = {}  # IP -> (MAC, port)
        connection.addListeners(self)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        in_port = event.port

        if packet.type == ethernet.ARP_TYPE:
            self._handle_arp(packet, in_port)
            return

        if packet.type == ethernet.IP_TYPE:
            self._handle_ip(packet, event, in_port)

    def _handle_arp(self, packet, in_port):
        a = packet.payload

        # Learn sender
        self.arp_table[a.protosrc] = (packet.src, in_port)

        # Reply if ARP is for router gateway
        if a.opcode == arp.REQUEST and a.protodst in GATEWAYS:
            reply = arp()
            reply.opcode = arp.REPLY
            reply.hwsrc = ROUTER_MAC
            reply.hwdst = packet.src
            reply.protosrc = a.protodst
            reply.protodst = a.protosrc

            eth = ethernet(
                type=ethernet.ARP_TYPE,
                src=ROUTER_MAC,
                dst=packet.src,
                payload=reply
            )

            msg = of.ofp_packet_out()
            msg.data = eth.pack()
            msg.actions.append(of.ofp_action_output(port=in_port))
            self.connection.send(msg)

    def _handle_ip(self, packet, event, in_port):
        ip = packet.payload

        # ---------- SECURITY POLICIES ----------
        if ip.srcip == HNOTRUST_IP:
            if ip.dstip == SERV1_IP:
                return
            if ip.protocol == ipv4.ICMP_PROTOCOL:
                return

        # ---------- ROUTING ----------
        if ip.dstip not in self.arp_table:
            return  # Haven't learned yet

        dst_mac, out_port = self.arp_table[ip.dstip]

        # Install flow
        msg = of.ofp_flow_mod()
        msg.priority = 10
        msg.match.dl_type = ethernet.IP_TYPE
        msg.match.nw_dst = ip.dstip
        msg.actions.append(of.ofp_action_dl_addr.set_src(ROUTER_MAC))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
        msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg)

        # Forward current packet
        pkt = of.ofp_packet_out()
        pkt.data = event.ofp
        pkt.actions.append(of.ofp_action_dl_addr.set_src(ROUTER_MAC))
        pkt.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
        pkt.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(pkt)

def launch():
    def start_switch(event):
        if len(event.connection.ports) == 5:
            Part4Router(event.connection)
        else:
            msg = of.ofp_flow_mod()
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            event.connection.send(msg)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
