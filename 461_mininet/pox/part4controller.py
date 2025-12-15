from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import ethernet, arp, ipv4
from pox.lib.addresses import IPAddr, EthAddr

log = core.getLogger()

# ---------------- CONSTANTS ----------------
ROUTER_MAC = EthAddr("00:00:00:aa:bb:cc")

GATEWAY_IPS = {
    IPAddr("10.0.1.1"),
    IPAddr("10.0.2.1"),
    IPAddr("10.0.3.1"),
    IPAddr("10.0.4.1"),
    IPAddr("172.16.10.1")
}

HNOTRUST_IP = IPAddr("172.16.10.100")
SERV1_IP    = IPAddr("10.0.4.10")

# -------------------------------------------------

class Part4Router(object):

    def __init__(self, connection):
        self.connection = connection
        self.arp_table = {}   # IP -> (MAC, port)
        connection.addListeners(self)
        log.info("Part4 router active on switch %s", connection.dpid)

    # ---------------- PACKET IN ----------------
    def _handle_PacketIn(self, event):
        packet = event.parsed
        in_port = event.port

        if packet.type == ethernet.ARP_TYPE:
            self.handle_arp(packet, in_port)
            return

        if packet.type == ethernet.IP_TYPE:
            self.handle_ip(packet, event, in_port)
            return

    # ---------------- ARP ----------------
    def handle_arp(self, packet, in_port):
        a = packet.payload

        # Learn sender
        self.arp_table[a.protosrc] = (packet.src, in_port)

        # Reply if ARP is for router gateway
        if a.opcode == arp.REQUEST and a.protodst in GATEWAY_IPS:
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

    # ---------------- IP ----------------
    def handle_ip(self, packet, event, in_port):
        ip = packet.payload

        # ---------- FIREWALL ----------
        if ip.srcip == HNOTRUST_IP:
            if ip.dstip == SERV1_IP:
                return
            if ip.protocol == ipv4.ICMP_PROTOCOL:
                return

        # ---------- ROUTING ----------
        if ip.dstip not in self.arp_table:
            return  # wait until ARP learned

        dst_mac, out_port = self.arp_table[ip.dstip]

        # Install flow
        fm = of.ofp_flow_mod()
        fm.priority = 10
        fm.match.dl_type = ethernet.IP_TYPE
        fm.match.nw_dst = ip.dstip
        fm.actions.append(of.ofp_action_dl_addr.set_src(ROUTER_MAC))
        fm.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
        fm.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(fm)

        # Forward current packet
        po = of.ofp_packet_out()
        po.data = event.ofp
        po.actions.append(of.ofp_action_dl_addr.set_src(ROUTER_MAC))
        po.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
        po.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(po)

# -------------------------------------------------

def launch():
    def start_switch(event):
        # Core switch = router
        if event.connection.dpid == 21:
            Part4Router(event.connection)
        else:
            # Access switches flood
            fm = of.ofp_flow_mod()
            fm.priority = 1
            fm.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            event.connection.send(fm)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
