from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import ethernet, arp, ipv4
from pox.lib.addresses import EthAddr, IPAddr

log = core.getLogger()

ROUTER_MAC = EthAddr("00:00:00:aa:bb:cc")

HNOTRUST = IPAddr("172.16.10.100")
SERV1    = IPAddr("10.0.4.10")

class Part4Router(object):
    def __init__(self, connection):
        self.connection = connection
        self.arp_table = {}   # ip -> (mac, port)
        connection.addListeners(self)

    def _handle_PacketIn(self, event):
        pkt = event.parsed
        in_port = event.port

        if pkt.type == ethernet.ARP_TYPE:
            self.handle_arp(pkt, in_port)
        elif pkt.type == ethernet.IP_TYPE:
            self.handle_ip(pkt, event, in_port)

    # ---------------- ARP ----------------
    def handle_arp(self, pkt, in_port):
        a = pkt.payload

        # Learn sender
        self.arp_table[a.protosrc] = (pkt.src, in_port)

        # Reply if ARP for gateway
        if a.opcode == arp.REQUEST:
            reply = arp()
            reply.opcode = arp.REPLY
            reply.hwsrc = ROUTER_MAC
            reply.hwdst = pkt.src
            reply.protosrc = a.protodst
            reply.protodst = a.protosrc

            eth = ethernet(
                type=ethernet.ARP_TYPE,
                src=ROUTER_MAC,
                dst=pkt.src,
                payload=reply
            )

            msg = of.ofp_packet_out()
            msg.data = eth.pack()
            msg.actions.append(of.ofp_action_output(port=in_port))
            self.connection.send(msg)

    # ---------------- IP ----------------
    def handle_ip(self, pkt, event, in_port):
        ip = pkt.payload

        # ---- SECURITY POLICIES ----
        if ip.srcip == HNOTRUST:
            if ip.dstip == SERV1:
                return
            if ip.protocol == ipv4.ICMP_PROTOCOL:
                return

        # ---- ROUTING ----
        if ip.dstip not in self.arp_table:
            return  # wait for ARP learning

        dst_mac, out_port = self.arp_table[ip.dstip]

        # Install flow
        fm = of.ofp_flow_mod()
        fm.priority = 100
        fm.match.dl_type = ethernet.IP_TYPE
        fm.match.nw_dst = ip.dstip
        fm.actions.append(of.ofp_action_dl_addr.set_src(ROUTER_MAC))
        fm.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
        fm.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(fm)

        # Forward current packet
        po = of.ofp_packet_out()
        po.data = event.ofp
        po.actions = fm.actions
        self.connection.send(po)

# ---------------- LAUNCH ----------------
def launch():
    def start(event):
        # core switch has 5 ports
        if len(event.connection.ports) == 5:
            Part4Router(event.connection)
        else:
            # edge switches flood
            msg = of.ofp_flow_mod()
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            event.connection.send(msg)

    core.openflow.addListenerByName("ConnectionUp", start)
