# Part 3 of UWCSE's Project 3
#
# based on Lab Final from UCSC's Networking Class
# which is based on of_tutorial by James McCauley

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr
from pox.lib.packet.arp import arp
log = core.getLogger()

#statically allocate a routing table for hosts
#MACs used in only in part 4
IPS = {
  "h10" : ("10.0.1.10", '00:00:00:00:00:01'),
  "h20" : ("10.0.2.20", '00:00:00:00:00:02'),
  "h30" : ("10.0.3.30", '00:00:00:00:00:03'),
  "serv1" : ("10.0.4.10", '00:00:00:00:00:04'),
  "hnotrust" : ("172.16.10.100", '00:00:00:00:00:05'),
}

def dpid_to_mac (dpid):
  return EthAddr("%012x" % (dpid & 0xffFFffFFffFF,))



class Entry():
  def __init__ (self, mac,port):
    self.mac = mac
    self.port = port

class Part4Controller (object):
  """
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    print (connection.dpid)
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection
    self.mac = dpid_to_mac(self.connection.dpid)
    self.arpTable ={} 
    # This binds our PacketIn event listener
    connection.addListeners(self)
    #use the dpid to figure out what switch is being created
    if (connection.dpid == 1):
      self.s1_setup()
    elif (connection.dpid == 2):
      self.s2_setup()
    elif (connection.dpid == 3):
      self.s3_setup()
    elif (connection.dpid == 21):
      self.cores21_setup()
    elif (connection.dpid == 31):
      self.dcs31_setup()
    else:
      print ("UNKNOWN SWITCH")
      exit(1)
  def flood(self):
    fm = of.ofp_flow_mod()
    fm.priority = 1 # a slightly higher priority than drop
    fm.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    self.connection.send(fm)

  def drop(self):
    # drop other packets
    fm_drop = of.ofp_flow_mod()
    # ICMP
    fm_drop.priority = 0 # a low priority
    # flood all ports
    self.connection.send(fm_drop)


  def s1_setup(self):
    #put switch 1 rules here
    self.flood()
    self.drop()

  def s2_setup(self):
    #put switch 2 rules here
    self.flood()
    self.drop()

  def s3_setup(self):
    #put switch 3 rules here
    self.flood()
    self.drop()

  def cores21_setup(self):
    self.Set_up_rule(11,0x800,1,"hnotrust",None,None)
    
    # block all ipv4 traffic from untrusted host
    self.Set_up_rule(10,0x800,None,"hnotrust","serv1",None)
     # actual routing
    # host 10
  def dcs31_setup(self):
    #put datacenter switch rules here
    self.flood()
    self.drop()

  def Set_up_rule(self,priority,dl_type,proto,src,dst,port_num):
     print("Set rule====",priority,dl_type,proto,src,dst,port_num)
     
     msg = of.ofp_flow_mod()
     if priority!=None: 
     	msg.priority = priority
        print("Priority",priority)
     if dl_type!=None: 
	msg.match.dl_type = dl_type
        print("dl_ty0e",dl_type)
     if proto!=None:
        msg.match.proto= proto
        print("Proto",proto)
     if src!=None: 
	msg.match.nw_src = IPS[src][0]
        print("nw_src",IPS[src][0])
     if dst!=None:
	msg.match.nw_dst = IPS[dst][0]
        print("nw_dst",IPS[dst][0])
     if port_num!=None: 
	msg.actions.append(of.ofp_action_output(port =port_num))
        print("action port",port_num)
     self.connection.send(msg)
     print(msg)
  #used in part 4 to handle individual ARP packets
  #not needed for part 3 (USE RULES!)
  #causes the switch to output packet_in on out_port
  def resend_packet(self, packet_in, out_port):
    msg = of.ofp_packet_out()
    msg.data = packet_in
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)
    self.connection.send(msg)
    print("send out packet")
  def _handle_PacketIn (self, event):
    """
    Packets not handled by the router rules will be
    forwarded to this method to be handled by the controller
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return
    packet_in = event.ofp # The actual ofp_packet_in message.
    dpid =self.connection.dpid
    """
    if packet.type == packet.LLDP_TYPE or packet.type == packet.IPV6_TYPE:
      # Drop LLDP packets 
      # Drop IPv6 packets
      # send of command without actions

      msg = of.ofp_packet_out()
      msg.buffer_id = event.ofp.buffer_id
      msg.in_port = event.port
      self.connection.send(msg)
    """

    print packet
    
    if packet.type ==packet.ARP_TYPE:
        """
        packet.next.srcip is a source IP address 
        packet.src is its source MAC address.
        """
        srcip = packet.payload.protosrc
        dstip = packet.payload.protodst
        if packet.payload.opcode ==arp.REQUEST:
            # if dpid not in self.arpTable:
            #     self.arpTable[dpid] = {}
            # if packet.src not in self.arpTable[dpid]:
            #     # store it in arpTable
            #     self.arpTable[dpid][srcip]=Entry(packet.src,event.port) #IP map to mac and port
            msg = of.ofp_flow_mod()
            msg.priority = 8
            msg.match.dl_type = 0x800 #IP
            msg.match.nw_dst = packet.payload.protosrc
            #####################################
            msg.actions.append(of.ofp_action_dl_addr.set_dst(packet.src)) # dst mac 
            # msg.actions.append(of.ofp_action_nw_addr.set_dst(srcip)) #dst ip
            msg.actions.append(of.ofp_action_output(port = event.port))
            #####################################
            self.connection.send(msg)

            #create arp based on self.Mac
            arp_reply = arp()
            # arp_reply.hwsrc = dpid_to_mac(dpid) # switch mac
            arp_reply.hwsrc = EthAddr("00:11:22:33:44:55")
            arp_reply.hwdst = packet.src        # host mac
            arp_reply.opcode = arp.REPLY        
            arp_reply.protodst = srcip
            arp_reply.protosrc = dstip
            #ethernet
            ether = ethernet()
            ether.type = ethernet.ARP_TYPE
            ether.dst = packet.src
            # ether.src = dpid_to_mac(dpid)
            ether.src = EthAddr("00:11:22:33:44:55")
            ether.set_payload(arp_reply)
            # send out arp reply
            # print("dpid ",dpid," mac ",dpid_to_mac(dpid),"srcip ",srcip," dstip ",dstip)
            # print("My mac",self.arpTable[dpid][srcip].mac,self.arpTable[dpid][srcip].port)
            self.resend_packet(ether.pack(), event.port)
            return
        elif packet.type ==packet.ARP_TYPE:
            print("get arp reply My IP",dstip," from ",srcip) 
            
    #elif packet.type == packet.IP_TYPE:
        # Handle client's request

        # Only accept ARP request for load balancer
        # log.debug("Receive an IPv4 packet from %s" % packet.next.srcip)
        print ("Unhandled packet from " + str(self.connection.dpid) + ":" + packet.dump())

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Part4Controller(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
