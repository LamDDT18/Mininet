
# Part 3 of UWCSE's Project 3
#
# based on Lab Final from UCSC's Networking Class
# which is based on of_tutorial by James McCauley

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr

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

class Part3Controller (object):
  """
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    print (connection.dpid)
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

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
    """
    # put core switch rules here
    # black list
    # block all ICMP traffic from untrusted host
    icmp_block =of.ofp_flow_mod()
    icmp_block.priority= 11
    icmp_block.match.dl_type= 0x0800
    icmp_block.proto = 1
    icmp_block.match.nw_src=IPS["hnotrust"][0]
    self.connection.send(icmp_block)
    print(icmp_block)  
    # block all ipv4 traffic from untrusted host
    ipv4_block = of.ofp_flow_mod()
    ipv4_block.priority = 10
    ipv4_block.match.dl_type =0x800
    ipv4_block.match.nw_src =IPS["hnotrust"][0]
    ipv4_block.match.nw_dst =IPS["serv1"][0]
    self.connection.send(ipv4_block)
    print(ipv4_block)
    """   
    # block all ICMP traffic from untrusted host
    self.Set_up_rule(11,0x800,1,"hnotrust",None,None)
    
    # block all ipv4 traffic from untrusted host
    self.Set_up_rule(10,0x800,None,"hnotrust","serv1",None)
     # actual routing
    # host 10
    
    fm_route_port_1 = of.ofp_flow_mod()
    fm_route_port_1.priority = 8
    fm_route_port_1.match.dl_type = 0x0800 # IPv4
    fm_route_port_1.match.nw_dst = IPS["h10"][0] # to host 1
    fm_route_port_1.actions.append(of.ofp_action_output(port = 1)) # send it out through port 1
    self.connection.send(fm_route_port_1)
    print(fm_route_port_1)
     
    # host 20
    fm_route_port_2 = of.ofp_flow_mod()
    fm_route_port_2.priority = 8
    fm_route_port_2.match.dl_type = 0x0800 # IPv4
    fm_route_port_2.match.nw_dst = IPS["h20"][0] # to host 2
    fm_route_port_2.actions.append(of.ofp_action_output(port = 2)) # send it out through port 1
    self.connection.send(fm_route_port_2)
    
    # host 30
    fm_route_port_3 = of.ofp_flow_mod()
    fm_route_port_3.priority = 8
    fm_route_port_3.match.dl_type = 0x0800 # IPv4
    fm_route_port_3.match.nw_dst = IPS["h30"][0] # to host 3
    fm_route_port_3.actions.append(of.ofp_action_output(port = 3)) # send it out through port 3
    self.connection.send(fm_route_port_3)

    # datacenter
    fm_route_port_dc = of.ofp_flow_mod()
    fm_route_port_dc.priority = 8
    fm_route_port_dc.match.dl_type = 0x0800 # IPvdc
    fm_route_port_dc.match.nw_dst = IPS["serv1"][0] # to host dc
    fm_route_port_dc.actions.append(of.ofp_action_output(port = 4)) # send it out through port 4
    self.connection.send(fm_route_port_dc)
    
    # out to the Internet
    fm_route_port_5 = of.ofp_flow_mod()
    fm_route_port_5.priority = 8
    fm_route_port_5.match.dl_type = 0x0800 # IPv4
    fm_route_port_5.actions.append(of.ofp_action_output(port = 5)) # send it out through port 5
    self.connection.send(fm_route_port_5)

   
    """
    # h10
    self.Set_up_rule(8,0x800,None,"h10",None,1)
    # h20
    
    self.Set_up_rule(8,0x800,None,"h20",None,2)
    # h30
    self.Set_up_rule(8,0x800,None,"h30",None,3)
    # serv1    
    self.Set_up_rule(8,0x800,None,"serv1",None,4)
    
    # out of Internet
    self.Set_up_rule(8,0x800,None,None,None,5)
    """
    self.flood()
    self.drop()
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
    print ("Unhandled packet from " + str(self.connection.dpid) + ":" + packet.dump())

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Part3Controller(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
