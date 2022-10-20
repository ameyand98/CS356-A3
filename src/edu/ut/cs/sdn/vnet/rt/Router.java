package edu.ut.cs.sdn.vnet.rt;

import edu.ut.cs.sdn.vnet.Device;
import edu.ut.cs.sdn.vnet.DumpFile;
import edu.ut.cs.sdn.vnet.Iface;
import java.util.*; //Timer and TimerTask

import net.floodlightcontroller.packet.*; 
//IPv4, ICMP, Ethernet, ARP, UDP, RIPv2, RIPv2Entry, MACAddress

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	

	/** Constants for sendRIPPacket */

	//RIP Requests
	private static final boolean IS_RIP_REQUEST = true;
	//RIP Responses
	private static final int	 IS_SOLICITED = 1;
	private static final int	 IS_UNSOLICITED = 0;
	private static final int 	 NOT_RIP_RESPONSE = -1;

	//IP Multicast String
	private static final String MULTICAST = "224.0.0.9";
	//MAC Broadcast String
	private static final String BROADCAST = "FF:FF:FF:FF:FF:FF";




	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;

	// reuester threads for IPs
	private ConcurrentHashMap<Integer, ArpRequester> requesterThreads= new ConcurrentHashMap<Integer, ArpRequester>();

	private boolean RIPEnabled;

	private Timer RIPTimer;
	
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
	}
	
	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ return this.routeTable; }

	/**
	 * Init Route Table and Send Init RIP Packets
	 */
	public void initRouteTable() {
		this.RIPEnabled = true;
		
		// assert(this.interfaces.values() != null);
		for (Iface iface: this.interfaces.values()) {
			//Add router's interfaces & assume dist = 0 (neighbor nodes)
			int maskIp = iface.getSubnetMask(); 
			int dstIp = iface.getIpAddress() & maskIp;
			this.routeTable.insert(dstIp, 0, maskIp, iface);
		}

		for (Iface iface: this.interfaces.values()) {
			//Add router's interfaces & assume dist = 0 (neighbor nodes)
			this.sendRIPPacket(iface, isRequest, NOT_RIP_RESPONSE, -1, null);
		}

		//Create timer/timer task
		this.RIPTimer = new Timer();
		RIPTimer.scheduleFixedRate(this.getUpdateTask(), 0, 10000);
	}
	
	/**
	 * Load a new routing table from a file.
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile)
	{
		if (!routeTable.load(routeTableFile, this))
		{
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");

		//Static Routing Table successfully loaded -> RIP not enabled
		this.RIPEnabled = false;
	}
	
	/**
	 * Load a new ARP cache from a file.
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile)
	{
		if (!arpCache.load(arpCacheFile))
		{
			System.err.println("Error setting up ARP cache from file "
					+ arpCacheFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " +
                etherPacket.toString().replace("\n", "\n\t"));
		
		/********************************************************************/
		/* TODO: Handle packets                                             */
		
		switch(etherPacket.getEtherType())
		{
		case Ethernet.TYPE_IPv4:
			this.handleIpPacket(etherPacket, inIface);
			break;
		case Ethernet.TYPE_ARP:
			this.handleARPPacket(etherPacket, inIface);
		
		}
		
		/********************************************************************/
	}

	/**
	 * Configure RIP Packet accordingly and send
	 * @param inIface the interface on which the packet was received
	 * @param isRequest determines if RIP Request/Response is being sent
	 * @param responseType determines if RIP unsolicited/solicited response is being sent
	 * @param ipAddress ip of iface sending RIP request (RIP solicited is being sent)
	 * @param macAddress mac of iface sending RIP request (RIP solicited is being sent)
	 */
	public void sendRIPPacket(IFace inIface, boolean isRequest, int responseType, int ipAddress, byte[] macAddress) {
		// assert((isRequest && responseType == NOT_RIP_RESPONSE) || (!isRequest && ((responseType == IS_SOLICITED && macAddress != null) || responseType == IS_UNSOLICITED)));

		//Build base RIP Packet
		Ethernet ether = new Ethernet();
		IPv4 ip = new IPv4();
		RIPv2 rip = new RIPv2();
		UDP udp = new UDP();

		udp.setPayload(rip);
		ip.setPayload(udp);
		ether.setPayload(ip);

		//Configure type, src/dst MAC address
		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
		if (isRequest || (!isRequest && responseType == IS_UNSOLICITED)) {
			//RIP Unsolicited Response or RIP Request Packet -> MAC Address == Broadcast
			ether.setDestinationAddress(BROADCAST);
		} else {
			//RIP solicited Response -> MAC Address == outIFace Address from Request
			// assert(!isRequest && responseType == IS_SOLICITED && macAddress != null);
			ether.setDestinationAddress(macAddress);
		}

		//Configure TTL, Protocol, src/dst address (IPv4)
		ip.setTtl((byte) 15);
		ip.setProtocol(IPv4.PROTOCOL_UDP);
		ip.setSourceAddress(inIface.getIpAddress());
		if (isRequest || (!isRequest && responseType == IS_UNSOLICITED)) {
			//RIP Unsolicited Response or RIP Request Packet -> Dst Address == Multicast
			ip.setDestinationAddress(IPv4.toIPv4Address(MULTICAST));
		} else {
			//RIP solicited Response -> MAC Address == outIFace Address from Request
			// assert(!isRequest && responseType == IS_SOLICITED && macAddress != null);
			ip.setDestinationAddress(ipAddress);
		}

		udp.setSourcePort(UDP.RIP_PORT);
		udp.setDestinationPort(UDP.RIP_PORT);
		
		rip.setCommand(isRequest ? RIPv2.COMMAND_REQUEST : RIPv2.COMMAND_RESPONSE);


		//Build RIP Packet w/ route table
		for(RouteEntry curEntry: this.routeTable.getEntries()) {
			RIPv2Entry ripEntry = new RIPv2Entry(curEntry.getDestinationAddress(), curEntry.getMaskAddress(), curEntry.getDistance());
			ripEntry.setNextHopAddress(inIface.getIpAddress());
			rip.addEntry(ripEntry);
		}

		ether.serialize();
		sendPacket(ether, inIface);
	}

	private TimerTask getUpdateTask() {
		TimerTask curTask = new TimerTask() {
			public void run() {
				for(Iface iface: this.interfaces.values()) {
					this.sendRIPPacket(iface, !IS_RIP_REQUEST, IS_UNSOLICITED, -1, null);
				}
			}
			
		};
		return curTask;
	}

	// creates an ICMP time exceeded message by default. You can change the type of icmp message  
	// by changing the header of this message
	private Ethernet getGenericICMPMsg(Ethernet etherPacket, Iface inIface, byte[] srcMAC) {
		IPv4 packet = (IPv4) etherPacket.getPayload();

		// create icmp packet 
		Ethernet ether  = new Ethernet();
		IPv4 ip = new  IPv4();
		ICMP icmp = new ICMP();
		Data data = new Data();
		ether.setPayload(ip);
		ip.setPayload(icmp);
		icmp.setPayload(data);

		// icmp header
		icmp.setIcmpType((byte)11);
		icmp.setIcmpCode((byte)0);

		byte[] ipBytes = packet.serialize();
		int numBytes = packet.getHeaderLength() * 4 + 8;

		// padding 
		byte[] icmpBytes = new byte[4 + numBytes];

		for (int i = 0; i < numBytes; i++) {
			icmpBytes[i + 4] = ipBytes[i];
		}
		data.setData(icmpBytes);

		// ip header
		ip.setTtl((byte) 64);
		ip.setProtocol(IPv4.PROTOCOL_ICMP);
		ip.setSourceAddress(inIface.getIpAddress());
		ip.setDestinationAddress(packet.getSourceAddress());

		// mac header
		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setSourceMACAddress(inIface.getMacAddress().toBytes());

		// dest mac to previous hop 
		ether.setDestinationMACAddress(srcMAC);
		return ether;
	} 

	private void handleRIPPacket(IPv4 ipPacket, Iface inIface, byte[] macAddress) {
		if(ipPacket.getDestinationAddress() == inIface.getIpAddress() || ipPacket.getDestinationAddress() == IPv4.toIPv4Address(MULTICAST)) {
			if(ipPacket.getProtocol() == IPv4.PROTOCOL_UDP) {
				UDP udp = (UDP) ipPacket.getPayload();
				if (udp.getDestinationAddress() == UDP.RIP_PORT) {
					RIPv2 rip = (RIPv2) udp.getPayload();
					switch (rip.getCommand()) {
						case  RIPv2.COMMAND_REQUEST:
							//RIP Request received -> send RIP Solicited Response
							this.sendRIPPacket(inIface, !IS_RIP_REQUEST, IS_SOLICITED, ipPacket.getSourceAddress(), macAddress);
							break;
						case  RIPv2.COMMAND_RESPONSE:
							//RIP Response received -> potentially reduce distances
							boolean RIPUpdated = false;
							for(RIPv2 ripEntry: rip.getEntries()) {
								int address = ripEntry.getAddress();
								int subnetMask = ripEntry.getSubnetMask();
								int distance = ripEntry.getMetric() + 1;
								int nextHop = ripEntry.getNextHopAddress();

								ripEntry.setMetric(distance);

								RouteEntry tgtEntry = this.routeTable.lookup(address);
								if (tgtEntry == null || tgtEntry.getDistance() > distance) {
									//Either entry not in router or needs to be updated (just insert again)
									this.routeTable.insert(address, nextHop, subnetMask, inIface, distance);
									for (Iface iface : this.interfaces.values()) {
										//NOT Required but this should propogate updates to route table
										this.sendRIPPacket(inIface, !IS_RIP_REQUEST, IS_UNSOLICITED, -1, null);
									}
								}
							}
							break;
						default:
							System.out.println("INVALID RIP COMMAND");
							// assert(false);
					}
				}
			}
		}
	}
	
	private void handleIpPacket(Ethernet etherPacket, Iface inIface)
	{
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }

		byte[] srcMAC = etherPacket.getSourceMACAddress();
		
		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
        System.out.println("Handle IP packet");

		if (RIPEnabled) {
			handleRIPPacket(ipPacket, inIface, etherPacket.getSourceMACAddress());
		}

        // Verify checksum
        short origCksum = ipPacket.getChecksum();
        ipPacket.resetChecksum();
        byte[] serialized = ipPacket.serialize();
        ipPacket.deserialize(serialized, 0, serialized.length);
        short calcCksum = ipPacket.getChecksum();
        if (origCksum != calcCksum)
        { return; }
        
        // Check TTL
        ipPacket.setTtl((byte)(ipPacket.getTtl()-1));
        if (0 == ipPacket.getTtl()) { 
			// send icmp time exceeded message
			System.out.println("ttl is 0, sending icmp time exceeded");
			// Ethernet ethernet = null;
			// ethernet = getGenericICMPMsg(etherPacket, inIface, srcMAC);
			// if (ethernet != null) {
			// 	sendPacket(ethernet, inIface);
			// }
			sendICMPMsg((byte)11, (byte)0, inIface, srcMAC, etherPacket);
			return; 
		}
        
        // Reset checksum now that TTL is decremented
        ipPacket.resetChecksum();
        
        // Check if packet is destined for one of router's interfaces
        for (Iface iface : this.interfaces.values())
        {
        	if (ipPacket.getDestinationAddress() == iface.getIpAddress()) { 
				Ethernet ether = getGenericICMPMsg(etherPacket, inIface, srcMAC);
				ICMP icmp = (ICMP) ether.getPayload().getPayload();

				
				if (ipPacket.getProtocol() == IPv4.PROTOCOL_TCP || ipPacket.getProtocol() == IPv4.PROTOCOL_UDP) {
					// send destination port unreachable icmp message
					icmp.setIcmpType((byte)3);
					icmp.setIcmpCode((byte)3);
					sendPacket(ether, inIface);
				} else if (ipPacket.getProtocol() == IPv4.PROTOCOL_ICMP) {
					// send echo icmp message
					ICMP echo = (ICMP) ipPacket.getPayload();
					if (echo.getIcmpType() == 8) {
						IPv4 ipv4 = (IPv4) ether.getPayload();
						ipv4.setSourceAddress(ipPacket.getDestinationAddress());
						icmp.setIcmpType((byte)0);
						// icmp.setIcmpCode((byte)0);
						icmp.setPayload(echo.getPayload());
						sendPacket(ether, inIface);
					}
				}
				return; 
			
			}
        }
		
        // Do route lookup and forward
        this.forwardIpPacket(etherPacket, inIface, srcMAC);
	}

	private void sendICMPMsg(byte type, byte code, Iface inIface, byte[] srcMAC, Ethernet etherPacket) {
		Ethernet ethernet = null;
		ethernet = getGenericICMPMsg(etherPacket, inIface, srcMAC);
		if (ethernet != null) {
			ICMP icmp = (ICMP) ethernet.getPayload().getPayload();
			icmp.setIcmpType(type);
			icmp.setIcmpCode(code);
			sendPacket(ethernet, inIface);
		}
	}

    private void forwardIpPacket(Ethernet etherPacket, Iface inIface, byte[] srcMAC)
    {
        // Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }
        System.out.println("Forward IP packet");
		
		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
        int dstAddr = ipPacket.getDestinationAddress();

        // Find matching route table entry 
        RouteEntry bestMatch = this.routeTable.lookup(dstAddr);

        // If no entry matched, do nothing
        if (null == bestMatch) { 
			System.out.println("No route table entry found, sending dest net unreachable");
			sendICMPMsg((byte)3, (byte)0, inIface, srcMAC, etherPacket);
			return; 
		}

        // Make sure we don't sent a packet back out the interface it came in
        Iface outIface = bestMatch.getInterface();
        if (outIface == inIface)
        { return; }

        // Set source MAC address in Ethernet header
        etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());

        // If no gateway, then nextHop is IP destination
        int nextHop = bestMatch.getGatewayAddress();
        if (0 == nextHop)
        { nextHop = dstAddr; }

        // Set destination MAC address in Ethernet header
        ArpEntry arpEntry = this.arpCache.lookup(nextHop);
        if (null == arpEntry) { 
			if (requesterThreads.containsKey(nextHop) && !requesterThreads.get(nextHop).isFinished()) {
				requesterThreads.get(nextHop).addPacketToQueue(etherPacket, inIface, srcMAC);
			} else {
				Ethernet arpReq = generateArpReq(etherPacket, bestMatch.getInterface());
				ArpRequester newReq = new ArpRequester(arpReq, bestMatch.getInterface(), this);
				newReq.addPacketToQueue(etherPacket, inIface, srcMAC);

				requesterThreads.put(nextHop, newReq);

				Thread thread = new Thread(newReq);
				thread.start();

			}
			return; 
		}
		if (arpEntry.getMac() != null) {
			etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
		}
        
        
        this.sendPacket(etherPacket, outIface);
    }

	// generates an ARP reply packet 
	private Ethernet generateARPReply(Ethernet etherPacket, Iface inIface) {
		System.out.println("Generating ARP reply");
		ARP arpPacket = (ARP) etherPacket.getPayload();

		// ARP reply 
		Ethernet ether = new Ethernet();
		ARP reply = new ARP();

		// Ethernet
		ether.setEtherType(Ethernet.TYPE_ARP);
		ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
		ether.setDestinationMACAddress(etherPacket.getSourceMACAddress());

		// ARP header
		reply.setHardwareType(ARP.HW_TYPE_ETHERNET);
		reply.setProtocolType(ARP.PROTO_TYPE_IP);
		reply.setHardwareAddressLength((byte) Ethernet.DATALAYER_ADDRESS_LENGTH);
		reply.setProtocolAddressLength((byte)4);
		reply.setOpCode(ARP.OP_REPLY);
		reply.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
		reply.setSenderProtocolAddress(IPv4.toIPv4AddressBytes(inIface.getIpAddress()));
		reply.setTargetHardwareAddress(arpPacket.getSenderHardwareAddress());
		reply.setTargetProtocolAddress(arpPacket.getSenderProtocolAddress());

		ether.setPayload(reply);

		return ether;
		
	}

	private Ethernet generateArpReq(Ethernet etherPacket, Iface outIface) {
		IPv4 ipPacket = (IPv4) etherPacket.getPayload();

		byte [] broadcast= { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff };
		byte [] targetHWAddress={0,0,0,0,0,0};

		Ethernet ether = new Ethernet();
		ARP arpReq = new ARP();

		ether.setEtherType(Ethernet.TYPE_ARP);
		ether.setSourceMACAddress(outIface.getMacAddress().toBytes());
		ether.setDestinationMACAddress(broadcast);

		arpReq.setHardwareType(ARP.HW_TYPE_ETHERNET);
		arpReq.setProtocolType(ARP.PROTO_TYPE_IP);
		arpReq.setHardwareAddressLength((byte)(Ethernet.DATALAYER_ADDRESS_LENGTH));
		arpReq.setProtocolAddressLength((byte)4);
		
		arpReq.setOpCode(ARP.OP_REQUEST);
		arpReq.setSenderHardwareAddress(outIface.getMacAddress().toBytes());
		arpReq.setSenderProtocolAddress(IPv4.toIPv4AddressBytes(outIface.getIpAddress()));
		arpReq.setTargetHardwareAddress(targetHWAddress);

		int nextHop = 0;
		RouteEntry entry = routeTable.lookup(ipPacket.getDestinationAddress());
		if (entry.getGatewayAddress() == 0) {
			nextHop = ipPacket.getDestinationAddress();
		} else {
			nextHop = entry.getGatewayAddress();
		}

		arpReq.setTargetProtocolAddress(nextHop);
		ether.setPayload(arpReq);
		return ether;

	}

	private void handleARPPacket(Ethernet etherPacket, Iface inIface) {
		if (etherPacket.getEtherType() != Ethernet.TYPE_ARP)
		{ return; }

		ARP arpPacket = (ARP) etherPacket.getPayload();
		int targetIp = ByteBuffer.wrap(arpPacket.getTargetProtocolAddress()).getInt();
		int senderIp = ByteBuffer.wrap(arpPacket.getSenderProtocolAddress()).getInt();

		if (targetIp == inIface.getIpAddress()) {
			// ARP packet intended for us
			if (arpPacket.getOpCode() == ARP.OP_REQUEST) {
				// Handle ARP request
				Ethernet ether = generateARPReply(etherPacket, inIface);
				sendPacket(ether, inIface);
			} else {
				System.out.println("Handling ARP reply");
				if (arpCache.lookup(senderIp) == null) {
					ArpRequester requestThread = requesterThreads.get(senderIp);
					if (requestThread == null) {
						return;
					}

					if (!requestThread.isFinished()) {
						requestThread.setReply(etherPacket, inIface);
						arpCache.insert(new MACAddress(arpPacket.getSenderHardwareAddress()), senderIp);
					}

					requesterThreads.remove(senderIp);
				}
			}

		} else {
			return;
		}

	}
}
