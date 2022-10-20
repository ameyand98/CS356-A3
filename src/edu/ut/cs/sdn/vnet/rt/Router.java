package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
import java.util.*;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;

	// reuester threads for IPs
	private ConcurrentHashMap<Integer, ARPRequester> requesterThreads= new ConcurrentHashMap<Integer, ARPRequester>();
	
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
	
	private void handleIpPacket(Ethernet etherPacket, Iface inIface)
	{
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }

		byte[] srcMAC = etherPacket.getSourceMACAddress();
		
		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
        System.out.println("Handle IP packet");

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
					ARPRequester requestThread = requesterThreads.get(senderIp);
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
