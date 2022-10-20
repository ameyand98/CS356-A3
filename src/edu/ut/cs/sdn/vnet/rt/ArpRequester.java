package edu.wisc.cs.sdn.vnet.rt;

import java.util.LinkedList;
import java.util.Queue;

import edu.wisc.cs.sdn.vnet.Iface;
import net.floodlightcontroller.packet.*;

public class ArpRequester implements Runnable {
    private Ethernet arpReq;
	private Iface arpRepIface;
    private Iface arpReqIface;
	private Router router;
	private boolean finished;
	
	private Queue<Ethernet> waitingPackets;
	private Queue<Iface> waitingIfaces;
	private Queue<byte[]> waitingSrcMacs;
	private Ethernet arpReply;

	public ArpRequester(Ethernet arpReq, Iface arpReqIface, Router router) {
		this.arpReq=arpReq;
		this.arpReqIface=arpReqIface;
		this.router=router;
		finished=false;		
		waitingPackets=new LinkedList<Ethernet>();
		waitingIfaces=new LinkedList<Iface>();
		waitingSrcMacs=new LinkedList<byte[]>();
	}

    public boolean isFinished() {
        return finished;
    }

    public void setReply(Ethernet reply, Iface replyIface) {
        this.arpReply = reply;
        this.arpRepIface = replyIface;
        finished = true;
    }

    public void addPacketToQueue(Ethernet packet, Iface inIface, byte[] srcMac) {
		waitingPackets.add(packet);
		waitingIfaces.add(inIface);
		waitingSrcMacs.add(srcMac);
	}

    public void run() {
		int reqCt = 0;
		while (reqCt < 3) {
			router.sendPacket(arpReq, arpReqIface);
			try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
			reqCt++;
			if(finished){
				break;
			}
		}

		finished = true;

		if (arpReply != null) {
			ARP arp = (ARP) arpReply.getPayload();
			while (!waitingPackets.isEmpty()) {
				Ethernet ether = waitingPackets.poll();
				ether.setDestinationMACAddress(arp.getSenderHardwareAddress());
				router.sendPacket(ether, arpRepIface);
			}
		} else {
			// Sending ICMP dest host unreachable 
			while (!waitingPackets.isEmpty()) {
				Ethernet ether = waitingPackets.poll();
				Iface inIface = waitingIfaces.poll();
				byte[] srcMAC = waitingSrcMacs.poll();

				Ethernet icmpEther = router.getGenericICMPMsg(ether, inIface, srcMAC);
				ICMP icmp = (ICMP) icmpEther.getPayload().getPayload();
				icmp.setIcmpType((byte)3);
				icmp.setIcmpCode((byte)1);

				router.sendPacket(icmpEther, inIface);
			}
		}
    }


}