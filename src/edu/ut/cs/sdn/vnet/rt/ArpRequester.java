package edu.wisc.cs.sdn.vnet.rt;

import java.util.LinkedList;
import java.util.Queue;

import edu.wisc.cs.sdn.vnet.Iface;
import net.floodlightcontroller.packet.*;

public class ArpRequester implements Runnable {
    private Ethernet arpReq;
	private Iface arpRepIface;
    private Iface arpReqIface;
	private Router rt;
	private boolean finished;
	
	private Queue<Ethernet> waiting;
	private Queue<Iface> waitingIfaces;
	private Queue<byte[]> waitingSrcMacs;
	private Ethernet arpReply;

	public ArpRequester(Ethernet arpReq, Iface arpReqIface, Router rt) {
		this.arpReq=arpReq;
		this.arpReqIface=arpReqIface;
		this.rt=rt;
		done=false;		
		waiting=new LinkedList<Ethernet>();
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
		waiting.add(packet);
		waitingIfaces.add(inIface);
		waitingSrcMacs.add(srcMac);
	}

    public void run() {
        
    }


}