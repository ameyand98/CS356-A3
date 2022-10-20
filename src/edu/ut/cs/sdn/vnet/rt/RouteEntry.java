package edu.ut.cs.sdn.vnet.rt;

import net.floodlightcontroller.packet.IPv4;
import edu.ut.cs.sdn.vnet.Iface;

import java.util.Timer;
import java.util.TimerTask;

/**
 * An entry in a route table.
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class RouteEntry 
{
	/** Destination IP address */
	private int destinationAddress;
	
	/** Gateway IP address */
	private int gatewayAddress;
	
	/** Subnet mask */
	private int maskAddress;
	
	/** Router interface out which packets should be sent to reach
	 * the destination or gateway */
	private Iface iface;

	/** Distance from Interface to destination/gateway */
	private int distance;

	/** RouteTable current Entry is in (for O(1) expiration) */
	private RouteTable curTable;

	/** Timer for expiration */
	private Timer timer;

	/** TIMEOUT constant in ms */
	private static final int TIMEOUT_MS = 30000;

	/**
	 * Create a new route table entry.
	 * @param destinationAddress destination IP address
	 * @param gatewayAddress gateway IP address
	 * @param maskAddress subnet mask
	 * @param iface the router interface out which packets should 
	 *        be sent to reach the destination or gateway
	 */
	public RouteEntry(int destinationAddress, int gatewayAddress, 
			int maskAddress, Iface iface)
	{
		this.destinationAddress = destinationAddress;
		this.gatewayAddress = gatewayAddress;
		this.maskAddress = maskAddress;
		this.iface = iface;
	}
	
	/**
	 * Create a new route table entry.
	 * @param destinationAddress destination IP address
	 * @param gatewayAddress gateway IP address
	 * @param maskAddress subnet mask
	 * @param iface the router interface out which packets should 
	 *        be sent to reach the destination or gateway
	 * @param distance the distance from the iface to the destination/gateway IP
	 */
	public RouteEntry(int destinationAddress, int gatewayAddress, 
			int maskAddress, Iface iface, int distance)
	{
		this.destinationAddress = destinationAddress;
		this.gatewayAddress = gatewayAddress;
		this.maskAddress = maskAddress;
		this.iface = iface;
		this.distance = distance;
	}

	/**
	 * Create a new route table entry.
	 * @param destinationAddress destination IP address
	 * @param gatewayAddress gateway IP address
	 * @param maskAddress subnet mask
	 * @param iface the router interface out which packets should 
	 *        be sent to reach the destination or gateway
	 * @param distance the distance from the iface to the destination/gateway IP
	 * @param curTable the RouteTable this entry resides in
	 */
	public RouteEntry(int destinationAddress, int gatewayAddress, 
			int maskAddress, Iface iface, int distance, RouteTable curTable)
	{
		this.destinationAddress = destinationAddress;
		this.gatewayAddress = gatewayAddress;
		this.maskAddress = maskAddress;
		this.iface = iface;
		this.distance = distance;
		this.curTable = curTable;
		
	}

	private TimerTask getTask() {
		curTask = new TimerTask() {
			public void run() {
				curTable.remove(this.getDestinationAddress(), this.getMaskAddress());
			}
		};
		return curTask;
	}

	/**
	 * Begin Timer for Entry Expiration
	 */
	public void beginTimer() {
		this.timer = new Timer();

		// assert(timer != null);
		this.timer.schedule(this.getTask(), TIMEOUT_MS);
	}

	/**
	 * reset Timer for Entry Expiration
	 */
	public void resetTimer() {
		// assert(this.gatewayAddress != 0);
		
		// Get new Timer
		this.timer.cancel();
		this.timer.purge();
		this.timer = new Timer();

		// assert(timer != null);
		this.timer.schedule(this.getTask(), TIMEOUT_MS);
	}
	
	/**
	 * @return destination IP address
	 */
	public int getDestinationAddress()
	{ return this.destinationAddress; }
	
	/**
	 * @return gateway IP address
	 */
	public int getGatewayAddress()
	{ return this.gatewayAddress; }

    public void setGatewayAddress(int gatewayAddress)
    { this.gatewayAddress = gatewayAddress; }
	
	/**
	 * @return subnet mask 
	 */
	public int getMaskAddress()
	{ return this.maskAddress; }

	/**
	 * @return distance
	 */
	public int getDistance()
	{ return this.distance; }

	public void setDistance(int distance)
	{ this.distance = distance; }

	/**
	 * @return curTable
	 */
	public RouteTable getCurTable()
	{ return this.curTable; }

	public void setCurTable(RouteTable curTable)
	{ this.curTable = curTable; }
	
	/**
	 * @return the router interface out which packets should be sent to 
	 *         reach the destination or gateway
	 */
	public Iface getInterface()
	{ return this.iface; }

    public void setInterface(Iface iface)
    { this.iface = iface; }
	
	public String toString()
	{
		return String.format("%s \t%s \t%s \t%s \t%d",
				IPv4.fromIPv4Address(this.destinationAddress),
				IPv4.fromIPv4Address(this.gatewayAddress),
				IPv4.fromIPv4Address(this.maskAddress),
				this.iface.getName(),
				this.distance);
	}
}
