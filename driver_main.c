//--------------------------------------------------------------
// includes
//--------------------------------------------------------------
#include <linux/init.h>
#include <linux/module.h>

#include <linux/kconfig.h>

#include <linux/sched.h>

#include <linux/slab.h>        // kmalloc
#include <linux/netdevice.h>   // net_device
#include <linux/etherdevice.h> // ether_setup
#include <linux/skbuff.h>      // sk_buff 
#include <linux/errno.h>       // ENODEV & etc
#include <linux/spinlock.h>

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/in.h>


//--------------------------------------------------------------
// module information
//--------------------------------------------------------------
MODULE_AUTHOR("Andrey Dubas");
MODULE_LICENSE("GPL");


//--------------------------------------------------------------
// enums
//--------------------------------------------------------------

enum interrupt_status
{
	DEVICE_RX_INTERRUPT = 1,
	DEVICE_TX_INTERRUPT = 2
};


//--------------------------------------------------------------
// structs
//--------------------------------------------------------------

typedef struct driver_device_packet
{
	struct driver_device_packet *next;
	struct driver_device_packet *prev;
	char *data;
	int len;
} driver_device_packet_t;

typedef struct driver_device_private_data
{
	unsigned char status; //RX, TX

	driver_device_packet_t *tx_begin;
	driver_device_packet_t *rx_begin;

	driver_device_packet_t *tx_end;
	driver_device_packet_t *rx_end;

	driver_device_packet_t *tx_packet;
	driver_device_packet_t *rx_packet;

	struct sk_buff *skb;
	spinlock_t lock;
} driver_device_private_data_t;

//--------------------------------------------------------------
// typedefs
//--------------------------------------------------------------
typedef struct net_device net_device_t;
typedef struct sk_buff    sk_buff_t;


//--------------------------------------------------------------
// function declaration
//--------------------------------------------------------------

int driver_module_init(void);
void driver_module_exit(void);

void driver_device_register(net_device_t *dev);
int driver_device_packet_pool_setup(net_device_t *dev);

int driver_device_init_op(net_device_t *dev);
int driver_device_config (net_device_t *dev, struct ifmap *map);
int driver_device_open (net_device_t *dev);
int driver_device_close (net_device_t *dev);

int driver_device_start_xmit(sk_buff_t* skb, net_device_t* dev);
int driver_device_hardware_tx(char *data, int len, net_device_t *dev);
int driver_device_interrupt_regular(int irq, void *dev_id, struct pt_regs *regs);
int driver_device_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd);
int driver_device_set_mac_address(struct net_device *dev, void *addr);
driver_device_packet_t * driver_device_get_message(net_device_t *dev);


int driver_device_header_hard(sk_buff_t *skb, net_device_t *dev,
		unsigned short type, void *daddr, void *saddr, unsigned len);
int driver_device_rebuild_header(sk_buff_t *skb);

void driver_device_receive(net_device_t * dev, driver_device_packet_t *pkt);

// queue private data version
/*
driver_device_packet_t * enqueue_packet(driver_device_packet_t * begin, driver_device_packet_t * end, char * data, int len);
driver_device_packet_t * dequeue_packet(driver_device_packet_t * begin, driver_device_packet_t * end);
driver_device_packet_t * enqueue_packet(driver_device_packet_t * begin, char * data, int len);
driver_device_packet_t * dequeue_packet(driver_device_packet_t * begin);
*/

driver_device_packet_t * enqueue_tx(
		  driver_device_private_data_t * private_data
		, char* data, int len);
driver_device_packet_t * enqueue_rx(
		  driver_device_private_data_t * private_data
		, char * data, int len);

driver_device_packet_t * dequeue_rx(driver_device_private_data_t * private_data);
driver_device_packet_t * dequeue_tx(driver_device_private_data_t * private_data);

//--------------------------------------------------------------
// flobal variables
//--------------------------------------------------------------
module_init(driver_module_init);
module_exit(driver_module_exit);

//--------------------------------------------------------------
// flobal variables
//--------------------------------------------------------------
static net_device_t *driver_interface_loop[2];
static const char* driver_device_name_pattern = "vd%d";
const int addition_device_size = sizeof(driver_device_private_data_t);
const int pool_message_size = 100;


static const struct net_device_ops net_device_operations =
{
/*
 * the same for alloc_netdev
 * google it
 * A: the first function is driver_device_register
 * then - driver_device_init_op
 * */
/*
 * The kernel calls 
 * ndo_open() when you bring up and assign an address to a interface, 
 * ndo_stop() when you shut down the interface, and 
 * ndo_start_xmit() when it wants to transmit a packet.
 * */
    .ndo_init = driver_device_init_op,
    .ndo_open = driver_device_open,
    .ndo_stop = driver_device_close,

    .ndo_start_xmit = driver_device_start_xmit,
    /*
    Method that initiates the transmission of a packet. The full packet (protocol
    headers and all) is contained in a socket buffer ( sk_buff ) structure.
    */

    // .ndo_hard_header = driver_device_header_hard,
    /*
     * Function (called before hard_start_xmit) that builds the hardware header from
     * the src and dest hardware addresses that were previously retrieved; its
     * job is to organize the info passed to it as arguments into an appropriate,
     * device-specific hardware header. eth_header is the default for Ethernet-
     * like interfaces, and ether_setup assigns this field accordingly.
     *
     * */

    //.ndo_rebuild_header = driver_device_rebuild_header,

/*
    .ndo_get_stats = vboxNetAdpGetStats,
*/
    .ndo_set_config = driver_device_config,
    .ndo_set_mac_address = driver_device_set_mac_address,
    .ndo_do_ioctl = driver_device_ioctl
};

//-------------------------------------------------------------
// function definition
//-------------------------------------------------------------

int driver_module_init(void)
{
	int result = 0, i;
	printk(KERN_INFO "module init");

	for (i = 0; i < 2; ++i)
	{
		driver_interface_loop[i] = alloc_netdev(	
				  sizeof(driver_device_private_data_t)
				, driver_device_name_pattern
				, NET_NAME_UNKNOWN
				, driver_device_register
				);
	}

	if (driver_interface_loop[0] == NULL || 
			driver_interface_loop[1] == NULL)
	{
		printk(KERN_WARNING "can't allocate netdev");
		return -ENODEV;
	}

	for (i = 0; i < 2; ++i)
	{
		printk(KERN_INFO "registering device with name: %s\n", driver_interface_loop[i]->name);
		if ((result = register_netdev(driver_interface_loop[i])))
		{
			printk(KERN_WARNING "error %i registering device \'%s\'\n", i, driver_interface_loop[i]->name);
		}
	}

	if (result)
	{
		driver_module_exit();
	}

	return result;
}

void driver_module_exit(void)
{
	int i;
	printk(KERN_INFO "module exit");
	// TODO: cleanup
	for (i = 0; i < 2; ++i)
	{
		if (driver_interface_loop[i])
		{
			unregister_netdev(driver_interface_loop[i]);
			free_netdev(driver_interface_loop[i]);
		}
	}
}


void driver_device_register(net_device_t *dev)
{
	driver_device_private_data_t *data;
	printk(KERN_INFO "device registering with a name: %s \n", dev->name);
	ether_setup(dev);

	data = netdev_priv(dev);
	memset(data, 0x0, sizeof(driver_device_private_data_t));
	spin_lock_init(&data->lock);

	dev->netdev_ops = &net_device_operations;
}

driver_device_packet_t* driver_device_allocate_message(driver_device_packet_t *prev)
{
	driver_device_packet_t *next;
	next = kmalloc(sizeof(driver_device_packet_t), GFP_KERNEL);
	if (next != NULL)
	{
		prev->next = next;
		next->next = NULL;
	}
	return next;
}

int driver_device_packet_pool_setup(net_device_t *dev)
{
	int i;
	driver_device_private_data_t *priv_data = (driver_device_private_data_t*) netdev_priv(dev);
	driver_device_packet_t *next;

	printk(KERN_DEBUG "driver_device_packet_pool_setup\n");


	//----------------------------------------------------------------
	// initialize pool
	//----------------------------------------------------------------
	priv_data->rx_begin = priv_data->rx_end =  
		kmalloc(sizeof(driver_device_private_data_t*), GFP_KERNEL);
	if (priv_data == NULL)
	{
		return -1;
	}
	priv_data->rx_begin->next = NULL;

	priv_data->tx_begin = priv_data->tx_end = 
		kmalloc(sizeof(driver_device_private_data_t*), GFP_KERNEL);

	if (priv_data == NULL)
	{
		return -1;
	}
	priv_data->tx_begin->next = NULL;

	//----------------------------------------------------------------
	// add more memory, if possible
	//----------------------------------------------------------------
	for (i = 2; i < pool_message_size*2; ++i)
	{
		if (i%2 == 0)
		{
			next = driver_device_allocate_message(priv_data->rx_end);
			if (next == NULL) break;
			priv_data->rx_end = next;
		}
		else
		{
			next = driver_device_allocate_message(priv_data->tx_end);
			if (next == NULL) break;
			priv_data->tx_end = next;
		}
	}

	printk(KERN_INFO "initialized memory for %i packets", i/2);

	priv_data->tx_end->next = priv_data->tx_begin;
	priv_data->rx_end->next = priv_data->rx_begin;

	return 0;
}

int driver_device_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	printk(KERN_INFO "driver_device_ioctl\n");
	return 0;
}

int driver_device_set_mac_address(struct net_device *dev, void *addr)
{
	printk(KERN_INFO "driver_device_set_mac_address\n");
	return 0;
}

bool driver_device_pool_is_full(driver_device_packet_t *begin, driver_device_packet_t *end)
{
	return end->next == begin;
}

#include <linux/ip.h>
#include <linux/byteorder/generic.h>

char* driver_device_source_ip_address_to_string(struct iphdr* ip, char* str_addr)
{
	// big endian case
	char* buf;
	uint32_t addr = __be32_to_cpu(ip->saddr);
	buf = (char*)&addr;
	sprintf(str_addr, "%hhx:%hhx:%hhx:%hhx", buf[0], buf[1], buf[2], buf[2]);
	return str_addr;
}

char* driver_device_destination_ip_address_to_string(struct iphdr* ip, char* str_addr)
{
	// big endian case
	char* buf;
	uint32_t addr = __be32_to_cpu(ip->saddr);
	buf = (char*)&addr;
	sprintf(str_addr, "%hhx:%hhx:%hhx:%hhx", buf[0], buf[1], buf[2], buf[2]);
	return str_addr;
}

int driver_device_interrupt_regular(int irq, void * dev_id, struct pt_regs * regs)
{
	net_device_t *dev;
	driver_device_private_data_t *device_data;
	int status_word;
	driver_device_packet_t * pkt;
	//char s_ip_str_addr[12], d_ip_str_addr[12];

	unsigned long irq_flags;
	printk(KERN_INFO "regular interrupt happens\n");

	dev = (net_device_t*) dev_id;
	device_data = netdev_priv(dev);

	spin_lock_irqsave(&device_data->lock, irq_flags);


	status_word = device_data->status;
	device_data->status = 0;

	// driver_device_source_ip_address_to_string(dev->nh, s_ip_str_addr);
	// driver_device_destination_ip_address_to_string(dev->nh, d_ip_str_addr);

	/*
	if (status_word & DEVICE_RX_INTERRUPT)
	{
		printk(KERN_DEBUG "DEVICE_RX_INTERRUPT\n");
		// printf("RX interrupt: source: %s, destination: %s\n", s_ip_str_addr, d_ip_str_addr);
		pkt = dequeue_rx(device_data);
		if (pkt)
		{
			printk(KERN_DEBUG "receives a packet\n");
			driver_device_receive(dev, pkt);
		}

	}
	*/

	if (status_word & DEVICE_TX_INTERRUPT)
	{
		// printf("TX interrupt: source: %s, destination: %s\n", s_ip_str_addr, d_ip_str_addr);
		// device_data->stats.tx_packets++;
		// device_data->stats.tx_bytes += device_data->skb->len
		printk(KERN_DEBUG "DEVICE_TX_INTERRUPT\n");
		pkt = dequeue_tx(device_data);
		if (pkt)
		{
			// TODO: ?
		}
		dev_kfree_skb(device_data->skb); // delete the skb
	}

	spin_unlock_irqrestore(&device_data->lock, irq_flags);
	if (pkt)
	{
		// release the packet!
	}
	return 0;
}


//-----------------------------------------------------------------
// device receive
//-----------------------------------------------------------------

void driver_device_receive(net_device_t * dev, driver_device_packet_t *pkt)
{
	printk(KERN_INFO "driver_device_receive\n");
	sk_buff_t * skb;
	// driver_device_private_data_t * device_data = netdev_priv(dev);
	skb = dev_alloc_skb(pkt->len + 2);
	if (!skb)
	{
		printk(KERN_NOTICE "device lacks on memory - packet dropped\n");
		goto out;
	}
	skb_reserve(skb, 2);
	memcpy(skb_put(skb, pkt->len), pkt->data, pkt->len);

	/*write metadata*/
	skb->dev = dev;
	skb->protocol = eth_type_trans(skb, dev);
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	
	/*
	 * The function is the dev layer receive entry point by
	 * OLD STYLE device drivers
	 * */
	int congestion_status = netif_rx(skb); // used to pass the sk_buff to 
					       // the generic device layer when a receive
					       // operation completes
					       // it calls the right 3 level function
					       // netif_rx (net/core/dev)
	if (congestion_status == NET_RX_DROP)
	{
		printk(KERN_WARNING "a packet has been dropped (netif_rx)\n");
	}
	else
	{
		printk(KERN_WARNING "\n");
		printk(KERN_WARNING "\n");
	}
out:
	return;

}

//-----------------------------------------------------------------
// device interrupts
//-----------------------------------------------------------------

/*
 *Configuration changes (passed by ifconfig
 *
 * ifmap
 * struct ifmap {
 * unsigned long   mem_start;
 * unsigned long   mem_end;
 * unsigned short  base_addr;
 * unsigned char   irq;
 * unsigned char   dma;
 * unsigned char   port;
 * };
 *
 * */

int driver_device_config (net_device_t *dev, struct ifmap *map)
{
	printk(KERN_INFO "device configuration event");

	return 0;
}

int driver_device_init_op (net_device_t *dev)
{
	printk(KERN_INFO "device init op");

	return 0;
}

int driver_device_open (net_device_t *dev)
{
	printk(KERN_INFO "device open");

	return 0;
}

int driver_device_close (net_device_t *dev)
{
	printk(KERN_INFO "device close");
	
	return 0;
}





int driver_device_start_xmit(sk_buff_t* skb, net_device_t* dev)
{
        // before is called .ndo_hard_header = driver_device_header_hard,
	int len;
	char* data, short_pkg[ETH_ZLEN];
	driver_device_private_data_t * device_data = netdev_priv(dev);	
	printk(KERN_INFO "device start transmit\n");
	
	data = skb->data;
	len = skb->len;
	if (len < ETH_ZLEN) // TODO: anyway to tx data partially
	{
		memset(short_pkg, 0, ETH_ZLEN);
		memcpy(short_pkg, data, len);
		len = ETH_ZLEN;
		data = short_pkg;
	}

	device_data->skb = skb;
	dev->trans_start = jiffies; // timestamp

	driver_device_hardware_tx(data, len, dev);

	return 0;
}

int driver_device_hardware_tx(char *data, int len, net_device_t *src_dev)
{
	struct iphdr *ip_header;
	net_device_t* dest_dev;
	int dest_index;
	driver_device_private_data_t *dest_priv_data, *src_priv_data;
	u32 *source_addr, *dest_addr;

	if (len < sizeof(struct ethhdr) + sizeof(struct iphdr))
	{
		printk(KERN_ERR "the whole ip packet size is %i", len);
		return -1;
	}

	ip_header = (struct iphdr*)(data + sizeof(struct ethhdr));
	source_addr = &ip_header->saddr;
	dest_addr   = &ip_header->daddr;

	((u8 *)source_addr)[2] ^= 1; // address of remote
	((u8 *)dest_addr)[2] ^= 1; // address of remote

	ip_header->check = 0;
	ip_header->check = ip_fast_csum((unsigned char*)ip_header, ip_header->ihl);

	/*
	 * some other stuff
	 **/

	src_priv_data = netdev_priv(src_dev);
	if (enqueue_tx(src_priv_data, data, len))
	{
		src_priv_data->status |= DEVICE_TX_INTERRUPT;
		driver_device_interrupt_regular(0, src_dev, NULL);
	}

	dest_index =  driver_interface_loop[0] == src_dev? 1 : 0;
	dest_dev = driver_interface_loop[dest_index];
	dest_priv_data = netdev_priv(dest_dev);
	if(enqueue_rx(dest_priv_data, data, len))
	{
		// mocking an interrupt
		// packet picking happens there
		dest_priv_data->status |= DEVICE_RX_INTERRUPT;
		driver_device_interrupt_regular(0, dest_dev, NULL);
	}

	return 0;
}

/*
driver_device_packet_t * enqueue_packet(driver_device_packet_t * begin, driver_device_packet_t * end, char * data, int len)
{
	driver_device_packet_t * to_return;
	printk(KERN_INFO "enqueue_packet start\n");
	if (end->next == begin)
	{
		printk(KERN_INFO "queue is full\n");
		return NULL;
	}	

	end->data = data;
	end->len = len;

	to_return = end;
	end = end->next;

	printk(KERN_INFO "enqueue_packet end\n");

	return to_return;
}

driver_device_packet_t * dequeue_packet(driver_device_packet_t * begin, driver_device_packet_t * end)
{
	printk(KERN_INFO "dequeue_packet start\n");
	if (end == begin)
	{
		printk(KERN_INFO "queue is empty\n");
		return NULL;
	}

	end = end->prev;
	printk(KERN_INFO "dequeue_packet end\n");
	return end;
}
*/


driver_device_packet_t * enqueue_packet(
		  driver_device_packet_t ** packet_pointer_ref
		, char * data, int len, spinlock_t * lock)
{
	unsigned long flags;
	spin_lock_irqsave(lock, flags);
	if (*packet_pointer_ref)
	{
		printk(KERN_WARNING "enqueue_packet: packet already exists\n");
		return NULL;
	}	
	*packet_pointer_ref = kmalloc(sizeof(driver_device_packet_t), GFP_KERNEL);
	(*packet_pointer_ref)->data = data;
	(*packet_pointer_ref)->len = len;
	spin_unlock_irqrestore(lock, flags);
	return *packet_pointer_ref;
}

driver_device_packet_t * enqueue_tx(
		  driver_device_private_data_t * private_data
		, char * data, int len)
{
	//printk(KERN_INFO "enqueue_tx: begin: %p, end: %p\n", (void*)private_data->tx_begin, (void*)private_data->tx_end);
	//return enqueue_packet(private_data->tx_begin, private_data->tx_end, data, len);
	
	// if (private_data->tx_packet)
	// {
	// 	printk(KERN_WARNING "enqueue_tx: packet already exists\n");
	// 	return NULL;
	// }	
	// private_data->tx_packet = kmalloc(sizeof(driver_device_packet_t), GFP_KERNEL);
	// private_data->tx_packet->data = data;
	// private_data->tx_packet->len= len;
	// return private_data->tx_packet;

	return enqueue_packet(&private_data->tx_packet, data, len, &private_data->lock);
}

driver_device_packet_t * enqueue_rx(
		  driver_device_private_data_t * private_data
		, char * data, int len)
{
	//printk(KERN_INFO "enqueue_rx: begin: %p, end: %p\n", (void*)private_data->rx_begin, (void*)private_data->rx_end);
	//return enqueue_packet(private_data->rx_begin, private_data->rx_end, data, len);

	// if (private_data->rx_packet)
	// {
	// 	printk(KERN_WARNING "enqueue_rx: packet already exists\n");
	// 	return NULL;
	// }	
	// private_data->rx_packet = kmalloc(sizeof(driver_device_packet_t), GFP_KERNEL);
	// private_data->rx_packet->data = data;
	// private_data->rx_packet->len= len;
	// return private_data->rx_packet;
	return enqueue_packet(&private_data->rx_packet, data, len, &private_data->lock);
}

driver_device_packet_t * dequeue_packet(driver_device_packet_t ** packet_ref, spinlock_t * lock)
{
	unsigned long flags;
	spin_lock_irqsave(lock, flags);
	if (!(*packet_ref))
	{
		printk(KERN_WARNING "no packet in a queue\n");
		return NULL;
	}	
	driver_device_packet_t * pkt = *packet_ref;
	*packet_ref = NULL;
	spin_unlock_irqrestore(lock, flags);
	return pkt;
}

driver_device_packet_t * dequeue_rx(driver_device_private_data_t * private_data)
{
	// printk(KERN_INFO "dequeue_rx: begin: %p, end: %p\n", (void*)private_data->rx_begin, (void*)private_data->rx_end);
	// return dequeue_packet(private_data->rx_begin, private_data->rx_end);

	// if (!private_data->rx_packet)
	// {
	// 	printk(KERN_WARNING "dequeue_rx: no packet\n");
	// 	return NULL;
	// }	
	// driver_device_packet_t * pkt = private_data->rx_packet;
	// private_data->rx_packet = NULL;
	// return pkt;
	
	return dequeue_packet(&private_data->rx_packet, &private_data->lock);
}

driver_device_packet_t * dequeue_tx(driver_device_private_data_t * private_data)
{
	// printk(KERN_INFO "dequeue_rx: begin: %p, end: %p\n", (void*)private_data->tx_begin, (void*)private_data->tx_end);
	// return dequeue_packet(private_data->tx_begin, private_data->tx_end);
	
	
	// if (!private_data->tx_packet)
	// {
	// 	printk(KERN_WARNING "dequeue_tx: no packet\n");
	// 	return NULL;
	// }	
	// driver_device_packet_t * pkt = private_data->tx_packet;
	// private_data->tx_packet = NULL;
	// return pkt;
	return dequeue_packet(&private_data->tx_packet, &private_data->lock);
}

/*
driver_device_packet_t * device_driver_get_tx_buffer(net_device_t * dev)
{
	driver_device_private_data_t *private_data = netdev_priv(dev);
	driver_device_packet_t * pkt;
}`
*/

driver_device_packet_t* driver_device_get_message(net_device_t *dev)
{
	driver_device_private_data_t * device_data;
	device_data = netdev_priv(dev);
	driver_device_packet_t * pkt = 0;
	
	device_data = 0;
	return pkt;
}
int driver_device_header_hard(sk_buff_t *skb, net_device_t *dev,
		unsigned short type, void *daddr, void *saddr, unsigned len)
{
	printk(KERN_INFO "driver_device_header_hard");
	printk(KERN_INFO " header construction function\n");

	return 0;
}

int driver_device_rebuild_header(sk_buff_t *skb)
{
	printk(KERN_INFO "driver_device_rebuild_header");
	printk(KERN_INFO " header rebuild function\n");

	return 0;
}
