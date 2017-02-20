#include<stdio.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<string.h>
#include<unistd.h>
#include<errno.h>

/*Linux*/
#define BTPROTO_HCI 		1
#define SOL_HCI         	0
#define HCI_FILTER      	2

#define EVT_CMD_STATUS		0x0F

#define HCI_EVENT_PKT		0x04

#define EVT_LE_META_EVENT       0x3E

#define HCI_FLT_EVENT_BITS      63

#define HCI_VENDOR_PKT          0xff

#define HCI_FLT_TYPE_BITS       31

/*HCI Packet Header */

#define HCI_EVENT		0x04
#define HCI_COMMAND		0x01

/*HCI Event Types*/

#define EVT_CMD_COMPLETE	0x0E

/*HCI OGF*/

#define CONTROL_BASEBAND	0x03

/*HCI OCF*/

#define HCI_RESET_COMMAND	0x0003

#define  uint8_t		unsigned char

/*HCI Event packet definitions*/
typedef struct
{
	sa_family_t    hci_family;
	unsigned short int hci_dev;
	unsigned short int hci_channel;
}sockaddr_hci;

typedef struct {
	unsigned char pkt_type;
        unsigned char opcode_msb;         /* OCF & OGF */
        unsigned char opcode_lsb;         /* OCF & OGF */
        unsigned char  plen;
}hci_command_hdr;

typedef struct {
	unsigned char pkt_type;
        unsigned char opcode_msb;         /* OCF & OGF */
        unsigned char opcode_lsb;         /* OCF & OGF */
        unsigned char plen;
	unsigned char set_event_mask_data[8]; 
}hci_set_event_mask;

typedef struct {
	unsigned char pkt_type;
        unsigned char opcode_msb;         /* OCF & OGF */
        unsigned char opcode_lsb;         /* OCF & OGF */
        unsigned char  plen;
	unsigned char adv_len;
	unsigned char adv_data[31];
}hci_set_le_adv_data;

typedef struct
{
	unsigned char event_type;
	unsigned char plen;
}hci_event_hdr;

typedef struct
{
	unsigned char pkt_type;
        unsigned char opcode_msb;         /* OCF & OGF */
        unsigned char opcode_lsb;         /* OCF & OGF */
        unsigned char  plen;
	unsigned char cod[3];	
}hci_set_cod;

typedef struct
{
	unsigned char pkt_type;
    unsigned char opcode_msb;         /* OCF & OGF */
    unsigned char opcode_lsb;         /* OCF & OGF */
    unsigned char plen;
	unsigned char scan_param;	
}hci_set_scan;

typedef struct
{
	unsigned char pkt_type;
    unsigned char opcode_msb;         /* OCF & OGF */
    unsigned char opcode_lsb;         /* OCF & OGF */
    unsigned char plen;
	unsigned char le_adv_enable;	
	
}hci_set_le_adv;
typedef struct
{
	unsigned char pkt_type;
    unsigned char opcode_msb;         /* OCF & OGF */
    unsigned char opcode_lsb;         /* OCF & OGF */
    unsigned char plen;
	unsigned char spp_param;	
}hci_set_spp;
struct hci_filter {
        unsigned int type_mask;
        unsigned int event_mask[2];
        unsigned short int opcode;
};

static inline void hci_set_bit(int nr, void *addr)
{
        *((unsigned int *) addr + (nr >> 5)) |= (1 << (nr & 31));
}

static inline void hci_filter_clear(struct hci_filter *f)
{
        memset(f, 0, sizeof(*f));
}

static inline void hci_filter_set_event(int e, struct hci_filter *f)
{
        hci_set_bit((e & HCI_FLT_EVENT_BITS), &f->event_mask);
}

static inline void hci_filter_set_ptype(int t, struct hci_filter *f)
{
        hci_set_bit((t == HCI_VENDOR_PKT) ? 0 : (t & HCI_FLT_TYPE_BITS), &f->type_mask);
}

static inline void hci_filter_set_opcode(int opcode, struct hci_filter *f)
{       
        f->opcode = opcode;
}    
