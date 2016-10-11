#include <linux/types.h>

#ifndef __VSAPI2_BTSCAN_H_
#define __VSAPI2_BTSCAN_H_

struct btheader_npu2fpga {
	__u8 msg_type;
	__u8 res[3];
	__u32 npu_session_id;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u32 fpga_session_id:24;
	__u32 fpga_scan_direction:1;
	__u32 fpga_session_id1:7;
#elif defined(__BIG_ENDIAN_BITFIELD)
#  error "to be improved"
#else
#  error "Please fix <asm/byteorder.h>"
#endif	
	__u8 server_mac[6];
	__u8 client_mac[6];
	__u16 physical_port;
	__u16 vlan_tag;
	__u32 client_ip;
	__u16 client_port;
	__u16 server_port;
	__u32 server_ip;
	__u8 block_offset;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8 end_of_session:1;
	__u8 res1:7;
#elif defined(__BIG_ENDIAN_BITFIELD)
#  error "to be improved"
#else
#  error "Please fix <asm/byteorder.h>"
#endif	
	__u16 block_length;
} __attribute((packed));

struct btheader_fpga2npu {
	__u8 msg_type;
	__u8 res[3];
	__u32 npu_session_id;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u32 fpga_session_id:24;
	__u32 fpga_scan_direction:1;
	__u32 fpga_session_id1:7;
#elif defined(__BIG_ENDIAN_BITFIELD)
#  error "to be improved!"
#else
#  error "Please fix <asm/byteorder.h>"
#endif	
	__u32 virus_id;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u32 scan_results:8;
	__u32 skip_bytes:24;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u32 skip_bytes:24;
	__u32 scan_results:8;
#else
#  error "Please fix <asm/byteorder.h>"
#endif	
} __attribute((packed));

#if defined(__LITTLE_ENDIAN_BITFIELD)
#  define BTSCAN_GET_FPGASID(pbthdr)	((ntohl(pbthdr->fpga_session_id) | (ntohl(pbthdr->fpga_session_id1)>>23))>>1)
#  define BTSCAN_GET_DIR(pbthdr)	(pbthdr->fpga_scan_direction)
#  define BTSCAN_SET_FPGASID_DIR(pbthdr, sid, dir)	\
	{	\
		pbthdr->fpga_session_id=ntohl(sid<<1);	\
		pbthdr->fpga_scan_direction=dir;	\
		pbthdr->fpga_session_id1=(sid<<1)>>1;	\
	}
#elif defined(__BIG_ENDIAN_BITFIELD)
#  error "to be improved"
#else
#  error "Please fix <asm/byteorder.h>"
#endif

// for btscan bottom half
#define BTSCAN_BH_STATE__IDLE			0
#define BTSCAN_BH_STATE__FETCH_QUEUE		1
#define BTSCAN_BH_STATE__WAIT_FOR_DMADONE	2
#define BTSCAN_BH_STATE__MORE_DMA		3
#define BTSCAN_BH_STATE__SCANDONE		4

#define BTSCAN_DMA_STAGE_STARTOFDMA	0x2 // bit 1
#define BTSCAN_DMA_STAGE_ENDOFDMA	0x1 // bit 0

#endif	// __VSAPI2_BTSCAN_H_
