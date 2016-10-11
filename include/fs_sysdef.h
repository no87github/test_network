/**
 * Copyright (C) 2005, Trend Micro Incorporated. All Rights Reserved. This
 * program is an unpublished copyrighted work which is proprietary to Trend
 * Micro Incorporated and contains confidential information that is not to be
 * reproduced or disclosed to any other person or entity without prior written
 * consent from Trend Micro, Inc. in each and every instance.
 *
 * WARNING: Unauthorized reproduction of this program as well as unauthorized
 * preparation of derivative works based upon the program or distribution of
 * copies by sale, rental, lease or lending are violations of federal copyright
 * laws and state trade secret laws, punishable by civil and criminal
 * penalties.
 */

#ifndef MP_SYSDEF_H
#define MP_SYSDEF_H

#include <stddef.h>
#include <stdint.h>
#include <mp_limits.h>
#include <TmVersion.h>

__BEGIN_DECLS

#define MP_UINT16_LO(uint16)	((uint16) & 0x00FF)
#define MP_UINT16_HI(uint16)	MP_UINT16_LO((uint16) >> 8)
#define MP_UINT16_MAKE(hi, lo)	((MP_UINT16_LO(hi) << 8) | MP_UINT16_LO(lo))

#define MP_UINT32_LO(uint32)	((uint32) & 0x0000FFFF)
#define MP_UINT32_HI(uint32)	MP_UINT32_LO((uint32) >> 16)
#define MP_UINT32_MAKE(hi, lo)  ((MP_UINT32_LO(hi) << 16) | MP_UINT32_LO(lo))

#define MP_UINT64_LO(uint64)	((uint64) & 0x00000000FFFFFFFF)
#define MP_UINT64_HI(uint64)	MP_UINT64_LO((uint64) >> 32)
#define MP_UINT64_MAKE(hi, lo)	((MP_UINT64_LO(hi) << 32) | MP_UINT64_LO(lo))

#ifndef MP_MAJOR_VERSION
#define MP_MAJOR_VERSION	TM_MAJOR_VERSION
#endif /* MP_MAJOR_VERSION */

#ifndef MP_MINOR_VERSION
#define MP_MINOR_VERSION	TM_MINOR_VERSION
#endif /* MP_MINOR_VERSION */

#ifndef MP_REVISION_NUMBER
#define MP_REVISION_NUMBER	TM_REVISION_NUM
#endif /* MP_REVISION_NUMBER */

#ifndef MP_BUILD_NUMBER
#define MP_BUILD_NUMBER		TM_BUILD_NUM
#endif /* MP_BUILD_NUMBER */

#ifndef MP_NIPQUAD
#define MP_NIPQUAD(addr) ((uint8_t *)&addr)[0], ((uint8_t *)&addr)[1], ((uint8_t *)&addr)[2], ((uint8_t *)&addr)[3]
#endif /* MP_NIPQUAD */

/**
 * It defaults to 511 instead of 512 because some systems store it
 * as an 8-bit datatype; 512 truncated to 8-bits is 0, while 511 is
 * 255 when truncated.
 */
#ifndef MP_LISTEN_BACKLOG
#define MP_LISTEN_BACKLOG (511)
#endif /* MP_LISTEN_BACKLOG */

#ifndef __MP_FUNCTION_NOT_IMPLEMENTED__
#define __MP_FUNCTION_NOT_IMPLEMENTED__
#endif /* __MP_FUNCTION_NOT_IMPLEMENTED__ */

#ifndef __MP_USE_OBSOLETE_FUNCTION__
#define __MP_USE_OBSOLETE_FUNCTION__
#endif /* __MP_USE_OBSOLETE_FUNCTION__ */

__END_DECLS

#endif /* MP_SYSDEF_H */
