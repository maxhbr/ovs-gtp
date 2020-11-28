#ifndef _WRAPPER_UAPI_LINUX_GTP_H_
#define _WRAPPER_UAPI_LINUX_GTP_H_

#include_next <linux/gtp.h>

#ifndef GTPA_PEER_ADDRESS
#define GTPA_PEER_ADDRESS GTPA_SGSN_ADDRESS
#endif

#endif
