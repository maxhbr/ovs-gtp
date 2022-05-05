#ifndef _WRAPPER_UAPI_LINUX_GTP_H_
#define _WRAPPER_UAPI_LINUX_GTP_H_

#include_next <linux/gtp.h>

#ifndef GTPA_PEER_ADDRESS
#define GTPA_PEER_ADDRESS GTPA_SGSN_ADDRESS
#endif

enum {
	GTP_METADATA_V1
};

struct gtpu_metadata {
	__u8	ver;
	__u8	flags;
	__u8	type;
	__u8    qfi;
};

enum {
        IFLA_GTP_LWT_MAX
};
#endif
