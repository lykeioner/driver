#ifndef CONFIG_H_IN
#define CONFIG_H_IN

#define HAVE_STATEMENT_EXPR 1
#define HAVE_BUILTIN_TYPES_COMPATIBLE_P 1
#define HAVE_TYPEOF 1
#define HAVE_ISBLANK 1
#define HAVE_BUILTIN_CLZL 1

// FIXME: Remove this, The cmake version hard-requires new style CLOEXEC support
#define STREAM_CLOEXEC "e"

#define IBV_CONFIG_DIR "/root/rdma-core-stable-v19/build/etc/libibverbs.d"
#define RS_CONF_DIR "/root/rdma-core-stable-v19/build/etc/rdma/rsocket"
#define IWPM_CONFIG_FILE "/root/rdma-core-stable-v19/build/etc/iwpmd.conf"

#define SRP_DEAMON_CONFIG_FILE "/root/rdma-core-stable-v19/build/etc/srp_daemon.conf"
#define SRP_DEAMON_LOCK_PREFIX "/usr/local/var/run/srp_daemon"

#define ACM_CONF_DIR "/root/rdma-core-stable-v19/build/etc/rdma"
#define IBACM_LIB_PATH "/root/rdma-core-stable-v19/build/lib/ibacm"
#define IBACM_BIN_PATH "/root/rdma-core-stable-v19/build/bin"
#define IBACM_PID_FILE "/usr/local/var/run/ibacm.pid"
#define IBACM_PORT_BASE "ibacm-tcp.port"
#define IBACM_IBACME_PORT_FILE "/usr/local/var/run/" IBACM_PORT_BASE
#define IBACM_PORT_FILE "/usr/local/var/run/ibacm.port"
#define IBACM_LOG_FILE "/usr/local/var/log/ibacm.log"
#define IBACM_SERVER_BASE "ibacm-unix.sock"
#define IBACM_IBACME_SERVER_PATH "/usr/local/var/run/" IBACM_SERVER_BASE
#define IBACM_SERVER_PATH "/usr/local/var/run/ibacm.sock"

#define VERBS_PROVIDER_DIR "/root/rdma-core-stable-v19/build/lib"
#define VERBS_PROVIDER_SUFFIX "-rdmav19.so"
#define IBVERBS_PABI_VERSION 19

// FIXME This has been supported in compilers forever, we should just fail to build on such old systems.
#define HAVE_FUNC_ATTRIBUTE_ALWAYS_INLINE 1

#define HAVE_FUNC_ATTRIBUTE_IFUNC 1

#define HAVE_WORKING_IF_H 1

// Operating mode for symbol versions
#define HAVE_FULL_SYMBOL_VERSIONS 1
/* #undef HAVE_LIMITED_SYMBOL_VERSIONS */

#define SIZEOF_LONG 8

#if 3 == 3
# define HAVE_LIBNL3 1
#elif 3 == 1
# define HAVE_LIBNL1 1
#elif 3 == 0
# define NRESOLVE_NEIGH 1
#endif

#if 2 == 1
# define VERBS_IOCTL_ONLY 1
# define VERBS_WRITE_ONLY 0
#elif  2 == 2
# define VERBS_IOCTL_ONLY 0
# define VERBS_WRITE_ONLY 1
#elif  2 == 3
# define VERBS_IOCTL_ONLY 0
# define VERBS_WRITE_ONLY 0
#endif

// Configuration defaults

#define IBACM_SERVER_MODE_UNIX 0
#define IBACM_SERVER_MODE_LOOP 1
#define IBACM_SERVER_MODE_OPEN 2
#define IBACM_SERVER_MODE_DEFAULT IBACM_SERVER_MODE_UNIX

#define IBACM_ACME_PLUS_KERNEL_ONLY_DEFAULT 0

#endif
