#ifndef CONFIG_H_IN
#define CONFIG_H_IN

#define HAVE_STATEMENT_EXPR 1
#define HAVE_BUILTIN_TYPES_COMPATIBLE_P 1
#define HAVE_TYPEOF 1
#define HAVE_ISBLANK 1

// FIXME: Remove this, The cmake version hard-requires new style CLOEXEC support
#define STREAM_CLOEXEC "e"

#define IBV_CONFIG_DIR "/data2/upstream/libbnxt/tmp/v17/build/etc/libibverbs.d"
#define RS_CONF_DIR "/data2/upstream/libbnxt/tmp/v17/build/etc/rdma/rsocket"
#define IWPM_CONFIG_FILE "/data2/upstream/libbnxt/tmp/v17/build/etc/iwpmd.conf"

#define SRP_DEAMON_CONFIG_FILE "/data2/upstream/libbnxt/tmp/v17/build/etc/srp_daemon.conf"
#define SRP_DEAMON_LOCK_PREFIX "/usr/local/var/run/srp_daemon"

#define ACM_CONF_DIR "/data2/upstream/libbnxt/tmp/v17/build/etc/rdma"
#define IBACM_LIB_PATH "/data2/upstream/libbnxt/tmp/v17/build/lib/ibacm"
#define IBACM_BIN_PATH "/data2/upstream/libbnxt/tmp/v17/build/bin"
#define IBACM_PID_FILE "/usr/local/var/run/ibacm.pid"
#define IBACM_PORT_FILE "/usr/local/var/run/ibacm.port"
#define IBACM_LOG_FILE "/usr/local/var/log/ibacm.log"

#define VERBS_PROVIDER_DIR "/data2/upstream/libbnxt/tmp/v17/build/lib"
#define VERBS_PROVIDER_SUFFIX "-rdmav17.so"
#define IBVERBS_PABI_VERSION 17

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

#endif
