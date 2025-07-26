#ifndef CONFIG_H_IN
#define CONFIG_H_IN

#define HAVE_STATEMENT_EXPR 1
#define HAVE_BUILTIN_TYPES_COMPATIBLE_P 1
#define HAVE_TYPEOF 1
#define HAVE_ISBLANK 1
#define HAVE_BUILTIN_CLZ 1
#define HAVE_BUILTIN_CLZL 1

//#define PACKAGE_VERSION "35.1"

// FIXME: Remove this, The cmake version hard-requires new style CLOEXEC support
#define STREAM_CLOEXEC "e"

#define RDMA_CDEV_DIR "/dev/infiniband"

#define VERBS_PROVIDER_SUFFIX "-rdmav34.so"
#define IBVERBS_PABI_VERSION 34

// FIXME This has been supported in compilers forever, we should just fail to build on such old systems.
#define HAVE_FUNC_ATTRIBUTE_ALWAYS_INLINE 1

#define HAVE_FUNC_ATTRIBUTE_IFUNC 1

/* #undef HAVE_FUNC_ATTRIBUTE_SYMVER */

#define HAVE_WORKING_IF_H 1

// Operating mode for symbol versions
#define HAVE_FULL_SYMBOL_VERSIONS 1
/* #undef HAVE_LIMITED_SYMBOL_VERSIONS */

#define SIZEOF_LONG 8

#if 3 == 1
# define VERBS_IOCTL_ONLY 1
# define VERBS_WRITE_ONLY 0
#elif  3 == 2
# define VERBS_IOCTL_ONLY 0
# define VERBS_WRITE_ONLY 1
#elif  3 == 3
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
