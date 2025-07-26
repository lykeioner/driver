dnl Process this file with autoconf to produce a configure script.
AC_PREREQ(2.57)

dnl Edit the BNXT_LIB_NAME to appropriate name in the line below
dnl when building the package manually. Or export BNXT_LIB_NAME
dnl on the shell before running "sh autogen.sh".
dnl Depending on the targeted distro SCM build script should export
dnl proper value to BNXT_LIB_NAME shell variable.
m4_define([bnxtlib_name], [m4_esyscmd(if test -z $BNXT_LIB_NAME; then	\
				BNXT_LIB_NAME=`echo -n libbnxt_re`;	\
				fi; echo -n $BNXT_LIB_NAME;)])
m4_define([libname_postfix], [m4_esyscmd(echo -n bnxtlib_name | cut -b 4-)])

m4_define([verbsincpath], [m4_esyscmd(if test -z $PREFIX; then	\
				PREFIX=`echo -n /usr`;		\
				fi; echo -n $PREFIX;)])
AC_INIT([bnxtlib_name], m4_esyscmd(echo -n `grep "LIBBNXT_RE_BUILD_VERSION" \
        src/version.h | head -1 | awk '{print $3}'`))
BNXTLIBNAME=`echo -n bnxtlib_name`
DRVFILENAME=`echo -n libname_postfix`
AC_SUBST(BNXTLIBNAME)
AC_CONFIG_SRCDIR([src/main.h])
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_HEADERS(config.h)
AM_INIT_AUTOMAKE(subdir-objects)
AR_FLAGS="cr"
AC_SUBST(AR_FLAGS)
LT_INIT

AC_ARG_ENABLE(libcheck, [ --disable-libcheck    do not test for the presence of ib libraries],
[	if test x$enableval = xno ; then
		disable_libcheck=yes
	fi
])

AC_ARG_ENABLE(dplock, [ --disable-dplock	Disable data path lock],
[
	AC_MSG_CHECKING([for disable-dplock])
	if test x$enableval = xno ; then
		AC_MSG_RESULT(yes. Fast path lock disabled. Recommended only for IB resources managed from single thread. Result unpredictable if the same resource manged by multiple threads)
		disable_dplock=yes
	fi
])

AC_ARG_ENABLE(defarm, [ --enable-defarm		Enable deferred arm],
[
	AC_MSG_CHECKING([for enable-defarm])
	if test x$enableval = xno ; then
		AC_MSG_RESULT(yes. Deferred arm logic enabled)
		enable_defarm=yes
	fi
])

AC_ARG_ENABLE(deferdb, [ --enable-deferdb		Enable db deferral for posting wrs],
[
	AC_MSG_CHECKING([for enable-deferdb])
	if test x$enableval = xno ; then
		AC_MSG_RESULT(yes. Deferred dblogic enabled)
		enable_deferdb=yes
	fi
])

AC_ARG_ENABLE(dev_debug, [ --enable-dev-debug         Enable dev debug to inject errors and rocelib debug],
[
        AC_MSG_CHECKING([for enable-dev-debug])
        if test x$enableval = xno ; then
                AC_MSG_RESULT(yes. dev debug logic enabled)
                enable_dev_debug=yes
        fi
])

dnl Checks for programs
AC_PROG_CC
AC_CHECK_SIZEOF(long)

dnl Checks for libraries
if test "$disable_libcheck" != "yes"
then
AC_CHECK_LIB(ibverbs, ibv_get_device_list, [],
    AC_MSG_ERROR([ibv_get_device_list() not found.  libbnxt_re requires libibverbs.]))
fi

dnl Checks for header files.
AC_CHECK_HEADERS(sysfs/libsysfs.h)

dnl Detect rdma-core version
m4_define([rcore_version],[m4_esyscmd(rc=$(grep -o 		\
	_ibv_device_ops verbsincpath/include/infiniband/verbs.h |	\
	tail -1);						\
	if test ! -z "$rc"; then				\
		rcverv54=$(grep "umad_open_smi_port" \
                           verbsincpath/include/infiniband/umad.h|tail -1);    \
		rcverv49=$(grep "IBV_PORT_LINK_SPEED_XDR_SUP" \
			   verbsincpath/include/infiniband/verbs.h|tail -1);    \
		rcverv46=$(grep "IBV_QUERY_QP_DATA_IN_ORDER_RETURN_CAPS" \
			   verbsincpath/include/infiniband/verbs.h|tail -1);    \
		rcverv45=$(grep "IBV_WC_FLUSH" \
			   verbsincpath/include/infiniband/verbs.h|tail -1);	\
		rcverv44=$(grep "IBV_WR_ATOMIC_WRITE" \
			   verbsincpath/include/infiniband/verbs.h|tail -1);	\
		rcverv39=$(grep "IBV_RATE_800_GBPS" \
			   verbsincpath/include/infiniband/verbs.h|tail -1);	\
		rcverv37=$(grep "IBV_WC_DRIVER3" \
			   verbsincpath/include/infiniband/verbs.h|tail -1);	\
		rcverv36=$(grep "ibv_query_qp_data_in_order" \
			   verbsincpath/include/infiniband/verbs.h|tail -1);	\
		rcverv35=$(grep "ibv_is_fork_initialized" \
			   verbsincpath/include/infiniband/verbs.h|tail -1);	\
		rcverv34=$(grep "ibv_reg_dmabuf_mr" \
			   verbsincpath/include/infiniband/verbs.h|tail -1);	\
		rcverv33=$(grep "_compat_query_device" \
			   verbsincpath/include/infiniband/verbs.h|tail -1|grep -o int);	\
		rcverv32=$(grep -o ibv_gid_type \
			verbsincpath/include/infiniband/verbs.h|tail -1);	\
		rcverv31=$(grep -o ibv_import_device \
			verbsincpath/include/infiniband/verbs.h|tail -1);	\
		rcverv29=$(grep -o ibv_flow_label_to_udp_sport \
			verbsincpath/include/infiniband/verbs.h|tail -1);	\
		rcverv28=$(grep -o IBV_ACCESS_HUGETLB \
			verbsincpath/include/infiniband/verbs.h|tail -1);	\
		rcverv25=$(grep -o ibv_reg_mr_iova		\
			verbsincpath/include/infiniband/verbs.h|tail -1);	\
		rcverv24=$(grep -o ibv_qp_create_send_ops_flags		\
			verbsincpath/include/infiniband/verbs.h|tail -1);	\
		rcverv22=$(grep -o ibv_advise_mr		\
			verbsincpath/include/infiniband/verbs.h|tail -1);	\
		rcverv19=$(grep -o ibv_alloc_dm_attr			\
			verbsincpath/include/infiniband/verbs.h|tail -1);	\
		rcverv17=$(grep -o ibv_alloc_td			\
			verbsincpath/include/infiniband/verbs.h|tail -1);	\
		if test ! -z "$rcverv54"; then                          \
			echo -n "v54";
		elif test ! -z "$rcverv49"; then                          \
			echo -n "v49";                          \
		elif test ! -z "$rcverv46"; then                                \
			echo -n "v46";                          \
		elif test ! -z "$rcverv45"; then                                \
			echo -n "v45";				\
		elif test ! -z "$rcverv44"; then			        \
			echo -n "v44";				\
		elif test ! -z "$rcverv39"; then			        \
			echo -n "v39";				\
		elif test ! -z "$rcverv37"; then			        \
			echo -n "v37";				\
		elif test ! -z "$rcverv36"; then			        \
			echo -n "v36";				\
		elif test ! -z "$rcverv35"; then			\
			echo -n "v35";				\
		elif test ! -z "$rcverv34"; then			\
			echo -n "v34";				\
		elif test ! -z "$rcverv33"; then			\
			echo -n "v33";				\
		elif test ! -z "$rcverv32"; then			\
			echo -n "v32";				\
		elif test ! -z "$rcverv31"; then			\
			echo -n "v31";				\
		elif test ! -z "$rcverv29"; then			\
			echo -n "v29";				\
		elif test ! -z "$rcverv28"; then			\
			echo -n "v28";				\
		elif test ! -z "$rcverv25"; then			\
			echo -n "v25";				\
		elif test ! -z "$rcverv24"; then			\
			echo -n "v24";				\
		elif test ! -z "$rcverv22"; then			\
			echo -n "v22";				\
		elif test ! -z "$rcverv19"; then			\
			echo -n "v19";				\
		elif test ! -z "$rcverv17"; then		\
			echo -n "v17";				\
		else						\
			rcver=$(grep -o IBV_RX_HASH_INNER	\
			verbsincpath/include/infiniband/verbs.h|tail -1);	\
			if test ! -z "$rcver"; then		\
				echo -n "v16";			\
			elif test ! -z `grep -o IBV_RAW_PACKET_CAP_DELAY_DROP		\
				verbsincpath/include/infiniband/verbs.h|tail -1`; then		\
				echo -n "v15";			\
			else					\
				echo -n "v14";			\
			fi					\
		fi
	else							\
		echo -n "";					\
	fi)
	])
RDMA_CORE_VERSION=`echo -n rcore_version`
AC_SUBST(RDMA_CORE_VERSION)

dnl Checks for the IB headers
if test "$disable_libcheck" != "yes"
then
	AC_CHECK_HEADER(infiniband/verbs.h, [],
		AC_MSG_ERROR([infiniband/verbs.h not found.]))
	rc=`grep -o _ibv_device_ops verbsincpath/include/infiniband/verbs.h|tail -1`
	if test -z "$rc"; then
		AC_CHECK_HEADER(infiniband/driver.h, [],
			AC_MSG_ERROR([<infiniband/driver.h> not found. Is libibverbs installed?]))
	else
		if test ! -e src/rc-compat/$(echo -n rcore_version)/driver.h; then
			AC_MSG_ERROR([src/rc-compat/driver.h not found. Corrupted distribution?])
		fi
	fi
fi

m4_define([__include_string__],[m4_esyscmd(rc=$(grep -o		\
	_ibv_device_ops verbsincpath/include/infiniband/verbs.h|        \
	tail -1);						\
	if test ! -z "$rc"; then				\
		echo -n "#include ";		\
		echo -n "\"src/rc-compat/`echo -n rcore_version`/driver.h\"";	\
	else							\
		echo -n "#include <infiniband/driver.h>";	\
	fi)
	])

m4_define([__include_path__],[m4_esyscmd(rc=$(grep -o		\
	_ibv_device_ops verbsincpath/include/infiniband/verbs.h|        \
	tail -1);						\
	if test ! -z "$rc"; then				\
		echo -n "-I./src/rc-compat/`echo -n rcore_version`";	\
	else							\
		echo -n "-Iverbsincpath/include";			\
	fi)
	])

AC_MSG_CHECKING([for rdma-core framework usage])
rc=`grep -o _ibv_device_ops verbsincpath/include/infiniband/verbs.h|tail -1`
if test "$rc" != ""; then
	AC_DEFINE([HAVE_RDMA_CORE_PKG],[1],[using rdma-core package version rcore_version])
	AC_DEFINE([HAVE_IBV_CMD_MODIFY_QP_EX],[1],[ibv_cmd_modify_qp_ex supported])
	RDMA_CORE_HEADERS=`echo -n __include_path__`
	case  "$(echo -n rcore_version)" in
	v54)
		AC_MSG_RESULT(yes using v53/v54)
		AC_DEFINE([IBV_CMD_REG_DMABUF_MR_HAS_8_ARG],[1],
			  [Rdma-Core Package ibv_cmd_reg_dmabuf_mr has 8 arguments])
		AC_DEFINE([IBV_CMD_CREATE_FLOW_HAS_5_ARG],[1],
			  [Rdma-Core Package ibv_cmd_create_flow has 5 arguments])
		AC_DEFINE([VERBS_ONLY_QUERY_DEVICE_EX_DEFINED],[1],
			  [Rdma-Core Package has only query_device_ex])
		AC_DEFINE([IBV_CMD_MODIFY_QP_EX_HAS_7_ARG],[1],
			  [Rdma-Core Package ibv_cmd_modify_qp_ex has 7 arguments])
		AC_DEFINE([IBV_FREE_CONTEXT_IN_CONTEXT_OPS],[1],
			  [Rdma-Core Package has free context in ibv_context_ops])
		AC_DEFINE([REG_MR_VERB_HAS_5_ARG],[1],
			  [Rdma-Core Package reg_mr has 5 argument])
		AC_DEFINE([IBV_CMD_ALLOC_MW_HAS_1_ARG],[1],
			  [Rdma-Core Package ibv_cmd_alloc_mw has single argument])
		AC_DEFINE([PROVIDER_DRIVER_HAS_2_ARGS],[1],
			  [Rdma-Core Package PROVIDER_DRIVER macro has 2 arguments])
		AC_DEFINE([ALLOC_CONTEXT_HAS_PRIVATE_DATA],[1],
			  [Rdma-Core Package alloc_context has private data])
		AC_DEFINE([VERBS_MR_DEFINED],[1],
			  [Rdma-Core Package has verbs_mr defined])
		AC_DEFINE([VERBS_INIT_AND_ALLOC_CONTEXT_HAS_5_ARG],[1],
			  [Rdma-Core Package has 5 Arg for verbs_init_and_alloc_context macro])
		AC_DEFINE([RCP_HAS_PROVIDER_DRIVER],[1],
			  [Rdma-Core Package has PROVIDER_DRIVER macro])
		AC_DEFINE([RCP_USE_IB_UVERBS],[1],
			[Rdma-Core Package uses IB user verbs API])
		AC_DEFINE([RCP_USE_ALLOC_CONTEXT],[1],
			[Rdma-Core Package uses alloc_context instead of init_context])
		AC_DEFINE([HAVE_IBV_DMABUF],[1],
			[Rdma-Core Package has verbs ibv_reg_dmabuf_mr defined])
		AC_DEFINE([IBV_CMD_CREATE_QP_EX_HAS_7_ARG],[1],
			  [Rdma-Core Package ibv_cmd_create_qp_ex has 7 arguments])
		AC_DEFINE([HAVE_IBV_WR_API],[1],
			[Rdma-Core Package has verbs ibv_qp_ex defined])
		rc=`grep -o ibv_read_sysfs_file src/rc-compat/v54/driver.h|tail -1`
	;;

	v49)
		AC_MSG_RESULT(yes using v49/v50/v51/v52)
		AC_DEFINE([VERBS_ONLY_QUERY_DEVICE_EX_DEFINED],[1],
			  [Rdma-Core Package has only query_device_ex])
		AC_DEFINE([IBV_CMD_MODIFY_QP_EX_HAS_7_ARG],[1],
			  [Rdma-Core Package ibv_cmd_modify_qp_ex has 7 arguments])
		AC_DEFINE([IBV_FREE_CONTEXT_IN_CONTEXT_OPS],[1],
			  [Rdma-Core Package has free context in ibv_context_ops])
		AC_DEFINE([REG_MR_VERB_HAS_5_ARG],[1],
			  [Rdma-Core Package reg_mr has 5 argument])
		AC_DEFINE([IBV_CMD_ALLOC_MW_HAS_1_ARG],[1],
			  [Rdma-Core Package ibv_cmd_alloc_mw has single argument])
		AC_DEFINE([PROVIDER_DRIVER_HAS_2_ARGS],[1],
			  [Rdma-Core Package PROVIDER_DRIVER macro has 2 arguments])
		AC_DEFINE([ALLOC_CONTEXT_HAS_PRIVATE_DATA],[1],
			  [Rdma-Core Package alloc_context has private data])
		AC_DEFINE([VERBS_MR_DEFINED],[1],
			  [Rdma-Core Package has verbs_mr defined])
		AC_DEFINE([VERBS_INIT_AND_ALLOC_CONTEXT_HAS_5_ARG],[1],
			  [Rdma-Core Package has 5 Arg for verbs_init_and_alloc_context macro])
		AC_DEFINE([RCP_HAS_PROVIDER_DRIVER],[1],
			  [Rdma-Core Package has PROVIDER_DRIVER macro])
		AC_DEFINE([RCP_USE_IB_UVERBS],[1],
			[Rdma-Core Package uses IB user verbs API])
		AC_DEFINE([RCP_USE_ALLOC_CONTEXT],[1],
			[Rdma-Core Package uses alloc_context instead of init_context])
		AC_DEFINE([HAVE_IBV_DMABUF],[1],
			[Rdma-Core Package has verbs ibv_reg_dmabuf_mr defined])
		AC_DEFINE([IBV_CMD_CREATE_QP_EX_HAS_7_ARG],[1],
			  [Rdma-Core Package ibv_cmd_create_qp_ex has 7 arguments])
		AC_DEFINE([HAVE_IBV_WR_API],[1],
			[Rdma-Core Package has verbs ibv_qp_ex defined])
		rc=`grep -o ibv_read_sysfs_file src/rc-compat/v49/driver.h|tail -1`
	;;

	v46)
		AC_MSG_RESULT(yes using v46/v47/v48)
		AC_DEFINE([VERBS_ONLY_QUERY_DEVICE_EX_DEFINED],[1],
			  [Rdma-Core Package has only query_device_ex])
		AC_DEFINE([IBV_CMD_MODIFY_QP_EX_HAS_7_ARG],[1],
			  [Rdma-Core Package ibv_cmd_modify_qp_ex has 7 arguments])
		AC_DEFINE([IBV_FREE_CONTEXT_IN_CONTEXT_OPS],[1],
			  [Rdma-Core Package has free context in ibv_context_ops])
		AC_DEFINE([REG_MR_VERB_HAS_5_ARG],[1],
			  [Rdma-Core Package reg_mr has 5 argument])
		AC_DEFINE([IBV_CMD_ALLOC_MW_HAS_1_ARG],[1],
			  [Rdma-Core Package ibv_cmd_alloc_mw has single argument])
		AC_DEFINE([PROVIDER_DRIVER_HAS_2_ARGS],[1],
			  [Rdma-Core Package PROVIDER_DRIVER macro has 2 arguments])
		AC_DEFINE([ALLOC_CONTEXT_HAS_PRIVATE_DATA],[1],
			  [Rdma-Core Package alloc_context has private data])
		AC_DEFINE([VERBS_MR_DEFINED],[1],
			  [Rdma-Core Package has verbs_mr defined])
		AC_DEFINE([VERBS_INIT_AND_ALLOC_CONTEXT_HAS_5_ARG],[1],
			  [Rdma-Core Package has 5 Arg for verbs_init_and_alloc_context macro])
		AC_DEFINE([RCP_HAS_PROVIDER_DRIVER],[1],
			  [Rdma-Core Package has PROVIDER_DRIVER macro])
		AC_DEFINE([RCP_USE_IB_UVERBS],[1],
			[Rdma-Core Package uses IB user verbs API])
		AC_DEFINE([RCP_USE_ALLOC_CONTEXT],[1],
			[Rdma-Core Package uses alloc_context instead of init_context])
		AC_DEFINE([HAVE_IBV_DMABUF],[1],
			[Rdma-Core Package has verbs ibv_reg_dmabuf_mr defined])
		AC_DEFINE([IBV_CMD_CREATE_QP_EX_HAS_7_ARG],[1],
			  [Rdma-Core Package ibv_cmd_create_qp_ex has 7 arguments])
		AC_DEFINE([HAVE_IBV_WR_API],[1],
			[Rdma-Core Package has verbs ibv_qp_ex defined])
		rc=`grep -o ibv_read_sysfs_file src/rc-compat/v46/driver.h|tail -1`
	;;

	v45)
		AC_MSG_RESULT(yes using v45)
		AC_DEFINE([VERBS_ONLY_QUERY_DEVICE_EX_DEFINED],[1],
			  [Rdma-Core Package has only query_device_ex])
		AC_DEFINE([IBV_CMD_MODIFY_QP_EX_HAS_7_ARG],[1],
			  [Rdma-Core Package ibv_cmd_modify_qp_ex has 7 arguments])
		AC_DEFINE([IBV_FREE_CONTEXT_IN_CONTEXT_OPS],[1],
			  [Rdma-Core Package has free context in ibv_context_ops])
		AC_DEFINE([REG_MR_VERB_HAS_5_ARG],[1],
			  [Rdma-Core Package reg_mr has 5 argument])
		AC_DEFINE([IBV_CMD_ALLOC_MW_HAS_1_ARG],[1],
			  [Rdma-Core Package ibv_cmd_alloc_mw has single argument])
		AC_DEFINE([PROVIDER_DRIVER_HAS_2_ARGS],[1],
			  [Rdma-Core Package PROVIDER_DRIVER macro has 2 arguments])
		AC_DEFINE([ALLOC_CONTEXT_HAS_PRIVATE_DATA],[1],
			  [Rdma-Core Package alloc_context has private data])
		AC_DEFINE([VERBS_MR_DEFINED],[1],
			  [Rdma-Core Package has verbs_mr defined])
		AC_DEFINE([VERBS_INIT_AND_ALLOC_CONTEXT_HAS_5_ARG],[1],
			  [Rdma-Core Package has 5 Arg for verbs_init_and_alloc_context macro])
		AC_DEFINE([RCP_HAS_PROVIDER_DRIVER],[1],
			  [Rdma-Core Package has PROVIDER_DRIVER macro])
		AC_DEFINE([RCP_USE_IB_UVERBS],[1],
			[Rdma-Core Package uses IB user verbs API])
		AC_DEFINE([RCP_USE_ALLOC_CONTEXT],[1],
			[Rdma-Core Package uses alloc_context instead of init_context])
		AC_DEFINE([HAVE_IBV_DMABUF],[1],
			[Rdma-Core Package has verbs ibv_reg_dmabuf_mr defined])
		AC_DEFINE([IBV_CMD_CREATE_QP_EX_HAS_7_ARG],[1],
			  [Rdma-Core Package ibv_cmd_create_qp_ex has 7 arguments])
		AC_DEFINE([HAVE_IBV_WR_API],[1],
			[Rdma-Core Package has verbs ibv_qp_ex defined])
		rc=`grep -o ibv_read_sysfs_file src/rc-compat/v45/driver.h|tail -1`
	;;

	v44)
		AC_MSG_RESULT(yes using v44)
		AC_DEFINE([VERBS_ONLY_QUERY_DEVICE_EX_DEFINED],[1],
			  [Rdma-Core Package has only query_device_ex])
		AC_DEFINE([IBV_CMD_MODIFY_QP_EX_HAS_7_ARG],[1],
			  [Rdma-Core Package ibv_cmd_modify_qp_ex has 7 arguments])
		AC_DEFINE([IBV_FREE_CONTEXT_IN_CONTEXT_OPS],[1],
			  [Rdma-Core Package has free context in ibv_context_ops])
		AC_DEFINE([REG_MR_VERB_HAS_5_ARG],[1],
			  [Rdma-Core Package reg_mr has 5 argument])
		AC_DEFINE([IBV_CMD_ALLOC_MW_HAS_1_ARG],[1],
			  [Rdma-Core Package ibv_cmd_alloc_mw has single argument])
		AC_DEFINE([PROVIDER_DRIVER_HAS_2_ARGS],[1],
			  [Rdma-Core Package PROVIDER_DRIVER macro has 2 arguments])
		AC_DEFINE([ALLOC_CONTEXT_HAS_PRIVATE_DATA],[1],
			  [Rdma-Core Package alloc_context has private data])
		AC_DEFINE([VERBS_MR_DEFINED],[1],
			  [Rdma-Core Package has verbs_mr defined])
		AC_DEFINE([VERBS_INIT_AND_ALLOC_CONTEXT_HAS_5_ARG],[1],
			  [Rdma-Core Package has 5 Arg for verbs_init_and_alloc_context macro])
		AC_DEFINE([RCP_HAS_PROVIDER_DRIVER],[1],
			  [Rdma-Core Package has PROVIDER_DRIVER macro])
		AC_DEFINE([RCP_USE_IB_UVERBS],[1],
			[Rdma-Core Package uses IB user verbs API])
		AC_DEFINE([RCP_USE_ALLOC_CONTEXT],[1],
			[Rdma-Core Package uses alloc_context instead of init_context])
		AC_DEFINE([HAVE_IBV_DMABUF],[1],
			[Rdma-Core Package has verbs ibv_reg_dmabuf_mr defined])
		AC_DEFINE([IBV_CMD_CREATE_QP_EX_HAS_7_ARG],[1],
			  [Rdma-Core Package ibv_cmd_create_qp_ex has 7 arguments])
		AC_DEFINE([HAVE_IBV_WR_API],[1],
			[Rdma-Core Package has verbs ibv_qp_ex defined])
		rc=`grep -o ibv_read_sysfs_file src/rc-compat/v44/driver.h|tail -1`
	;;

	v39)
		AC_MSG_RESULT(yes using v39/v40/v41/v42/v43)
		AC_DEFINE([VERBS_ONLY_QUERY_DEVICE_EX_DEFINED],[1],
			  [Rdma-Core Package has only query_device_ex])
		AC_DEFINE([IBV_CMD_MODIFY_QP_EX_HAS_7_ARG],[1],
			  [Rdma-Core Package ibv_cmd_modify_qp_ex has 7 arguments])
		AC_DEFINE([IBV_FREE_CONTEXT_IN_CONTEXT_OPS],[1],
			  [Rdma-Core Package has free context in ibv_context_ops])
		AC_DEFINE([REG_MR_VERB_HAS_5_ARG],[1],
			  [Rdma-Core Package reg_mr has 5 argument])
		AC_DEFINE([IBV_CMD_ALLOC_MW_HAS_1_ARG],[1],
			  [Rdma-Core Package ibv_cmd_alloc_mw has single argument])
		AC_DEFINE([PROVIDER_DRIVER_HAS_2_ARGS],[1],
			  [Rdma-Core Package PROVIDER_DRIVER macro has 2 arguments])
		AC_DEFINE([ALLOC_CONTEXT_HAS_PRIVATE_DATA],[1],
			  [Rdma-Core Package alloc_context has private data])
		AC_DEFINE([VERBS_MR_DEFINED],[1],
			  [Rdma-Core Package has verbs_mr defined])
		AC_DEFINE([VERBS_INIT_AND_ALLOC_CONTEXT_HAS_5_ARG],[1],
			  [Rdma-Core Package has 5 Arg for verbs_init_and_alloc_context macro])
		AC_DEFINE([RCP_HAS_PROVIDER_DRIVER],[1],
			  [Rdma-Core Package has PROVIDER_DRIVER macro])
		AC_DEFINE([RCP_USE_IB_UVERBS],[1],
			[Rdma-Core Package uses IB user verbs API])
		AC_DEFINE([RCP_USE_ALLOC_CONTEXT],[1],
			[Rdma-Core Package uses alloc_context instead of init_context])
		AC_DEFINE([HAVE_IBV_DMABUF],[1],
			[Rdma-Core Package has verbs ibv_reg_dmabuf_mr defined])
		AC_DEFINE([IBV_CMD_CREATE_QP_EX_HAS_7_ARG],[1],
			  [Rdma-Core Package ibv_cmd_create_qp_ex has 7 arguments])
		AC_DEFINE([HAVE_IBV_WR_API],[1],
			[Rdma-Core Package has verbs ibv_qp_ex defined])
		rc=`grep -o ibv_read_sysfs_file src/rc-compat/v39/driver.h|tail -1`
	;;

	v37)
		AC_MSG_RESULT(yes using v37/v38)
		AC_DEFINE([VERBS_ONLY_QUERY_DEVICE_EX_DEFINED],[1],
			  [Rdma-Core Package has only query_device_ex])
		AC_DEFINE([IBV_CMD_MODIFY_QP_EX_HAS_7_ARG],[1],
			  [Rdma-Core Package ibv_cmd_modify_qp_ex has 7 arguments])
		AC_DEFINE([IBV_FREE_CONTEXT_IN_CONTEXT_OPS],[1],
			  [Rdma-Core Package has free context in ibv_context_ops])
		AC_DEFINE([REG_MR_VERB_HAS_5_ARG],[1],
			  [Rdma-Core Package reg_mr has 5 argument])
		AC_DEFINE([IBV_CMD_ALLOC_MW_HAS_1_ARG],[1],
			  [Rdma-Core Package ibv_cmd_alloc_mw has single argument])
		AC_DEFINE([PROVIDER_DRIVER_HAS_2_ARGS],[1],
			  [Rdma-Core Package PROVIDER_DRIVER macro has 2 arguments])
		AC_DEFINE([ALLOC_CONTEXT_HAS_PRIVATE_DATA],[1],
			  [Rdma-Core Package alloc_context has private data])
		AC_DEFINE([VERBS_MR_DEFINED],[1],
			  [Rdma-Core Package has verbs_mr defined])
		AC_DEFINE([VERBS_INIT_AND_ALLOC_CONTEXT_HAS_5_ARG],[1],
			  [Rdma-Core Package has 5 Arg for verbs_init_and_alloc_context macro])
		AC_DEFINE([RCP_HAS_PROVIDER_DRIVER],[1],
			  [Rdma-Core Package has PROVIDER_DRIVER macro])
		AC_DEFINE([RCP_USE_IB_UVERBS],[1],
			[Rdma-Core Package uses IB user verbs API])
		AC_DEFINE([RCP_USE_ALLOC_CONTEXT],[1],
			[Rdma-Core Package uses alloc_context instead of init_context])
		AC_DEFINE([HAVE_IBV_DMABUF],[1],
			[Rdma-Core Package has verbs ibv_reg_dmabuf_mr defined])
		AC_DEFINE([IBV_CMD_CREATE_QP_EX_HAS_7_ARG],[1],
			  [Rdma-Core Package ibv_cmd_create_qp_ex has 7 arguments])
		AC_DEFINE([HAVE_IBV_WR_API],[1],
			[Rdma-Core Package has verbs ibv_qp_ex defined])
		rc=`grep -o ibv_read_sysfs_file src/rc-compat/v35/driver.h|tail -1`
	;;

	v36)
		AC_MSG_RESULT(yes using v36)
		AC_DEFINE([VERBS_ONLY_QUERY_DEVICE_EX_DEFINED],[1],
			  [Rdma-Core Package has only query_device_ex])
		AC_DEFINE([IBV_CMD_MODIFY_QP_EX_HAS_7_ARG],[1],
			  [Rdma-Core Package ibv_cmd_modify_qp_ex has 7 arguments])
		AC_DEFINE([IBV_FREE_CONTEXT_IN_CONTEXT_OPS],[1],
			  [Rdma-Core Package has free context in ibv_context_ops])
		AC_DEFINE([REG_MR_VERB_HAS_5_ARG],[1],
			  [Rdma-Core Package reg_mr has 5 argument])
		AC_DEFINE([IBV_CMD_ALLOC_MW_HAS_1_ARG],[1],
			  [Rdma-Core Package ibv_cmd_alloc_mw has single argument])
		AC_DEFINE([PROVIDER_DRIVER_HAS_2_ARGS],[1],
			  [Rdma-Core Package PROVIDER_DRIVER macro has 2 arguments])
		AC_DEFINE([ALLOC_CONTEXT_HAS_PRIVATE_DATA],[1],
			  [Rdma-Core Package alloc_context has private data])
		AC_DEFINE([VERBS_MR_DEFINED],[1],
			  [Rdma-Core Package has verbs_mr defined])
		AC_DEFINE([VERBS_INIT_AND_ALLOC_CONTEXT_HAS_5_ARG],[1],
			  [Rdma-Core Package has 5 Arg for verbs_init_and_alloc_context macro])
		AC_DEFINE([RCP_HAS_PROVIDER_DRIVER],[1],
			  [Rdma-Core Package has PROVIDER_DRIVER macro])
		AC_DEFINE([RCP_USE_IB_UVERBS],[1],
			[Rdma-Core Package uses IB user verbs API])
		AC_DEFINE([RCP_USE_ALLOC_CONTEXT],[1],
			[Rdma-Core Package uses alloc_context instead of init_context])
		AC_DEFINE([HAVE_IBV_DMABUF],[1],
			[Rdma-Core Package has verbs ibv_reg_dmabuf_mr defined])
		AC_DEFINE([IBV_CMD_CREATE_QP_EX_HAS_7_ARG],[1],
			  [Rdma-Core Package ibv_cmd_create_qp_ex has 7 arguments])
		AC_DEFINE([HAVE_IBV_WR_API],[1],
			[Rdma-Core Package has verbs ibv_qp_ex defined])
		rc=`grep -o ibv_read_sysfs_file src/rc-compat/v35/driver.h|tail -1`
	;;

	v35)
		AC_MSG_RESULT(yes using v35)
		AC_DEFINE([VERBS_ONLY_QUERY_DEVICE_EX_DEFINED],[1],
			  [Rdma-Core Package has only query_device_ex])
		AC_DEFINE([IBV_CMD_MODIFY_QP_EX_HAS_7_ARG],[1],
			  [Rdma-Core Package ibv_cmd_modify_qp_ex has 7 arguments])
		AC_DEFINE([IBV_FREE_CONTEXT_IN_CONTEXT_OPS],[1],
			  [Rdma-Core Package has free context in ibv_context_ops])
		AC_DEFINE([REG_MR_VERB_HAS_5_ARG],[1],
			  [Rdma-Core Package reg_mr has 5 argument])
		AC_DEFINE([IBV_CMD_ALLOC_MW_HAS_1_ARG],[1],
			  [Rdma-Core Package ibv_cmd_alloc_mw has single argument])
		AC_DEFINE([PROVIDER_DRIVER_HAS_2_ARGS],[1],
			  [Rdma-Core Package PROVIDER_DRIVER macro has 2 arguments])
		AC_DEFINE([ALLOC_CONTEXT_HAS_PRIVATE_DATA],[1],
			  [Rdma-Core Package alloc_context has private data])
		AC_DEFINE([VERBS_MR_DEFINED],[1],
			  [Rdma-Core Package has verbs_mr defined])
		AC_DEFINE([VERBS_INIT_AND_ALLOC_CONTEXT_HAS_5_ARG],[1],
			  [Rdma-Core Package has 5 Arg for verbs_init_and_alloc_context macro])
		AC_DEFINE([RCP_HAS_PROVIDER_DRIVER],[1],
			  [Rdma-Core Package has PROVIDER_DRIVER macro])
		AC_DEFINE([RCP_USE_IB_UVERBS],[1],
			[Rdma-Core Package uses IB user verbs API])
		AC_DEFINE([RCP_USE_ALLOC_CONTEXT],[1],
			[Rdma-Core Package uses alloc_context instead of init_context])
		AC_DEFINE([HAVE_IBV_DMABUF],[1],
			[Rdma-Core Package has verbs ibv_reg_dmabuf_mr defined])
		AC_DEFINE([IBV_CMD_CREATE_QP_EX_HAS_7_ARG],[1],
			  [Rdma-Core Package ibv_cmd_create_qp_ex has 7 arguments])
		AC_DEFINE([HAVE_IBV_WR_API],[1],
			[Rdma-Core Package has verbs ibv_qp_ex defined])
		rc=`grep -o ibv_read_sysfs_file src/rc-compat/v35/driver.h|tail -1`
	;;

	v34)
		AC_MSG_RESULT(yes using v34)
		AC_DEFINE([VERBS_ONLY_QUERY_DEVICE_EX_DEFINED],[1],
			  [Rdma-Core Package has only query_device_ex])
		AC_DEFINE([IBV_CMD_MODIFY_QP_EX_HAS_7_ARG],[1],
			  [Rdma-Core Package ibv_cmd_modify_qp_ex has 7 arguments])
		AC_DEFINE([IBV_FREE_CONTEXT_IN_CONTEXT_OPS],[1],
			  [Rdma-Core Package has free context in ibv_context_ops])
		AC_DEFINE([REG_MR_VERB_HAS_5_ARG],[1],
			  [Rdma-Core Package reg_mr has 5 argument])
		AC_DEFINE([IBV_CMD_ALLOC_MW_HAS_1_ARG],[1],
			  [Rdma-Core Package ibv_cmd_alloc_mw has single argument])
		AC_DEFINE([PROVIDER_DRIVER_HAS_2_ARGS],[1],
			  [Rdma-Core Package PROVIDER_DRIVER macro has 2 arguments])
		AC_DEFINE([ALLOC_CONTEXT_HAS_PRIVATE_DATA],[1],
			  [Rdma-Core Package alloc_context has private data])
		AC_DEFINE([VERBS_MR_DEFINED],[1],
			  [Rdma-Core Package has verbs_mr defined])
		AC_DEFINE([VERBS_INIT_AND_ALLOC_CONTEXT_HAS_5_ARG],[1],
			  [Rdma-Core Package has 5 Arg for verbs_init_and_alloc_context macro])
		AC_DEFINE([RCP_HAS_PROVIDER_DRIVER],[1],
			  [Rdma-Core Package has PROVIDER_DRIVER macro])
		AC_DEFINE([RCP_USE_IB_UVERBS],[1],
			[Rdma-Core Package uses IB user verbs API])
		AC_DEFINE([RCP_USE_ALLOC_CONTEXT],[1],
			[Rdma-Core Package uses alloc_context instead of init_context])
		AC_DEFINE([HAVE_IBV_DMABUF],[1],
			[Rdma-Core Package has verbs ibv_reg_dmabuf_mr defined])
		AC_DEFINE([IBV_CMD_CREATE_QP_EX_HAS_7_ARG],[1],
			  [Rdma-Core Package ibv_cmd_create_qp_ex has 7 arguments])
		AC_DEFINE([HAVE_IBV_WR_API],[1],
			[Rdma-Core Package has verbs ibv_qp_ex defined])
		rc=`grep -o ibv_read_sysfs_file src/rc-compat/v34/driver.h|tail -1`
	;;
	v33)
		AC_MSG_RESULT(yes using v33)
		AC_DEFINE([VERBS_ONLY_QUERY_DEVICE_EX_DEFINED],[1],
			  [Rdma-Core Package has only query_device_ex])
		AC_DEFINE([IBV_CMD_MODIFY_QP_EX_HAS_7_ARG],[1],
			  [Rdma-Core Package ibv_cmd_modify_qp_ex has 7 arguments])
		AC_DEFINE([IBV_FREE_CONTEXT_IN_CONTEXT_OPS],[1],
			  [Rdma-Core Package has free context in ibv_context_ops])
		AC_DEFINE([REG_MR_VERB_HAS_5_ARG],[1],
			  [Rdma-Core Package reg_mr has 5 argument])
		AC_DEFINE([IBV_CMD_ALLOC_MW_HAS_1_ARG],[1],
			  [Rdma-Core Package ibv_cmd_alloc_mw has single argument])
		AC_DEFINE([PROVIDER_DRIVER_HAS_2_ARGS],[1],
			  [Rdma-Core Package PROVIDER_DRIVER macro has 2 arguments])
		AC_DEFINE([ALLOC_CONTEXT_HAS_PRIVATE_DATA],[1],
			  [Rdma-Core Package alloc_context has private data])
		AC_DEFINE([VERBS_MR_DEFINED],[1],
			  [Rdma-Core Package has verbs_mr defined])
		AC_DEFINE([VERBS_INIT_AND_ALLOC_CONTEXT_HAS_5_ARG],[1],
			  [Rdma-Core Package has 5 Arg for verbs_init_and_alloc_context macro])
		AC_DEFINE([RCP_HAS_PROVIDER_DRIVER],[1],
			  [Rdma-Core Package has PROVIDER_DRIVER macro])
		AC_DEFINE([RCP_USE_IB_UVERBS],[1],
			[Rdma-Core Package uses IB user verbs API])
		AC_DEFINE([RCP_USE_ALLOC_CONTEXT],[1],
			[Rdma-Core Package uses alloc_context instead of init_context])
		AC_DEFINE([IBV_CMD_CREATE_QP_EX_HAS_7_ARG],[1],
			  [Rdma-Core Package ibv_cmd_create_qp_ex has 7 arguments])
		AC_DEFINE([HAVE_IBV_WR_API],[1],
			[Rdma-Core Package has verbs ibv_qp_ex defined])
		rc=`grep -o ibv_read_sysfs_file src/rc-compat/v22/driver.h|tail -1`
	;;
	v32)
		AC_MSG_RESULT(yes using v32)
		AC_DEFINE([IBV_CMD_MODIFY_QP_EX_HAS_7_ARG],[1],
			  [Rdma-Core Package ibv_cmd_modify_qp_ex has 7 arguments])
		AC_DEFINE([IBV_FREE_CONTEXT_IN_CONTEXT_OPS],[1],
			  [Rdma-Core Package has free context in ibv_context_ops])
		AC_DEFINE([REG_MR_VERB_HAS_5_ARG],[1],
			  [Rdma-Core Package reg_mr has 5 argument])
		AC_DEFINE([IBV_CMD_ALLOC_MW_HAS_1_ARG],[1],
			  [Rdma-Core Package ibv_cmd_alloc_mw has single argument])
		AC_DEFINE([PROVIDER_DRIVER_HAS_2_ARGS],[1],
			  [Rdma-Core Package PROVIDER_DRIVER macro has 2 arguments])
		AC_DEFINE([ALLOC_CONTEXT_HAS_PRIVATE_DATA],[1],
			  [Rdma-Core Package alloc_context has private data])
		AC_DEFINE([VERBS_MR_DEFINED],[1],
			  [Rdma-Core Package has verbs_mr defined])
		AC_DEFINE([VERBS_INIT_AND_ALLOC_CONTEXT_HAS_5_ARG],[1],
			  [Rdma-Core Package has 5 Arg for verbs_init_and_alloc_context macro])
		AC_DEFINE([RCP_HAS_PROVIDER_DRIVER],[1],
			  [Rdma-Core Package has PROVIDER_DRIVER macro])
		AC_DEFINE([RCP_USE_IB_UVERBS],[1],
			[Rdma-Core Package uses IB user verbs API])
		AC_DEFINE([RCP_USE_ALLOC_CONTEXT],[1],
			[Rdma-Core Package uses alloc_context instead of init_context])
		AC_DEFINE([IBV_CMD_CREATE_QP_EX_HAS_7_ARG],[1],
			  [Rdma-Core Package ibv_cmd_create_qp_ex has 7 arguments])
		AC_DEFINE([HAVE_IBV_WR_API],[1],
			[Rdma-Core Package has verbs ibv_qp_ex defined])
		rc=`grep -o ibv_read_sysfs_file src/rc-compat/v22/driver.h|tail -1`
	;;

	v31)
		AC_MSG_RESULT(yes using v31)
		AC_DEFINE([IBV_CMD_MODIFY_QP_EX_HAS_7_ARG],[1],
			  [Rdma-Core Package ibv_cmd_modify_qp_ex has 7 arguments])
		AC_DEFINE([IBV_FREE_CONTEXT_IN_CONTEXT_OPS],[1],
			  [Rdma-Core Package has free context in ibv_context_ops])
		AC_DEFINE([REG_MR_VERB_HAS_5_ARG],[1],
			  [Rdma-Core Package reg_mr has 5 argument])
		AC_DEFINE([IBV_CMD_ALLOC_MW_HAS_1_ARG],[1],
			  [Rdma-Core Package ibv_cmd_alloc_mw has single argument])
		AC_DEFINE([PROVIDER_DRIVER_HAS_2_ARGS],[1],
			  [Rdma-Core Package PROVIDER_DRIVER macro has 2 arguments])
		AC_DEFINE([ALLOC_CONTEXT_HAS_PRIVATE_DATA],[1],
			  [Rdma-Core Package alloc_context has private data])
		AC_DEFINE([VERBS_MR_DEFINED],[1],
			  [Rdma-Core Package has verbs_mr defined])
		AC_DEFINE([VERBS_INIT_AND_ALLOC_CONTEXT_HAS_5_ARG],[1],
			  [Rdma-Core Package has 5 Arg for verbs_init_and_alloc_context macro])
		AC_DEFINE([RCP_HAS_PROVIDER_DRIVER],[1],
			  [Rdma-Core Package has PROVIDER_DRIVER macro])
		AC_DEFINE([RCP_USE_IB_UVERBS],[1],
			[Rdma-Core Package uses IB user verbs API])
		AC_DEFINE([RCP_USE_ALLOC_CONTEXT],[1],
			[Rdma-Core Package uses alloc_context instead of init_context])
		AC_DEFINE([IBV_CMD_CREATE_QP_EX_HAS_7_ARG],[1],
			  [Rdma-Core Package ibv_cmd_create_qp_ex has 7 arguments])
		AC_DEFINE([HAVE_IBV_WR_API],[1],
			[Rdma-Core Package has verbs ibv_qp_ex defined])
		rc=`grep -o ibv_read_sysfs_file src/rc-compat/v22/driver.h|tail -1`
	;;


	v29)
		AC_MSG_RESULT(yes using v29)
		AC_DEFINE([IBV_CMD_MODIFY_QP_EX_HAS_7_ARG],[1],
			  [Rdma-Core Package ibv_cmd_modify_qp_ex has 7 arguments])
		AC_DEFINE([IBV_FREE_CONTEXT_IN_CONTEXT_OPS],[1],
			  [Rdma-Core Package has free context in ibv_context_ops])
		AC_DEFINE([REG_MR_VERB_HAS_5_ARG],[1],
			  [Rdma-Core Package reg_mr has 5 argument])
		AC_DEFINE([IBV_CMD_ALLOC_MW_HAS_1_ARG],[1],
			  [Rdma-Core Package ibv_cmd_alloc_mw has single argument])
		AC_DEFINE([PROVIDER_DRIVER_HAS_2_ARGS],[1],
			  [Rdma-Core Package PROVIDER_DRIVER macro has 2 arguments])
		AC_DEFINE([ALLOC_CONTEXT_HAS_PRIVATE_DATA],[1],
			  [Rdma-Core Package alloc_context has private data])
		AC_DEFINE([VERBS_MR_DEFINED],[1],
			  [Rdma-Core Package has verbs_mr defined])
		AC_DEFINE([VERBS_INIT_AND_ALLOC_CONTEXT_HAS_5_ARG],[1],
			  [Rdma-Core Package has 5 Arg for verbs_init_and_alloc_context macro])
		AC_DEFINE([RCP_HAS_PROVIDER_DRIVER],[1],
			  [Rdma-Core Package has PROVIDER_DRIVER macro])
		AC_DEFINE([RCP_USE_IB_UVERBS],[1],
			[Rdma-Core Package uses IB user verbs API])
		AC_DEFINE([RCP_USE_ALLOC_CONTEXT],[1],
			[Rdma-Core Package uses alloc_context instead of init_context])
		AC_DEFINE([HAVE_IBV_WR_API],[1],
			[Rdma-Core Package has verbs ibv_qp_ex defined])
		rc=`grep -o ibv_read_sysfs_file src/rc-compat/v22/driver.h|tail -1`
	;;

	v28)
		AC_MSG_RESULT(yes using v28)
		AC_DEFINE([IBV_CMD_MODIFY_QP_EX_HAS_7_ARG],[1],
			  [Rdma-Core Package ibv_cmd_modify_qp_ex has 7 arguments])
		AC_DEFINE([IBV_FREE_CONTEXT_IN_CONTEXT_OPS],[1],
			  [Rdma-Core Package has free context in ibv_context_ops])
		AC_DEFINE([REG_MR_VERB_HAS_5_ARG],[1],
			  [Rdma-Core Package reg_mr has 5 argument])
		AC_DEFINE([IBV_CMD_ALLOC_MW_HAS_1_ARG],[1],
			  [Rdma-Core Package ibv_cmd_alloc_mw has single argument])
		AC_DEFINE([PROVIDER_DRIVER_HAS_2_ARGS],[1],
			  [Rdma-Core Package PROVIDER_DRIVER macro has 2 arguments])
		AC_DEFINE([ALLOC_CONTEXT_HAS_PRIVATE_DATA],[1],
			  [Rdma-Core Package alloc_context has private data])
		AC_DEFINE([VERBS_MR_DEFINED],[1],
			  [Rdma-Core Package has verbs_mr defined])
		AC_DEFINE([VERBS_INIT_AND_ALLOC_CONTEXT_HAS_5_ARG],[1],
			  [Rdma-Core Package has 5 Arg for verbs_init_and_alloc_context macro])
		AC_DEFINE([RCP_HAS_PROVIDER_DRIVER],[1],
			  [Rdma-Core Package has PROVIDER_DRIVER macro])
		AC_DEFINE([RCP_USE_IB_UVERBS],[1],
			[Rdma-Core Package uses IB user verbs API])
		AC_DEFINE([RCP_USE_ALLOC_CONTEXT],[1],
			[Rdma-Core Package uses alloc_context instead of init_context])
		AC_DEFINE([HAVE_IBV_WR_API],[1],
			[Rdma-Core Package has verbs ibv_qp_ex defined])
		rc=`grep -o ibv_read_sysfs_file src/rc-compat/v22/driver.h|tail -1`
	;;

	v25)
		AC_MSG_RESULT(yes using v25)
		AC_DEFINE([IBV_CMD_MODIFY_QP_EX_HAS_7_ARG],[1],
			  [Rdma-Core Package ibv_cmd_modify_qp_ex has 7 arguments])
		AC_DEFINE([REG_MR_VERB_HAS_5_ARG],[1],
			  [Rdma-Core Package reg_mr has 5 argument])
		AC_DEFINE([IBV_CMD_ALLOC_MW_HAS_1_ARG],[1],
			  [Rdma-Core Package ibv_cmd_alloc_mw has single argument])
		AC_DEFINE([PROVIDER_DRIVER_HAS_2_ARGS],[1],
			  [Rdma-Core Package PROVIDER_DRIVER macro has 2 arguments])
		AC_DEFINE([ALLOC_CONTEXT_HAS_PRIVATE_DATA],[1],
			  [Rdma-Core Package alloc_context has private data])
		AC_DEFINE([VERBS_MR_DEFINED],[1],
			  [Rdma-Core Package has verbs_mr defined])
		AC_DEFINE([VERBS_INIT_AND_ALLOC_CONTEXT_HAS_5_ARG],[1],
			  [Rdma-Core Package has 5 Arg for verbs_init_and_alloc_context macro])
		AC_DEFINE([RCP_HAS_PROVIDER_DRIVER],[1],
			  [Rdma-Core Package has PROVIDER_DRIVER macro])
		AC_DEFINE([RCP_USE_IB_UVERBS],[1],
			[Rdma-Core Package uses IB user verbs API])
		AC_DEFINE([RCP_USE_ALLOC_CONTEXT],[1],
			[Rdma-Core Package uses alloc_context instead of init_context])
		AC_DEFINE([HAVE_IBV_WR_API],[1],
			[Rdma-Core Package has verbs ibv_qp_ex defined])
		rc=`grep -o ibv_read_sysfs_file src/rc-compat/v22/driver.h|tail -1`
	;;
	v24)
		AC_MSG_RESULT(yes using v24)
		AC_DEFINE([IBV_CMD_MODIFY_QP_EX_HAS_7_ARG],[1],
			  [Rdma-Core Package ibv_cmd_modify_qp_ex has 7 arguments])
		AC_DEFINE([IBV_CMD_ALLOC_MW_HAS_1_ARG],[1],
			  [Rdma-Core Package ibv_cmd_alloc_mw has single argument])
		AC_DEFINE([PROVIDER_DRIVER_HAS_2_ARGS],[1],
			  [Rdma-Core Package PROVIDER_DRIVER macro has 2 arguments])
		AC_DEFINE([ALLOC_CONTEXT_HAS_PRIVATE_DATA],[1],
			  [Rdma-Core Package alloc_context has private data])
		AC_DEFINE([VERBS_MR_DEFINED],[1],
			  [Rdma-Core Package has verbs_mr defined])
		AC_DEFINE([VERBS_INIT_AND_ALLOC_CONTEXT_HAS_5_ARG],[1],
			  [Rdma-Core Package has 5 Arg for verbs_init_and_alloc_context macro])
		AC_DEFINE([RCP_HAS_PROVIDER_DRIVER],[1],
			  [Rdma-Core Package has PROVIDER_DRIVER macro])
		AC_DEFINE([RCP_USE_IB_UVERBS],[1],
			[Rdma-Core Package uses IB user verbs API])
		AC_DEFINE([RCP_USE_ALLOC_CONTEXT],[1],
			[Rdma-Core Package uses alloc_context instead of init_context])
		AC_DEFINE([HAVE_IBV_WR_API],[1],
			[Rdma-Core Package has verbs ibv_qp_ex defined])
		rc=`grep -o ibv_read_sysfs_file src/rc-compat/v22/driver.h|tail -1`
	;;
	v22)
		AC_MSG_RESULT(yes using v22)
		AC_DEFINE([IBV_CMD_MODIFY_QP_EX_HAS_7_ARG],[1],
			  [Rdma-Core Package ibv_cmd_modify_qp_ex has 7 arguments])
		AC_DEFINE([IBV_CMD_ALLOC_MW_HAS_1_ARG],[1],
			  [Rdma-Core Package ibv_cmd_alloc_mw has single argument])
		AC_DEFINE([PROVIDER_DRIVER_HAS_2_ARGS],[1],
			  [Rdma-Core Package PROVIDER_DRIVER macro has 2 arguments])
		AC_DEFINE([ALLOC_CONTEXT_HAS_PRIVATE_DATA],[1],
			  [Rdma-Core Package alloc_context has private data])
		AC_DEFINE([VERBS_MR_DEFINED],[1],
			  [Rdma-Core Package has verbs_mr defined])
		AC_DEFINE([VERBS_INIT_AND_ALLOC_CONTEXT_HAS_5_ARG],[1],
			  [Rdma-Core Package has 5 Arg for verbs_init_and_alloc_context macro])
		AC_DEFINE([RCP_HAS_PROVIDER_DRIVER],[1],
			  [Rdma-Core Package has PROVIDER_DRIVER macro])
		AC_DEFINE([RCP_USE_IB_UVERBS],[1],
			[Rdma-Core Package uses IB user verbs API])
		AC_DEFINE([RCP_USE_ALLOC_CONTEXT],[1],
			[Rdma-Core Package uses alloc_context instead of init_context])
		AC_DEFINE([ASYNC_EVENT_VERB_HAS_1_ARG],[1],
			  [Rdma-Core Package async_event has 1 argument])
		rc=`grep -o ibv_read_sysfs_file src/rc-compat/v22/driver.h|tail -1`
	;;
	v19)
		AC_MSG_RESULT(yes using v19)
		AC_DEFINE([IBV_CMD_MODIFY_QP_EX_HAS_9_ARG],[1],
			  [Rdma-Core Package ibv_cmd_modify_qp_ex has 9 arguments])
		AC_DEFINE([VERBS_INIT_AND_ALLOC_CONTEXT_HAS_5_ARG],[1],
			  [Rdma-Core Package has 5 Arg for verbs_init_and_alloc_context macro])
		AC_DEFINE([RCP_HAS_PROVIDER_DRIVER],[1],
			  [Rdma-Core Package has PROVIDER_DRIVER macro])
		AC_DEFINE([RCP_USE_IB_UVERBS],[1],
			[Rdma-Core Package uses IB user verbs API])
		AC_DEFINE([RCP_USE_ALLOC_CONTEXT],[1],
			[Rdma-Core Package uses alloc_context instead of init_context])
		AC_DEFINE([ASYNC_EVENT_VERB_HAS_1_ARG],[1],
			  [Rdma-Core Package async_event has 1 argument])
		rc=`grep -o ibv_read_sysfs_file src/rc-compat/v19/driver.h|tail -1`
	;;
	v17)
		dnl rdma-core 17
		AC_MSG_RESULT(yes using v17)
		AC_DEFINE([IBV_CMD_MODIFY_QP_EX_HAS_9_ARG],[1],
			  [Rdma-Core Package ibv_cmd_modify_qp_ex has 9 arguments])
		AC_DEFINE([RCP_HAS_PROVIDER_DRIVER],[1],
			  [Rdma-Core Package has PROVIDER_DRIVER macro])
		AC_DEFINE([RCP_USE_IB_UVERBS],[1],
			[Rdma-Core Package uses IB user verbs API])
		AC_DEFINE([RCP_USE_ALLOC_CONTEXT],[1],
			[Rdma-Core Package uses alloc_context instead of init_context])
		AC_DEFINE([ASYNC_EVENT_VERB_HAS_1_ARG],[1],
			  [Rdma-Core Package async_event has 1 argument])
		rc=`grep -o ibv_read_sysfs_file src/rc-compat/v17/driver.h|tail -1`
	;;
	v16)
		dnl rdma-core 16
		AC_MSG_RESULT(yes using v16)
		AC_DEFINE([IBV_CMD_MODIFY_QP_EX_HAS_9_ARG],[1],
			  [Rdma-Core Package ibv_cmd_modify_qp_ex has 9 arguments])
		AC_DEFINE([RCP_HAS_PROVIDER_DRIVER],[1],
				[Rdma-Core Package has PROVIDER_DRIVER macro])
		AC_DEFINE([ASYNC_EVENT_VERB_HAS_1_ARG],[1],
			  [Rdma-Core Package async_event has 1 argument])
		rc=`grep -o ibv_read_sysfs_file src/rc-compat/v16/driver.h|tail -1`
	;;
	v15)
		dnl rdma-core 15
		AC_MSG_RESULT(yes using v15)
		AC_DEFINE([IBV_CMD_MODIFY_QP_EX_HAS_9_ARG],[1],
			  [Rdma-Core Package ibv_cmd_modify_qp_ex has 9 arguments])
		AC_DEFINE([ASYNC_EVENT_VERB_HAS_1_ARG],[1],
			  [Rdma-Core Package async_event has 1 argument])
		rc=`grep -o ibv_read_sysfs_file src/rc-compat/v15/driver.h|tail -1`
	;;
	*)
		dnl rdma-core 14 or lower
		AC_MSG_RESULT(yes using v14 or lower)
		AC_DEFINE([IBV_CMD_MODIFY_QP_EX_HAS_9_ARG],[1],
			  [Rdma-Core Package ibv_cmd_modify_qp_ex has 9 arguments])
		AC_DEFINE([ASYNC_EVENT_VERB_HAS_1_ARG],[1],
			  [Rdma-Core Package async_event has 1 argument])
		rc=`grep -o ibv_read_sysfs_file src/rc-compat/v14/driver.h|tail -1`
	;;
	esac
	if test "$rc" = ""; then
		AC_MSG_ERROR([ibv_read_sysfs_file() not found. Check driver.h])
	fi
else
	AC_MSG_RESULT(no)
	dnl Checks for library functions
	AC_CHECK_FUNCS(ibv_read_sysfs_file ibv_register_driver)
fi

AC_SUBST(RDMA_CORE_HEADERS)
AC_CHECK_HEADERS([rdma/ib_user_ioctl_cmds.h], [
    AC_DEFINE([IB_USER_IOCTL_CMDS], [1],
	      [Define if ib_user_ioctl_cmds.h file])
])
AC_CHECK_HEADERS([inttypes.h locale.h stddef.h stdint.h])
dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST

dnl Check for libibverbs device library extension
dummy=if$$
cat <<IBV_VERSION > $dummy.c
__include_string__
IBV_DEVICE_LIBRARY_EXTENSION
IBV_VERSION
IBV_DEVICE_LIBRARY_EXTENSION=$($CC $CPPFLAGS -E $dummy.c $(echo -n __include_path__) 2> /dev/null | tail -1)
rm -f $dummy.c
if test $IBV_DEVICE_LIBRARY_EXTENSION = IBV_DEVICE_LIBRARY_EXTENSION; then
	AC_MSG_ERROR([IBV_DEVICE_LIBRARY_EXTENSION not defined.  Is libibverbs new enough?])
fi
AC_SUBST(IBV_DEVICE_LIBRARY_EXTENSION)

AC_MSG_CHECKING([for new definition of struct ibv_send_wr])
dummy=if$$
cat << WR_MW_BIND > $dummy.c
#include <infiniband/verbs.h>
struct ibv_send_wr wr = {
        .bind_mw.rkey = 0
        };
WR_MW_BIND
BIND_RESULT=`$CC $CPPFLAGS -c $dummy.c 2> /dev/null`
if test -f $dummy.o; then
    AC_MSG_RESULT(yes)
    AC_DEFINE([HAVE_WR_BIND_MW],[1],[ibv_send_wr has bind_mw member])
else
    AC_MSG_RESULT(no)
fi
rm -f $dummy.*

AC_MSG_CHECKING([for send-with-invalidate opcode support])
dummy=if$$
cat << SEND_W_INV > $dummy.c
#include <infiniband/verbs.h>
struct ibv_send_wr wr = {
	.opcode = IBV_WR_SEND_WITH_INV
	};
SEND_W_INV
INVAL_RESULT=`$CC $CPPFLAGS -c $dummy.c 2> /dev/null`
if test -f $dummy.o; then
    AC_MSG_RESULT(yes)
    AC_DEFINE([HAVE_SEND_WITH_INV],[1],[send-with-invalidate supported])
else
    AC_MSG_RESULT(no)
fi
rm -f $dummy.*

AC_MSG_CHECKING([for local-invalidate opcode support])
dummy=if$$
cat << LOCAL_INVAL > $dummy.c
#include <infiniband/verbs.h>
struct ibv_send_wr wr = {
	.opcode = IBV_WR_LOCAL_INV
	};
LOCAL_INVAL
LINVAL_RESULT=`$CC $CPPFLAGS -c $dummy.c 2> /dev/null`
if test -f $dummy.o; then
    AC_MSG_RESULT(yes)
    AC_DEFINE([HAVE_LOCAL_INV],[1],[local-invalidate supported])
else
    AC_MSG_RESULT(no)
fi
rm $dummy.*

AC_MSG_CHECKING([check for ib_uverbs_flow_spec_action_handle defined])
dummy=if$$
cat << FLOW_SPEC > $dummy.c
#include <rdma/ib_user_verbs.h>
struct ib_uverbs_flow_spec_action_handle hand = {
	.handle = 0
};
FLOW_SPEC
FLOW_SPEC_RESULT=`$CC $CPPFLAGS -c $dummy.c 2> /dev/null`
if test -f $dummy.o; then
    AC_MSG_RESULT(yes)
    AC_DEFINE([HAVE_FLOW_SPEC],[1],[flow spec structs defined])
else
    AC_MSG_RESULT(no)
fi
rm $dummy.*

cat << RDMA_DRIVER_ID > $dummy.c
#include <infiniband/ib_user_ioctl_verbs.h>
unsigned int en_val = RDMA_DRIVER_BNXT_RE;
RDMA_DRIVER_ID
RDMA_DRIVER_ID_RESULT=`$CC $CPPFLAGS -c $dummy.c 2> /dev/null`
if test -f $dummy.o; then
    AC_MSG_RESULT(yes)
    AC_DEFINE([HAVE_RDMA_DRIVER_ID],[1],[rdma_driver_id in ib_user_ioctl_verbs.h defined])
else
    AC_MSG_RESULT(no)
fi
rm $dummy.*

AC_MSG_CHECKING([check if ib_uverbs_cq_moderation is defined])
dummy=if$$
cat << UVERBS_CQ_MODERATION_ST > $dummy.c
#include <rdma/ib_user_verbs.h>
struct  ib_uverbs_cq_moderation cq_mod;
UVERBS_CQ_MODERATION_ST
UVERBS_CQ_MODERATION_ST_RESULT=`$CC $CPPFLAGS -c $dummy.c 2> /dev/null`
if test -f $dummy.o; then
    AC_MSG_RESULT(yes)
    AC_DEFINE([HAVE_UVERBS_CQ_MOD_ST],[1],[ib_uverbs_cq_moderation defined])
else
    AC_MSG_RESULT(no)
fi
rm $dummy.*

AC_MSG_CHECKING([check if ib_uverbs_ex_modify_cq is defined])
dummy=if$$
cat << UVERBS_EX_MODIFY_CQ_ST > $dummy.c
#include <rdma/ib_user_verbs.h>
struct  ib_uverbs_ex_modify_cq ex_mod;
UVERBS_EX_MODIFY_CQ_ST
UVERBS_EX_MODIFY_CQ_ST_RESULT=`$CC $CPPFLAGS -c $dummy.c 2> /dev/null`
if test -f $dummy.o; then
    AC_MSG_RESULT(yes)
    AC_DEFINE([HAVE_UVERBS_EX_MODIFY_CQ_ST],[1],[ib_uverbs_ex_modify_cq defined])
else
    AC_MSG_RESULT(no)
fi
rm $dummy.*

AC_MSG_CHECKING([for sched_yield defined])
rc=$(grep -o sched_yield /usr/include/sched.h | tail -1)
if test ! -z "$rc"; then
    AC_MSG_RESULT(yes)
    AC_DEFINE([SCHED_YIELD_DEFINED],[1],[sched_yield defined])
else
    AC_MSG_RESULT(no)
fi

AC_MSG_CHECKING([for disabling data path spin lock])
if test "$disable_dplock" = "yes"; then
    AC_MSG_RESULT(yes)
    AC_DEFINE([BNXT_RE_DISABLE_DP_SPINLOCK],[1],[DP spinlock disabled])
else
    AC_MSG_RESULT(no)
fi

AC_MSG_CHECKING([for enabling deferred arming logic])
if test "$enable_defarm" = "yes"; then
    AC_MSG_RESULT(yes)
    AC_DEFINE([BNXT_RE_ENABLE_DEF_ARM],[1],[deferred arm enabled])
else
    AC_MSG_RESULT(no)
fi

AC_MSG_CHECKING([for enabling deferred db logic])
if test "$enable_deferdb" = "yes"; then
    AC_MSG_RESULT(yes)
    AC_DEFINE([BNXT_RE_ENABLE_DEFFER_DB],[1],[deferred db enabled])
else
    AC_MSG_RESULT(no)
fi

AC_MSG_CHECKING([for enabling dev debug logic])
if test "$enable_dev_debug" = "yes"; then
    AC_MSG_RESULT(yes)
    AC_DEFINE([BNXT_RE_ENABLE_DEV_DEBUG],[1],[dev debug enabled])
else
    AC_MSG_RESULT(no)
fi

AC_MSG_CHECKING([for compile time macro definitions])
AC_MSG_RESULT(yes)
AC_DEFINE([HAVE_J8916_ENABLED],[1],[have eng-8916 definition])

# The doorbell lock is required on 32-bit platforms. On 64-bit platforms ringing
# the db is atomic.
AC_CHECK_SIZEOF([long])
AS_IF([test "$ac_cv_sizeof_long" -eq 4],
    [AC_DEFINE([BNXT_RE_HAVE_DB_LOCK], 1, [32-bit platform detected])],
    [])

AC_MSG_CHECKING([for $DRVFILENAME.driver file])
cat << BNXT_DRIVER > $DRVFILENAME.driver
driver $(echo -n libname_postfix)
BNXT_DRIVER
if test -f $DRVFILENAME.driver; then
        AC_MSG_RESULT(yes)
        AC_SUBST(DRVFILENAME)
else
        AC_MSG_RESULT(no)
fi

AC_CACHE_CHECK(whether ld accepts --version-script, ac_cv_version_script,
    if test -n "`$LD --help < /dev/null 2>/dev/null | grep version-script`"; then
        ac_cv_version_script=yes
    else
        ac_cv_version_script=no
    fi)

AM_CONDITIONAL(HAVE_LD_VERSION_SCRIPT, test "$ac_cv_version_script" = "yes")
AM_CONDITIONAL(FMODEL, test "$FMODEL" = "1")
AM_CONDITIONAL([HAVE_ROCELIB_TEST_SUITE], [test "$enable_dev_debug" = "yes"])
AC_CONFIG_FILES([Makefile libbnxt.spec])
AC_OUTPUT
