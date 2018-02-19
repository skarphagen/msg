AC_INIT([msg],
        [1.0.0],
        [skarphagen.embedded@gmail.com])

AC_CONFIG_AUX_DIR(config)
AC_CONFIG_MACRO_DIR(m4)
AM_INIT_AUTOMAKE()

# Checks for programs.
AC_PROG_CC_C99
AC_PROG_CPP
AM_PROG_AR

# Use the C language and compiler for the following checks
AC_LANG([C])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

AC_ARG_ENABLE([msg-lttng],AS_HELP_STRING(
	[--enable-msg-lttng],[enable msg lttng]))

AS_IF([test "x$enable_msg_lttng" == "xyes"],
	[CFLAGS=-DMSG_LTTNG_ENABLED]
      	[AC_SUBST(MSG_LTTNG_LIBS, -llttng-ust)])

AC_CONFIG_FILES([
	 Makefile
         include/Makefile
         src/Makefile
         cli/Makefile
	 ])

LT_INIT

AC_OUTPUT
