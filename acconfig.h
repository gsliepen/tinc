/* Define to the name name of this package */
#undef PACKAGE

/* Define to the version of the package */
#undef VERSION

/* Define to rpl_malloc if the replacement function should be used.  */
#undef malloc

/* Define to rpl_realloc if the replacement function should be used.  */
#undef realloc

/* This is always defined.  It enables GNU extensions on systems that
   have them.  */
#if !defined(_GNU_SOURCE)
# undef _GNU_SOURCE
#endif

#if !defined(__USE_BSD)
# undef __USE_BSD
#endif

#undef HAVE_NAMESPACES
#undef HAVE_STL
