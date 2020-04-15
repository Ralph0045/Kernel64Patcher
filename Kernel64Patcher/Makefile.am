AM_CFLAGS = $(GLOBAL_CFLAGS) $(libgeneral_CFLAGS) $(liboffsetfinder64_CFLAGS)
AM_CXXFLAGS = $(AM_CFLAGS) $(GLOBAL_CXXFLAGS)
AM_LDFLAGS = $(libgeneral_LIBS) $(liboffsetfinder64_LIBS)

bin_PROGRAMS = Kernel64Patcher

Kernel64Patcher_CFLAGS = $(AM_CFLAGS)
Kernel64Patcher_CXXFLAGS = $(AM_CXXFLAGS)
Kernel64Patcher_LDFLAGS = $(AM_LDFLAGS)
Kernel64Patcher_SOURCES = 	main.cpp
