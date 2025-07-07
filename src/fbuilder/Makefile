.SUFFIXES:
ROOT = ../..
-include $(ROOT)/config.mk

MOD = fbuilder
MOD_DIR = $(ROOT)/src/$(MOD)
PROG = $(MOD_DIR)/$(MOD)
TARGET = $(PROG)
LIBS = ../../src/fbuilder_rs/target/debug/libfbuilder_rs.a 

include $(ROOT)/src/prog.mk
