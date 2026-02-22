# Makefile for the fdupes program.
#
# fdupes is a command line program calculate X!
#

PLATFORM := $(shell uname)

PKG_CONFIG := pkg-config

INSTALL_DIR := ~/bin

ifeq ($(PLATFORM), Darwin)
    CPP := clang++
else
    CPP := g++
endif

CPP_FLAGS  = -c -Wall -pedantic --std=c++17
CPP_FLAGS += $(shell $(PKG_CONFIG) --cflags openssl)    \
             $(shell $(PKG_CONFIG) --cflags gmp)        \
             $(shell $(PKG_CONFIG) --cflags gmpxx)

LFLAGS     = $(shell $(PKG_CONFIG) --libs openssl)      \
             $(shell $(PKG_CONFIG) --libs gmpxx)

ifdef DEBUG
    CPP_FLAGS += -g3 -O0 -DDEBUG -D_DEBUG
    OBJDIR := $(PLATFORM)_objd
else
    CPP_FLAGS += -O3 -DNDEBUG -DRELEASE
    OBJDIR := $(PLATFORM)_objn
endif

ifeq ($(PLATFORM),Linux)
    CPP_FLAGS += -DLINUX -D_LINUX -D__LINUX__
endif

.DEFAULT : all

all : $(OBJDIR)/fdupes

.PHONY : clean doc

dep : $(DEP_FILES)

-include $(OBJ_FILES:.o=.d)

CPP_SRC_FILES := fdupes.cpp

OBJ_LIST := $(CPP_SRC_FILES:.cpp=.o) $(C_SRC_FILES:.c=.o)
OBJ_FILES := $(addprefix $(OBJDIR)/, $(OBJ_LIST))
DEP_FILES := $(OBJ_FILES:.o=.d)

$(OBJDIR)/fdupes : $(OBJ_FILES) makefile
	@if [ ! -d $(@D) ] ; then mkdir -p $(@D) ; fi
	$(CPP) -o $@ $(OBJ_FILES) $(LFLAGS)
ifndef DEBUG
	strip $(OBJDIR)/fdupes
endif

$(OBJDIR)/%.o : %.cpp makefile $(OBJDIR)/%.d
	@if [ ! -d $(@D) ] ; then mkdir -p $(@D) ; fi
	$(CPP) $(CPP_FLAGS) -o $@ $<

$(OBJDIR)/%.d : %.cpp makefile
	@if [ ! -d $(@D) ] ; then mkdir -p $(@D) ; fi
	@echo "Generating dependencies for $<"
	$(CPP) $(CPP_FLAGS) -MM -MT $@ $< > $(@:.o=.d)

clean:
	rm -rf $(PLATFORM)_obj[dn] doc build build-debug

install: $(OBJDIR)/fdupes
	@mkdir -p $(INSTALL_DIR)
	cp $(OBJDIR)/fdupes $(INSTALL_DIR)

doc:
	rm -rf doc
	doxygen doxy.cfg


