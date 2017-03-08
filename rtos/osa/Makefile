#-----------------------------------------------------------------------
# include system enviroment header file
#-----------------------------------------------------------------------
DISP_TOP   = $(shell pwd -P | sed "s/.*\/rtos/./g" | sed "s/\/[A-Za-z0-9+._ -]*/\/../g")/..

BUILD_DIR         = $(DISP_TOP)/build

INSTALL_DIR       = $(DISP_TOP)/Install/Core
LIB_INSTALL_DIR   = $(INSTALL_DIR)/Lib
INC_INSTALL_DIR   = $(INSTALL_DIR)/Inc/rtos

include $(DISP_TOP)/Install/Core/Rule.mk


#-----------------------------------------------------------------------
# moudule name
#-----------------------------------------------------------------------
BUILD_TYPE	   = a
TARGET		   = libosa.a

# Define Global Data
DEFINE    = 

# Files Dir to build
FILES_DIR = ./Src 


# Files to build
SRCS :=  $(wildcard $(addsuffix /*.c, $(FILES_DIR)))
# Files to exclude
FILES2EXCLUDE  = 
SRCS          := $(filter-out $(FILES2EXCLUDE), $(SRCS))
OBJS           = $(addprefix ./OBJS/, $(patsubst %.c, %.o, $(notdir $(SRCS))))

# ASM Files to build
ASM_SRCS := $(wildcard $(addsuffix /*.S, $(FILES_DIR)))
# ASM Files to exclude
FILES2EXCLUDE  = 
ASM_SRCS      := $(filter-out $(FILES2EXCLUDE), $(ASM_SRCS))
OBJS          += $(addprefix ./OBJS/, $(patsubst %.S, %.o, $(notdir $(ASM_SRCS))))


# Include INC folder
INC = 	./Inc $(FILES_DIR) \
		$(DISP_TOP)/include \
		$(DISP_TOP)/rtos/threadx/Inc \
		

CFLAGS += -O4 -Werror $(addprefix -I, $(INC)) $(DEFINE)
ASFLAGS += $(addprefix -I, $(INC)) $(DEFINE)
VPATH   = ./:./OBJS$(addprefix :, $(FILES_DIR))

.PHONY: all clean

all : $(TARGET) install

$(TARGET) : $(OBJS) 
	$(LINK) -r -o $(TARGET) $(OBJS) 
	install $(TARGET)  $(LIB_INSTALL_DIR)/
	
OBJS/%.o : %.c
	@if [ ! -d OBJS ]; then \
		mkdir -p OBJS; \
	fi
	$(CC) $(CFLAGS) -c $< -o $@

OBJS/%.o : %.S
	$(AS) $(ASFLAGS) -c $< -o $@


clean: 
	rm -rf $(TARGET) OBJS $(LIB_INSTALL_DIR)/$(TARGET) 

install:
	install -d $(INC_INSTALL_DIR)
	install ./Inc/*.h $(INC_INSTALL_DIR)
