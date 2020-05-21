CROSS_COMPILE :=
CC := $(CROSS_COMPILE)gcc

SRC_DIR :=./src/
INC_DIR :=./inc/
LIB_DIR :=./lib/
BIN_DIR :=./bin/
OUTPUT_DIR :=../output/

TARGET :=IoTyzer

CFLAGS := -O2 -Wall -Werror -m64
CINCLUDE :=-I$(INC_DIR)
CLIBRARY := -l$(TARGET) -L$(LIB_DIR)

.PHONY : clean libIoTyzer

all : libIoTyzer

libIoTyzer : clean 
	$(CC) $(CFLAGS) -fPIC -shared -o $(LIB_DIR)$@.so $(SRC_DIR)$@.c $(CINCLUDE)
	@cp $(LIB_DIR)$@.so $(OUTPUT_DIR)

clean :
	@rm -rf $(SRC_DIR)*.o $(LIB_DIR)*