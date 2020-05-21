CROSS_COMPILE :=
CC := $(CROSS_COMPILE)gcc

SRC_DIR :=./src/
INC_DIR :=./inc/
LIB_DIR :=./lib/
BIN_DIR :=./bin/
OUTPUT_DIR :=../output/

TARGET :=IoTyzer

CFLAGS := -O2 -Wall -Werror
CINCLUDE :=-I$(INC_DIR)
CLIBRARY := -L$(LIB_DIR) -l$(TARGET)

OBJS_SERVER :=$(SRC_DIR)print.o $(SRC_DIR)casting.o						\
	$(SRC_DIR)socket.o $(SRC_DIR)cavp.o $(SRC_DIR)cavp_server.o						\
	$(SRC_DIR)rand.o									\
	$(SRC_DIR)aria.o $(SRC_DIR)seed.o $(SRC_DIR)lea.o $(SRC_DIR)mode_of_operate.o		\
	$(SRC_DIR)kor_kat_test_s.o $(SRC_DIR)kor_mct_test_s.o $(SRC_DIR)kor_mmt_test_s.o

OBJS_CLIENT :=$(SRC_DIR)print.o $(SRC_DIR)casting.o 						\
	$(SRC_DIR)socket.o $(SRC_DIR)cavp.o $(SRC_DIR)cavp_client.o $(SRC_DIR)comm.o				\
	$(SRC_DIR)kor_kat_test_c.o $(SRC_DIR)kor_mct_test_c.o $(SRC_DIR)kor_mmt_test_c.o

OBJS_LIB :=$(SRC_DIR)print.o $(SRC_DIR)comm.o

OBJS_TARGET :=$(SRC_DIR)print.o $(SRC_DIR)casting.o $(SRC_DIR)comm.o				\
	$(SRC_DIR)aria.o $(SRC_DIR)seed.o $(SRC_DIR)lea.o $(SRC_DIR)mode_of_operate.o

.PHONY : clean										\
	print casting									\
	socket cavp cavp_server cavp_client comm		\
	rand aria seed lea mode_of_operate				\
	kor_kat_test_s kor_kat_test_c					\
	kor_mct_test_s kor_mct_test_c					\
	kor_mmt_test_s kor_mmt_test_c					\
	libIoTyzer Server Client Target

all : lib$(TARGET) $(TARGET)Client $(TARGET)Target $(TARGET)Server

print :
	$(CC) $(CFLAGS) -o $(SRC_DIR)$@.o -c $(SRC_DIR)util/$@.c $(CINCLUDE)

casting :
	$(CC) $(CFLAGS) -o $(SRC_DIR)$@.o -c $(SRC_DIR)util/$@.c $(CINCLUDE)

socket :
	$(CC) $(CFLAGS) -o $(SRC_DIR)$@.o -c $(SRC_DIR)socket/$@.c $(CINCLUDE)

cavp :
	$(CC) $(CFLAGS) -o $(SRC_DIR)$@.o -c $(SRC_DIR)cavp/$@.c $(CINCLUDE)

cavp_server :
	$(CC) $(CFLAGS) -o $(SRC_DIR)$@.o -c $(SRC_DIR)cavp/$@.c $(CINCLUDE)

cavp_client :
	$(CC) $(CFLAGS) -o $(SRC_DIR)$@.o -c $(SRC_DIR)cavp/$@.c $(CINCLUDE)

comm :
	$(CC) $(CFLAGS) -o $(SRC_DIR)$@.o -c $(SRC_DIR)comm/$@.c $(CINCLUDE)

rand :
	$(CC) $(CFLAGS) -o $(SRC_DIR)$@.o -c $(SRC_DIR)crypto/$@.c $(CINCLUDE)

aria :
	$(CC) $(CFLAGS) -o $(SRC_DIR)$@.o -c $(SRC_DIR)crypto/$@.c $(CINCLUDE)

seed :
	$(CC) $(CFLAGS) -o $(SRC_DIR)$@.o -c $(SRC_DIR)crypto/$@.c $(CINCLUDE)

lea :
	$(CC) $(CFLAGS) -o $(SRC_DIR)$@.o -c $(SRC_DIR)crypto/$@.c $(CINCLUDE)

mode_of_operate :
	$(CC) $(CFLAGS) -o $(SRC_DIR)$@.o -c $(SRC_DIR)crypto/$@.c $(CINCLUDE)

kor_kat_test_s : print casting rand aria seed lea mode_of_operate
	$(CC) $(CFLAGS) -o $(SRC_DIR)$@.o -c $(SRC_DIR)cavp/$@.c $(CINCLUDE)

kor_kat_test_c : print casting
	$(CC) $(CFLAGS) -o $(SRC_DIR)$@.o -c $(SRC_DIR)cavp/$@.c $(CINCLUDE) $(CLIBRARY)

kor_mct_test_s : print casting rand aria seed lea mode_of_operate
	$(CC) $(CFLAGS) -o $(SRC_DIR)$@.o -c $(SRC_DIR)cavp/$@.c $(CINCLUDE)

kor_mct_test_c : print casting
	$(CC) $(CFLAGS) -o $(SRC_DIR)$@.o -c $(SRC_DIR)cavp/$@.c $(CINCLUDE) $(CLIBRARY)

kor_mmt_test_s : print casting rand aria seed lea mode_of_operate
	$(CC) $(CFLAGS) -o $(SRC_DIR)$@.o -c $(SRC_DIR)cavp/$@.c $(CINCLUDE)

kor_mmt_test_c : print casting
	$(CC) $(CFLAGS) -o $(SRC_DIR)$@.o -c $(SRC_DIR)cavp/$@.c $(CINCLUDE) $(CLIBRARY)

$(TARGET)Server : clean socket cavp cavp_server kor_kat_test_s kor_mct_test_s kor_mmt_test_s
	$(CC) $(CFLAGS) -o $(BIN_DIR)$@ $(SRC_DIR)$@.c $(OBJS_SERVER) $(CINCLUDE)
	@cp $(BIN_DIR)$@ $(OUTPUT_DIR)

$(TARGET)Client : clean comm socket cavp cavp_client kor_kat_test_c kor_mct_test_c kor_mmt_test_c
	$(CC) $(CFLAGS) -o $(BIN_DIR)$@ $(SRC_DIR)$@.c $(OBJS_CLIENT) $(CINCLUDE) $(CLIBRARY)
	@cp $(BIN_DIR)$@ $(OUTPUT_DIR)

lib$(TARGET) : clean
	$(CC) $(CFLAGS) -fpic -shared -o $(LIB_DIR)$@.so $(SRC_DIR)$@.c $(SRC_DIR)util/print.c $(SRC_DIR)comm/comm.c $(CINCLUDE)
	@cp $(LIB_DIR)$@.so $(OUTPUT_DIR)

$(TARGET)Target : clean print comm rand aria seed lea mode_of_operate
	$(CC) $(CFLAGS) -o $(BIN_DIR)$@ $(SRC_DIR)$@.c $(OBJS_TARGET) $(CINCLUDE)
	@cp $(BIN_DIR)$@ $(OUTPUT_DIR)

clean :
	@rm -rf $(SRC_DIR)*.o $(BIN_DIR)*
