OUTPUT_DIR := ./output/
TESTVECTOR_DIR := ./testvector/


all : clean build_IoTyzer


build_IoTyzer :
	$(MAKE) -C IoTyzer

clean :
	@rm -rf $(OUTPUT_DIR)* $(TESTVECTOR_DIR)*
