SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW

RECEIVER_FOLDER_SGX := receiver-in-sgx
RECEIVER_FOLDER 	:= receiver
SENDER_FOLDER_SGX 	:= sender-in-sgx
SENDER_FOLDER 		:= sender


.PHONY: all test_receiver test_sender clean

all: occlum_instance


occlum_instance: build_src_receiver build_src_sender
	bash occlum_build_receiver.sh
	bash occlum_build_sender.sh

build_src_receiver:
	@$(MAKE) --no-print-directory -C $(RECEIVER_FOLDER_SGX)
	@$(MAKE) --no-print-directory -C $(RECEIVER_FOLDER)

build_src_sender:
	@$(MAKE) --no-print-directory -C $(SENDER_FOLDER_SGX)
	@$(MAKE) --no-print-directory -C $(SENDER_FOLDER)


test_receiver:
	@LD_LIBRARY_PATH=$(RECEIVER_FOLDER)/build:$(SGX_SDK)/sdk_libs RUST_BACKTRACE=1 \
		$(RECEIVER_FOLDER)/build/receiver  

test_sender:
	@LD_LIBRARY_PATH=$(SENDER_FOLDER)/build:$(SGX_SDK)/sdk_libs RUST_BACKTRACE=1 \
		$(SENDER_FOLDER)/build/sender  
	

clean:
	@$(MAKE) --no-print-directory -C $(RECEIVER_FOLDER) 	clean
	@$(MAKE) --no-print-directory -C $(RECEIVER_FOLDER_SGX) clean
	@$(MAKE) --no-print-directory -C $(SENDER_FOLDER) 		clean
	@$(MAKE) --no-print-directory -C $(SENDER_FOLDER_SGX) 	clean

	@rm -rf .occlum occlum_instance_receiver
	@rm -rf .occlum occlum_instance_sender
