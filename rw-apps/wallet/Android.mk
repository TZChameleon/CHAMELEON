LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_CFLAGS += -DANDROID_BUILD
LOCAL_CFLAGS += -Wall

LOCAL_SRC_FILES += host/extern.c host/test_helpers.c host/test_stream.c host/test_prandom.c host/test_wallet.c host/test_transaction.c host/test_performance.c host/main.c host/stream_comm.c host/user_interface.c host/endian.c host/messages.pb.c host/pb_decode.c host/pb_encode.c host/wallet.c host/prandom.c host/bignum256.c host/storage_common.c host/transaction.c host/baseconv.c host/tz_functions.c host/rw_test.c

LOCAL_C_INCLUDES := $(LOCAL_PATH)/ta/include

LOCAL_SHARED_LIBRARIES := libteec
LOCAL_MODULE := optee_example_wallet
LOCAL_VENDOR_MODULE := true
LOCAL_MODULE_TAGS := optional
include $(BUILD_EXECUTABLE)

include $(LOCAL_PATH)/ta/Android.mk
