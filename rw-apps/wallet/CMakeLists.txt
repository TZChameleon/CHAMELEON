project (optee_example_wallet C)

set (SRC host/extern.c host/test_helpers.c host/test_stream.c host/test_prandom.c host/test_wallet.c host/test_transaction.c host/test_performance.c host/main.c host/stream_comm.c host/user_interface.c host/endian.c host/messages.pb.c host/pb_decode.c host/pb_encode.c host/wallet.c host/prandom.c host/bignum256.c host/storage_common.c host/transaction.c host/baseconv.c host/tz_functions.c host/rw_test.c)

add_executable (${PROJECT_NAME} ${SRC})

target_include_directories(${PROJECT_NAME}
			   PRIVATE ta/include
			   PRIVATE include)

target_link_libraries (${PROJECT_NAME} PRIVATE teec)

install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
