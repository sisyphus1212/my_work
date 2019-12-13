#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
//#include <bfsys/bf_sal/bf_sys_intf.h>

#define BT_BUF_SIZE 1024

//#define LOG_CRIT(...) bf_sys_log_and_trace(BF_MOD_TM, BF_LOG_CRIT, __VA_ARGS__)
//#define LOG_ERROR(...) bf_sys_log_and_trace(BF_MOD_TM, BF_LOG_ERR, __VA_ARGS__)
//#define LOG_WARN(...) bf_sys_log_and_trace(BF_MOD_TM, BF_LOG_WARN, __VA_ARGS__)
//#define LOG_TRACE(...) bf_sys_log_and_trace(BF_MOD_TM, BF_LOG_INFO, __VA_ARGS__)
//#define LOG_DBG(...) bf_sys_log_and_trace(BF_MOD_TM, BF_LOG_DBG, __VA_ARGS__)
#ifdef __cplusplus
extern "C" {
#endif

void print_backtrace();

#ifdef __cplusplus
}
#endif
