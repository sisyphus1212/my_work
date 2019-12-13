#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
//#include <bfsys/bf_sal/bf_sys_intf.h>
#include "backtrace.h"
#define BT_BUF_SIZE 1024

//#define LOG_CRIT(...) bf_sys_log_and_trace(BF_MOD_TM, BF_LOG_CRIT, __VA_ARGS__)
//#define LOG_ERROR(...) bf_sys_log_and_trace(BF_MOD_TM, BF_LOG_ERR, __VA_ARGS__)
//#define LOG_WARN(...) bf_sys_log_and_trace(BF_MOD_TM, BF_LOG_WARN, __VA_ARGS__)
//#define LOG_TRACE(...) bf_sys_log_and_trace(BF_MOD_TM, BF_LOG_INFO, __VA_ARGS__)
//#define LOG_DBG(...) bf_sys_log_and_trace(BF_MOD_TM, BF_LOG_DBG, __VA_ARGS__)
void print_backtrace()
{
    int j, nptrs;
    void *buffer[BT_BUF_SIZE];
    char **strings;

    nptrs = backtrace(buffer, BT_BUF_SIZE);
    printf("backtrace() returned %d addresses\n", nptrs);

    /* The call backtrace_symbols_fd(buffer, nptrs, STDOUT_FILENO)
      would produce similar output to the following: */

    strings = backtrace_symbols(buffer, nptrs);
    if (strings == NULL) {
       perror("backtrace_symbols");
       exit(EXIT_FAILURE);
    }

    for (j = 0; j < nptrs; j++)
    {
       printf("%s\n", strings[j]);
        //LOG_ERROR(
        //"##################\n%s:%d debug_backtrace: "
        //" %s\n#################\n",
        //__func__,
        //__LINE__,
        //strings[j]);
   }
    free(strings);
}

int main()
{

    print_backtrace();
}
