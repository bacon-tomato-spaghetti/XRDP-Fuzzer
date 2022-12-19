#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <limits.h>
#include <stdbool.h>
#if defined(HAVE_CONFIG_H)
#include <config_ac.h>
#endif

#include "xrdp/libxrdp.h"
#include "ms-rdpbcgr.h"
#include "xrdp/common/log.h"
#include "xrdp/common/string_calls.h"
#include "xrdp/common/trans.h"

/* this lets the source compile without afl-clang-fast/lto */
#ifndef __AFL_FUZZ_TESTCASE_LEN

ssize_t       fuzz_len;
unsigned char fuzz_buf[1024000];

  #define __AFL_FUZZ_TESTCASE_LEN fuzz_len
  #define __AFL_FUZZ_TESTCASE_BUF fuzz_buf
  #define __AFL_FUZZ_INIT() void sync(void);
  #define __AFL_LOOP(x) \
    ((fuzz_len = read(0, fuzz_buf, sizeof(fuzz_buf))) > 0 ? 1 : 0)
  #define __AFL_INIT() sync()

#endif

#pragma clang optimize off
#pragma GCC            optimize("O0")

extern unsigned char *g_inbuf;

__AFL_FUZZ_INIT();

int main(int argc, char **argv) {
    __AFL_INIT();
    ssize_t        len;                        /* how much input did we read? */
    unsigned char *buf;                        /* test case buffer pointer    */

    /* The number passed to __AFL_LOOP() controls the maximum number of
     iterations before the loop exits and the program is allowed to
     terminate normally. This limits the impact of accidental memory leaks
     and similar hiccups. */

    buf = __AFL_FUZZ_TESTCASE_BUF;  // this must be assigned before __AFL_LOOP!
    g_inbuf = buf;    

    while (__AFL_LOOP(UINT_MAX)) {  // increase if you have good stability
        /* input */
        len = __AFL_FUZZ_TESTCASE_LEN;  // do not use the macro directly in a call!
        
        struct trans* trans = calloc(1, sizeof(struct trans));

        trans->mode = 1;
        trans->tls = 0;
        make_stream(trans->in_s);
        init_stream(trans->in_s, 0x10);
        make_stream(trans->out_s);
        init_stream(trans->out_s, 0x10);
        /* assign tcp calls by default */
        trans->trans_recv = trans_tcp_recv;
        trans->trans_send = trans_tcp_send;
        trans->trans_can_recv = trans_tcp_can_recv;
        init_stream(trans->in_s, 8192 * 4);

        trans->extra_flags = 0;
        trans->header_size = 0;
        trans->no_stream_init_on_data_in = 1;
        trans->trans_data_in = NULL;
        trans->status = TRANS_STATUS_UP;
        
        struct xrdp_session* session= libxrdp_init((tbus)0, trans, NULL);
        trans->si = &(session->si);
        trans->my_source = XRDP_SOURCE_CLIENT;
        /* this callback function is in xrdp_wm.c */
        session->callback = NULL;
        /* this function is just above */
        session->is_term = NULL;

        libxrdp_process_incoming(session);
    }

  return 0;
}