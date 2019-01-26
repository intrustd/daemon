#ifndef __intrustd_init_common_H__
#define __intrustd_init_common_H__

#define COMM 3

void close_all_files();
void setup_signals();
void restore_sigchld();

#endif
