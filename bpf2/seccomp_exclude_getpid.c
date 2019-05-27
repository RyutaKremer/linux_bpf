// getpid()を拒否

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>

// seccompが定義されていない場合定義
#ifndef seccomp
int seccomp(unsigned int op, unsigned int flags, void *args)
{
	// errnoを0に戻すのはシステムコール共通の実装？
    errno = 0;
	// システムコールの呼び出し
	// __NR_seccompはシステムコールの番号
    return syscall(__NR_seccomp, op, flags, args);
}
#endif

struct sock_filter filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
            (offsetof(struct seccomp_data, arch))),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
            (offsetof(struct seccomp_data, nr))),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getpid, 0, 1), // ここで記述?
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
};

struct sock_fprog prog = {
    .len = (unsigned short) (sizeof(filter) / sizeof(filter[0])),
    .filter = filter,
};


int main(){
    int err;

	// PR_SET_NO_NEW_PRIVS: 呼び出し元のプロセスのno_new_privs ビットをarg2 の値に設定
	// no_new_privsが1の時, execveはその呼び出しなしで実行できなかったことに対する特権を許可しなくなる
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("prctl");
        exit(EXIT_FAILURE);
    }

	// SECCOMP_SET_MODE_FILTERによってarg3で渡された Berkeley Packet Filter へのポインターで定義されるシステムコールのみ許可
    //if(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)){
    if(seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog)){
        perror("seccomp");
    }

    pid_t pid = getpid();
    printf("%d\n", pid);

    return 0;
}
