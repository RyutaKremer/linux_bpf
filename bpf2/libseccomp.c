// gcc libseccomp.c -lseccomp

#include <stdio.h>
#include <fcntl.h>
#include <seccomp.h>
//#include </usr/include/linux/seccomp.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#define BUF_SIZE    256

int main(int argc, char *argv[])
{
    int rc = -1;
    scmp_filter_ctx ctx;
    struct scmp_arg_cmp arg_cmp[] = { SCMP_A0(SCMP_CMP_EQ, 2) };
    int fd;
    unsigned char buf[BUF_SIZE];

    ctx = seccomp_init(SCMP_ACT_KILL);
    if (ctx == NULL) goto out;

    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);
    if (rc < 0) goto out;
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
    if (rc < 0) goto out;
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    if (rc < 0) goto out;
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
            SCMP_CMP(0, SCMP_CMP_EQ, 1));
    if (rc < 0) goto out;
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
    if (rc < 0) goto out;

    rc = seccomp_load(ctx);
    if (rc < 0) goto out;

    pid_t pid = getpid();
    printf("%d\n", pid);

out:
    seccomp_release(ctx);
    return -rc;
}
