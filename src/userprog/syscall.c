#include "userprog/syscall.h"
#include "lib/stdio.h"
#include "lib/kernel/stdio.h"
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "devices/input.h"

#define USER_ASSERT(CONDITION) \
    if (CONDITION)             \
    {                          \
    }                          \
    else                       \
    {                          \
        exit(-1);              \
    }

static struct open_file
{
    int fd;
    struct file *file;
    struct list_elem elem;
};

static void syscall_handler(struct intr_frame *);
static bool is_valid_ptr(const void *ptr);
static bool is_user_mem(const void *start, size_t size);
static bool is_valid_str(const char *str);
static struct open_file *get_file_by_fd(const int fd);

static void halt(void) NO_RETURN;
static void exit(int status) NO_RETURN;
static pid_t exec(const char *file);
static int wait(pid_t);
static bool create(const char *file, unsigned initial_size);
static bool remove(const char *file);
static int open(const char *file);
static int filesize(int fd);
static int read(int fd, void *buffer, unsigned length);
static int write(int fd, const void *buffer, unsigned length);
static void seek(int fd, unsigned position);
static unsigned tell(int fd);
static void close(int fd);

static struct lock file_lock;

void syscall_init(void)
{
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");

    lock_init(&file_lock);
}

static void syscall_handler(struct intr_frame *f)
{
    USER_ASSERT(is_user_mem(f->esp, sizeof(void *)));

    void *args[4];
    for (size_t i = 0; i != 4; ++i)
        args[i] = f->esp + i * sizeof(void *);

    int syscall_num = *(int *)args[0];

    /* Check validation. */
    switch (syscall_num)
    {
    case SYS_READ:
    case SYS_WRITE:
        USER_ASSERT(is_user_mem(args[3], sizeof(void *)));
    case SYS_CREATE:
    case SYS_SEEK:
        USER_ASSERT(is_user_mem(args[2], sizeof(void *)));
    case SYS_EXIT:
    case SYS_EXEC:
    case SYS_WAIT:
    case SYS_REMOVE:
    case SYS_OPEN:
    case SYS_FILESIZE:
    case SYS_TELL:
    case SYS_CLOSE:
        USER_ASSERT(is_user_mem(args[1], sizeof(void *)));
    case SYS_HALT:
        break;
    default:
        NOT_REACHED();
    }

    /* Forward. */
    switch (syscall_num)
    {
    case SYS_HALT:
        halt();
        NOT_REACHED();
    case SYS_EXIT:
        exit(*(int *)args[1]);
        NOT_REACHED();
    case SYS_EXEC:
        f->eax = exec(*(const char **)args[1]);
        break;
    case SYS_WAIT:
        f->eax = wait(*(pid_t *)args[1]);
        break;
    case SYS_CREATE:
        f->eax = create(*(const char **)args[1], *(unsigned *)args[2]);
        break;
    case SYS_REMOVE:
        f->eax = remove(*(const char **)args[1]);
        break;
    case SYS_OPEN:
        f->eax = open(*(const char **)args[1]);
        break;
    case SYS_FILESIZE:
        f->eax = filesize(*(int *)args[1]);
        break;
    case SYS_READ:
        f->eax = read(*(int *)args[1], *(void **)args[2], *(unsigned *)args[3]);
        break;
    case SYS_WRITE:
        f->eax = write(*(int *)args[1], *(const void **)args[2], *(unsigned *)args[3]);
        break;
    case SYS_SEEK:
        seek(*(int *)args[1], *(unsigned *)args[2]);
        break;
    case SYS_TELL:
        f->eax = tell(*(int *)args[1]);
        break;
    case SYS_CLOSE:
        close(*(int *)args[1]);
        break;
    default:
        NOT_REACHED();
    }
}

/* Trả về true nếu PTR không phải là con trỏ rỗng,
     một con trỏ tới không gian địa chỉ ảo kernel
     hoặc một con trỏ tới bộ nhớ ảo chưa được ánh xạ. */
static bool is_valid_ptr(const void *ptr)
{
    return ptr != NULL && is_user_vaddr(ptr) && pagedir_get_page(thread_current()->pagedir, ptr) != NULL;
}

/* Returns true if [START, START + SIZE) is all valid. */
static bool is_user_mem(const void *start, size_t size)
{
    for (const void *ptr = start; ptr < start + size; ptr += PGSIZE)
    {
        if (!is_valid_ptr(ptr))
            return false;
    }

    if (size > 1 && !is_valid_ptr(start + size - 1))
        return false;

    return true;
}

/* Trả về true nếu STR là chuỗi hợp lệ trong không gian người dùng. */
static bool is_valid_str(const char *str)
{
    if (!is_valid_ptr(str))
        return false;

    for (const char *c = str; *c != '\0';)
    {
        ++c;
        if (c - str + 2 == PGSIZE || !is_valid_ptr(c))
            return false;
    }

    return true;
}

static struct open_file *get_file_by_fd(const int fd)
{
    struct list *l = &thread_current()->process->files;

    for (struct list_elem *e = list_begin(l); e != list_end(l); e = list_next(e))
    {
        struct open_file *f = list_entry(e, struct open_file, elem);
        if (f->fd == fd)
            return f;
    }

    USER_ASSERT(false);
}

static void exit(int status)
{
    struct process *self = thread_current()->process;//tiến trình hiện tại đang chạy

    while (!list_empty(&self->files))
    {
        struct open_file *f = list_entry(list_back(&self->files),
                                         struct open_file, elem);
        close(f->fd);
    }

    self->exit_code = status;
    thread_exit();
}

static int write(int fd, const void *buffer, unsigned size)
{
    USER_ASSERT(is_user_mem(buffer, size));
    USER_ASSERT(fd != STDIN_FILENO);

    if (fd == STDOUT_FILENO)
    {
        putbuf((const char *)buffer, size);
        return size;
    }

    struct open_file *f = get_file_by_fd(fd);

    lock_acquire(&file_lock);
    int ret = file_write(f->file, buffer, size);
    lock_release(&file_lock);

    return ret;
}

static pid_t exec(const char *cmd_line)
{
    USER_ASSERT(is_valid_str(cmd_line));

    lock_acquire(&file_lock);
    pid_t pid = process_execute(cmd_line);
    lock_release(&file_lock);

    if (pid == TID_ERROR)
        return -1;

    struct process *child = get_child(pid);
    sema_down(&child->sema_load);

    if (child->status == PROCESS_FAILED)
    {
        sema_down(&child->sema_wait);
        palloc_free_page(child);
        return -1;
    }
    else
    {
        ASSERT(child->status == PROCESS_NORMAL);
        return pid;
    }
}

static void halt(void)
{
    shutdown_power_off();
}

static int wait(pid_t pid)
{
    return process_wait(pid);
}

static bool create(const char *file, unsigned initial_size)
{
    USER_ASSERT(is_valid_str(file));

    lock_acquire(&file_lock);
    bool ret = filesys_create(file, initial_size);
    lock_release(&file_lock);

    return ret;
}

static bool remove(const char *file)
{
    USER_ASSERT(is_valid_str(file));

    lock_acquire(&file_lock);
    bool ret = filesys_remove(file);
    lock_release(&file_lock);

    return ret;
}

static int open(const char *file)
{
    USER_ASSERT(is_valid_str(file));

    lock_acquire(&file_lock);
    struct file *f = filesys_open(file);
    lock_release(&file_lock);

    if (f == NULL)
        return -1;

    struct process *self = thread_current()->process;

    struct open_file *open_file = malloc(sizeof(struct open_file));
    open_file->fd = self->fd++;
    open_file->file = f;
    list_push_back(&self->files, &open_file->elem);

    return open_file->fd;
}

static int filesize(int fd)
{
    struct open_file *f = get_file_by_fd(fd);

    lock_acquire(&file_lock);
    int ret = file_length(f->file);
    lock_release(&file_lock);

    return ret;
}

static int read(int fd, void *buffer, unsigned size)
{
    USER_ASSERT(is_user_mem(buffer, size));
    USER_ASSERT(fd != STDOUT_FILENO);

    if (fd == STDIN_FILENO)
    {
        uint8_t *c = buffer;
        for (unsigned i = 0; i != size; ++i)
            *c++ = input_getc();
        return size;
    }

    struct open_file *f = get_file_by_fd(fd);

    lock_acquire(&file_lock);
    int ret = file_read(f->file, buffer, size);
    lock_release(&file_lock);

    return ret;
}

static void seek(int fd, unsigned position)
{
    struct open_file *f = get_file_by_fd(fd);

    lock_acquire(&file_lock);
    file_seek(f->file, position);
    lock_release(&file_lock);
}

static unsigned tell(int fd)
{
    struct open_file *f = get_file_by_fd(fd);

    lock_acquire(&file_lock);
    int ret = file_tell(f->file);
    lock_release(&file_lock);

    return ret;
}

static void close(int fd)
{
    struct open_file *f = get_file_by_fd(fd);

    lock_acquire(&file_lock);
    file_close(f->file);
    lock_release(&file_lock);

    list_remove(&f->elem);
    free(f);
}
