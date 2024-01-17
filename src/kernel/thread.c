#include "stdlib/assert.h"
#include "stdlib/string.h"

#include "kernel/asm.h"
#include "kernel/thread.h"

#include "kernel/misc/gdt.h"
#include "kernel/misc/util.h"

#include "kernel/lib/memory/map.h"
#include "kernel/lib/memory/layout.h"
#include "kernel/lib/console/terminal.h"

#if LAB >= 7
// arguments are passed via 'rdi', 'rsi', 'rdx' (see IA-32 calling conventions)
static void thread_foo(struct task *thread, thread_func_t foo, void *arg)
{
    assert(thread != NULL && foo != NULL);

    foo(arg);

    task_destroy(thread);

    // call schedule
    asm volatile ("int3");
}
#endif

// LAB7 Instruction:
// 1. create new task
// 2. allocate and map stack (hint: you can use 'USER_STACK_TOP')
// 3. pass function arguments via 'rdi, rsi, rdx' (store 'data' on new stack)
// 4. setup segment registers
// 5. setup instruction pointer and stack pointer
// Don't override stack (don't use large 'data')
//# if LAB >= 7
struct task *thread_create(const char *name, thread_func_t foo, const uint8_t *data, size_t size) {
    struct page *stack;
    struct task *task = task_new(name);

    if (task == NULL) {
        goto cleanup;
    }

    stack = page_alloc();
    if (stack == NULL) {
        terminal_printf("Unable to allocate memory for thread %s\n", name);
        goto cleanup;
    }

    if (page_insert(task->pml4, stack, USER_STACK_TOP - PAGE_SIZE, PTE_U | PTE_W) != 0) {
        terminal_printf("Unable to create thread %s. page_insert() error\n", name);
        goto cleanup;
    }

    uint8_t *stack_top = (uint8_t *) USER_STACK_TOP;
    {
        uintptr_t cr3 = rcr3();
        lcr3(PADDR(task->pml4));

        if (data != NULL) {
            void *data_ptr = (void *) ROUND_DOWN((uintptr_t)(stack_top - size), sizeof(void *));

            memcpy(data_ptr, data, size);
            data = stack_top = data_ptr;
        }

        stack_top -= sizeof(uintptr_t);
        *(uintptr_t *) stack_top = (uintptr_t) 0;

        task->context.gprs.rdi = (uintptr_t) task;
        task->context.gprs.rsi = (uintptr_t) foo;
        task->context.gprs.rdx = (uintptr_t) data;

        lcr3(cr3);
    }

    task->context.cs = GD_KT | GDT_DPL_S;
    task->context.ds = GD_KD | GDT_DPL_S;
    task->context.es = GD_KD | GDT_DPL_S;
    task->context.ss = GD_KD | GDT_DPL_S;

    task->context.rip = (uintptr_t) thread_foo;
    task->context.rsp = (uintptr_t) stack_top;

    return task;

    cleanup:
        if (task != NULL)
            task_destroy(task);

    return NULL;
}
//#endif

// LAB7 Instruction: 
// change 'state', so scheduler can run this thread
void thread_run(struct task *thread) {
    assert(thread->state == TASK_STATE_DONT_RUN);
    thread->state = TASK_STATE_READY;
}
