#include "kernel/task.h"
#include "kernel/syscall.h"
#include "kernel/lib/memory/map.h"
#include "kernel/lib/memory/mmu.h"
#include "kernel/lib/memory/layout.h"

#include "stdlib/assert.h"
#include "stdlib/string.h"
#include "stdlib/syscall.h"

#include "kernel/lib/console/terminal.h"

// LAB5 Instruction:
// - find page, virtual address 'va' belongs to. Use page_lookup
// - insert it into 'dest->pml4' and 'src->pml4' if needed
__attribute__((unused))
static int task_share_page(struct task *dest,
                           struct task *src,
                           void *va,
                           unsigned permissions) {
    uintptr_t virtual_address = (uintptr_t) va;
    struct page *page = NULL;

    page = page_lookup(src->pml4, virtual_address, NULL);
    assert(page != NULL);

    if ((permissions & PTE_W) != 0 || (permissions & PTE_COW) != 0) {
        permissions = (permissions | PTE_COW) & ~PTE_W;

        if (page_insert(src->pml4, page, virtual_address, permissions) != 0) {
            return -1;
        }
    }

    if (page_insert(dest->pml4, page, virtual_address, permissions) != 0) {
        return -1;
    }

    terminal_printf("Page shared %page (va: %page): refs: %d\n", page, va, page->ref);

    return 0;
}

// LAB5 Instruction:
// - create new task, copy context, setup return value
//
// - share pages:
// - check all entries inside pml4 before 'USER_TOP'
// - check all entries inside page directory pointer size NPDP_ENTRIES
// - check all entries inside page directory size NPD_ENTRIES
// - check all entries inside page table and share if present NPT_ENTRIES
//
// - mark new task as 'ready'
// - return new task id
__attribute__((unused))
static int sys_fork(struct task *task) {
    struct task *child = task_new("child");

    if (child == NULL)
        return -1;
    child->context = task->context;
    child->context.gprs.rax = 0; // return value

    for (uint16_t pml_index = 0; pml_index <= PML4_IDX(USER_TOP); pml_index++) {
        if ((task->pml4[pml_index] & PML4E_P) == 0)
            continue;

        uintptr_t pdpe_pa = PML4E_ADDR(task->pml4[pml_index]);
        pdpe_t *pdpe = VADDR(pdpe_pa);
        for (uint16_t pdp_index = 0; pdp_index < NPDP_ENTRIES; pdp_index++) {
            if ((pdpe[pdp_index] & PDPE_P) == 0)
                continue;

            uintptr_t pde_pa = PDPE_ADDR(pdpe[pdp_index]);
            pde_t *pde = VADDR(pde_pa);
            for (uint16_t pd_index = 0; pd_index < NPD_ENTRIES; pd_index++) {
                if ((pde[pd_index] & PDE_P) == 0)
                    continue;

                uintptr_t pte_pa = PTE_ADDR(pde[pd_index]);
                pte_t *pte = VADDR(pte_pa);
                for (uint16_t pt_index = 0; pt_index < NPT_ENTRIES; pt_index++) {
                    if ((pte[pt_index] & PTE_P) == 0)
                        continue;

                    unsigned permissions = pte[pt_index] & PTE_FLAGS_MASK;
                    void *page_address = PAGE_ADDR(pml_index, pdp_index, pd_index, pt_index, 0);

                    if (task_share_page(child, task, page_address, permissions) != 0) {
                        task_destroy(child);
                        return -1;
                    }
                }
            }
        }
    }

    child->state = TASK_STATE_READY;

    return child->id;
}

// LAB5 Instruction:
// - implement 'puts', 'exit', 'fork' and 'yield' syscalls
// - you can get syscall number from 'rax'
// - return value also should be passed via 'rax'
void syscall(struct task *task) {
    enum syscall syscall = task->context.gprs.rax;
    int64_t ret = 0;

    switch (syscall) {
        case SYSCALL_PUTS:
            terminal_printf("[%d] task: %s", task->id, (char *) task->context.gprs.rbx);
            break;
        case SYSCALL_EXIT:
            terminal_printf("[%d] task was exit with value [%d]\n", task->id, task->context.gprs.rbx);
            task_destroy(task);

            return schedule();
        case SYSCALL_FORK:
            ret = sys_fork(task);
            break;
        case SYSCALL_YIELD:
            return schedule();
        default:
            panic("Unknown syscall: %u\n", syscall);
    }

    task->context.gprs.rax = ret;

    task_run(task);
}
