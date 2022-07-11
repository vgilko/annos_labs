#ifndef __LAYOUT_H__
#define __LAYOUT_H__

#ifdef __USER__
# error "This file is for kernel internal use only"
#endif

#include "kernel/lib/memory/mmu.h"

 
/*
 * Virtual memory map:                                                              
 *
 *                   +------------------------------+ 0xFFFF FFFF FFFF FFFF
 *                   |                              | 
 *                   |                              | 
 *                   |                              | 
 *                   |                              | 
 *                   |     OS Kernel 32 GB          | 
 *                   |                              | 
 *                   |                              |  
 *                   |                              | 
 *  KERNEL_BASE,---> +------------------------------+ 0xFFFF FFF8 0000 0000 
 * KERNEL_STACK_TOP  |                              |                         
 *                   |                              |                            
 *                   |     OS Stack. Grow form      |                                      
 *                   |    high address to lower     |
 *                   |                              |
 *  KERNEL_INFO ---> +------------------------------+
 *                   |                              |
 *                   |                              |
 *    APIC_BASE ---> +------------------------------+ 
 *                   |                              |
 *  IOAPIC_BASE ---> +------------------------------+ 
 *                   .                              .
 *                   .     Unmapped Memory          .
 *                   .                              .
 *                   +------------------------------+ 0x0000 0100 0000 0000
 *                   |                              | 
 *                   |     User Space 1 TB          | 
 *                   |                              | 
 *                   +                              + 
 *                   |                              | 
 *                   +------------------------------+ 0x0000 0000 0000 0000
 * 
 */
 

#define VADDR(paddr_) ((void *)((uintptr_t)(paddr_) + VADDR_BASE))
#define PADDR(vaddr_) ((uintptr_t)(vaddr_) - VADDR_BASE)

#define KERNEL_STACK_TOP	(KERNEL_BASE)
#define KERNEL_STACK_SIZE	(PAGE_SIZE * 8)

#define KERNEL_INFO		(KERNEL_STACK_TOP - KERNEL_STACK_SIZE - PAGE_SIZE)

// Virtual address of the APIC base
#define APIC_BASE		(KERNEL_INFO - PAGE_SIZE)
#define IOAPIC_BASE		(APIC_BASE - PAGE_SIZE)

// Separate stack for interrupts (using IST),
// because otherwise they may override stack of kernel threads
#define INTERRUPT_STACK_SIZE	(PAGE_SIZE * 2)
#define INTERRUPT_STACK_TOP	(IOAPIC_BASE)

#define EXCEPTION_STACK_SIZE	(PAGE_SIZE * 2)
#define EXCEPTION_STACK_TOP	(INTERRUPT_STACK_TOP - INTERRUPT_STACK_SIZE)

// It is good idea to make at least one temporary page for each
// processor. But for now we use only one processor, so one page
// should be enough.
#define KERNEL_TEMP_PAGE_CNT	(1)
#define KERNEL_TEMP		(EXCEPTION_STACK_TOP - EXCEPTION_STACK_SIZE - KERNEL_TEMP_PAGE_CNT*PAGE_SIZE)

// Physical address of the APIC base
#define APIC_BASE_PA	0xFEE00000
// Physical address of the IO APIC base
#define IOAPIC_BASE_PA	0xFEC00000

#define USER_TOP	    0x0000010000000000	// 1 TB
#define USER_STACK_TOP	0x0000000a00000000

#endif
