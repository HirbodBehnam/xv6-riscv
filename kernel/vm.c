#include "param.h"
#include "types.h"
#include "memlayout.h"
#include "elf.h"
#include "riscv.h"
#include "defs.h"
#include "fs.h"
#include "spinlock.h"
#include "proc.h"

/*
 * the kernel's page table.
 */
pagetable_t kernel_pagetable;

extern char etext[];  // kernel.ld sets this to end of kernel code.

extern char trampoline[]; // trampoline.S

// Make a direct-map page table for the kernel.
pagetable_t
kvmmake(void)
{
  pagetable_t kpgtbl;

  kpgtbl = (pagetable_t) kalloc();
  memset(kpgtbl, 0, PGSIZE);

  // uart registers
  uart0_log = 0x20000000L;
  kvmmap(kpgtbl, uart0_log, UART0_PHY, PGSIZE, PTE_R | PTE_W);

  // virtio mmio disk interface
  kvmmap(kpgtbl, VIRTIO0, VIRTIO0, PGSIZE, PTE_R | PTE_W);

  // google goldfish rtc interface
  kvmmap(kpgtbl, GOLDFISH_RTC, GOLDFISH_RTC, PGSIZE, PTE_R | PTE_W);

  // PLIC
  kvmmap(kpgtbl, PLIC, PLIC, 0x400000, PTE_R | PTE_W);

  // map kernel text executable and read-only.
  kvmmap(kpgtbl, KERNBASE, KERNBASE, (uint64)etext-KERNBASE, PTE_R | PTE_X);

  // map kernel data and the physical RAM we'll make use of.
  kvmmap(kpgtbl, (uint64)etext, (uint64)etext, PHYSTOP-(uint64)etext, PTE_R | PTE_W);

  // map the trampoline for trap entry/exit to
  // the highest virtual address in the kernel.
  kvmmap(kpgtbl, TRAMPOLINE, (uint64)trampoline, PGSIZE, PTE_R | PTE_X);

  // allocate and map a kernel stack for each process.
  proc_mapstacks(kpgtbl);
  
  return kpgtbl;
}

// Initialize the one kernel_pagetable
void
kvminit(void)
{
  kernel_pagetable = kvmmake();
}

// Switch h/w page table register to the kernel's page table,
// and enable paging.
void
kvminithart()
{
  // wait for any previous writes to the page table memory to finish.
  sfence_vma();

  w_satp(MAKE_SATP(kernel_pagetable));

  // flush stale entries from the TLB.
  sfence_vma();
}

// Return the address of the PTE in page table pagetable
// that corresponds to virtual address va.  If alloc!=0,
// create any required page-table pages.
//
// The risc-v Sv39 scheme has three levels of page-table
// pages. A page-table page contains 512 64-bit PTEs.
// A 64-bit virtual address is split into five fields:
//   39..63 -- must be zero.
//   30..38 -- 9 bits of level-2 index.
//   21..29 -- 9 bits of level-1 index.
//   12..20 -- 9 bits of level-0 index.
//    0..11 -- 12 bits of byte offset within the page.
pte_t *
walk(pagetable_t pagetable, uint64 va, int alloc)
{
  if(va >= MAXVA)
    panic("walk");

  for(int level = 2; level > 0; level--) {
    pte_t *pte = &pagetable[PX(level, va)];
    if(*pte & PTE_V) {
      pagetable = (pagetable_t)PTE2PA(*pte);
    } else {
      if(!alloc || (pagetable = (pde_t*)kalloc()) == 0)
        return 0;
      memset(pagetable, 0, PGSIZE);
      *pte = PA2PTE(pagetable) | PTE_V;
    }
  }
  return &pagetable[PX(0, va)];
}

// Walks the page table just like walk function
// but does it with huge pages. This means that
// there is only one page table which we need to dereference.
//
// A 64-bit virtual address is split into four fields in huge pages:
//   39..63 -- must be zero.
//   30..38 -- 9 bits of level-2 index.
//   21..29 -- 9 bits of level-1 index.
//    0..20 -- 21 bits of byte offset within the page.
pte_t *
walk_huge(pagetable_t pagetable, uint64 va, int alloc)
{
  if(va >= MAXVA)
    panic("walk");

  pte_t *level2_pte = &pagetable[PX(2, va)]; // always level 2
  if(*level2_pte & PTE_V) { // is page table entry valid and points to another address?
    pagetable = (pagetable_t)PTE2PA(*level2_pte);
  } else {
    if(!alloc || (pagetable = (pde_t*)kalloc()) == 0) // try to allocate a page
      return 0;
    memset(pagetable, 0, PGSIZE); // empty the page
    *level2_pte = PA2PTE(pagetable) | PTE_V;
  }
  return &pagetable[PX(1, va)];
}

// Look up a virtual address, return the physical address,
// or 0 if not mapped.
// Can only be used to look up user pages.
uint64
walkaddr(pagetable_t pagetable, uint64 va)
{
  pte_t *pte;
  uint64 pa;

  if(va >= MAXVA)
    return 0;

  pte = walk(pagetable, va, 0);
  if(pte == 0)
    return 0;
  if((*pte & PTE_V) == 0)
    return 0;
  if((*pte & PTE_U) == 0)
    return 0;
  pa = PTE2PA(*pte);
  return pa;
}

// add a mapping to the kernel page table.
// only used when booting.
// does not flush TLB or enable paging.
// might use huge pages.
void
kvmmap(pagetable_t kpgtbl, uint64 va, uint64 pa, uint64 sz, int perm)
{
  if(kmappages(kpgtbl, va, sz, pa, perm) != 0)
    panic("kvmmap");
}

// Create PTEs for virtual addresses starting at va that refer to
// physical addresses starting at pa. va and size might not
// be page-aligned. Returns 0 on success, -1 if walk() couldn't
// allocate a needed page-table page.
int
mappages(pagetable_t pagetable, uint64 va, uint64 size, uint64 pa, int perm)
{
  uint64 a, last;
  pte_t *pte;

  if(size == 0)
    panic("mappages: size");
  
  a = PGROUNDDOWN(va);
  last = PGROUNDDOWN(va + size - 1);
  for(;;){
    if((pte = walk(pagetable, a, 1)) == 0)
      return -1;
    if(*pte & PTE_V)
      panic("mappages: remap");
    *pte = PA2PTE(pa) | perm | PTE_V;
    if(a == last)
      break;
    a += PGSIZE;
    pa += PGSIZE;
  }
  return 0;
}

// Checks if a huge page can be allocated instead of multiple
// simple pages.
// To check so, at first it checks if start boundery aligned.
// Next, it checks if the size of the allocated page is less
// than the size of requested allocation.
// Returns 1 if applicable.
int
huge_pages_applicable(uint64 start, uint64 end) {
  if (start % PGHUGESIZE != 0) // start is on boundry?
    return 0;
  if (end - start < PGHUGESIZE) // requested size is less than huge page size?
    return 0;
  return 1;
}

// Create PTEs for virtual addresses starting at va that refer to
// physical addresses starting at pa. va and size might not
// be page-aligned. Returns 0 on success, -1 if walk() couldn't
// allocate a needed page-table page.
// As the name suggests, it uses huge pages.
int
kmappages(pagetable_t pagetable, uint64 va, uint64 size, uint64 pa, int perm)
{
  uint64 a, last;
  pte_t *pte;
  int use_huge_pages;

  if(size == 0)
    panic("mappages: size");
  
  a = PGROUNDDOWN(va);
  last = PGROUNDDOWN(va + size - 1);
  for(;;){
    use_huge_pages = huge_pages_applicable(a, last);
    if (use_huge_pages) {
      if((pte = walk_huge(pagetable, a, 1)) == 0)
        return -1;
    } else {
      if((pte = walk(pagetable, a, 1)) == 0)
        return -1;
    }
    if(*pte & PTE_V)
      panic("mappages: remap");
    *pte = PA2PTE(pa) | perm | PTE_V;
    if(a == last)
      break;
    a += use_huge_pages ? PGHUGESIZE : PGSIZE;
    pa += use_huge_pages ? PGHUGESIZE : PGSIZE;
  }
  return 0;
}

// Remove npages of mappings starting from va. va must be
// page-aligned. The mappings must exist.
// Optionally free the physical memory.
void
uvmunmap(pagetable_t pagetable, uint64 va, uint64 npages, int do_free)
{
  uint64 a;
  pte_t *pte;

  if((va % PGSIZE) != 0)
    panic("uvmunmap: not aligned");

  for(a = va; a < va + npages*PGSIZE; a += PGSIZE){
    pte = walk(pagetable, a, 0);
    // Hirbod: This used to contain a panic.
    // But because of lazy allocation, we just continue and ignore them.
    // There used be another panic in which it checks if pte is equal to zero.
    // This will happen if sbrk requests more than 2MB of memory and does not use the
    // upper page at all. In this case, the last page table is non-existant
    // and thus the result of walk will be zero!
    // A simple program with sbrk(1024*1024*3) and then and exit will show it to you.
    if((pte == 0) || (*pte & PTE_V) == 0)
      continue;
    if(PTE_FLAGS(*pte) == PTE_V)
      panic("uvmunmap: not a leaf");
    if(do_free){
      uint64 pa = PTE2PA(*pte);
      kfree((void*)pa);
    }
    *pte = 0;
  }
}

// create an empty user page table.
// returns 0 if out of memory.
pagetable_t
uvmcreate()
{
  pagetable_t pagetable;
  pagetable = (pagetable_t) kalloc();
  if(pagetable == 0)
    return 0;
  memset(pagetable, 0, PGSIZE);
  return pagetable;
}

// Load the user initcode into address 0 of pagetable,
// for the very first process.
// sz must be less than a page.
void
uvmfirst(pagetable_t pagetable, uchar *src, uint sz)
{
  char *mem;

  if(sz >= PGSIZE)
    panic("uvmfirst: more than a page");
  mem = kalloc();
  memset(mem, 0, PGSIZE);
  mappages(pagetable, 0, PGSIZE, (uint64)mem, PTE_W|PTE_R|PTE_X|PTE_U);
  memmove(mem, src, sz);
}

// Allocate PTEs and physical memory to grow process from oldsz to
// newsz, which need not be page aligned.  Returns new size or 0 on error.
uint64
uvmalloc(pagetable_t pagetable, uint64 oldsz, uint64 newsz, int xperm)
{
  char *mem;
  uint64 a;

  if(newsz < oldsz)
    return oldsz;

  oldsz = PGROUNDUP(oldsz);
  for(a = oldsz; a < newsz; a += PGSIZE){
    mem = kalloc();
    if(mem == 0){
      uvmdealloc(pagetable, a, oldsz);
      return 0;
    }
    memset(mem, 0, PGSIZE);
    if(mappages(pagetable, a, PGSIZE, (uint64)mem, PTE_R|PTE_U|xperm) != 0){
      kfree(mem);
      uvmdealloc(pagetable, a, oldsz);
      return 0;
    }
  }
  return newsz;
}

// Lazily allocate the page table for this address if applicable
enum MemoryAllocatationStatus
uvmlazy(pagetable_t pagetable, uint64 addr, int ignore_allocated)
{
  // Validate the address
  if (myproc()->sz <= addr || myproc()->top_of_stack > addr)
    return ALLOCATE_SEGFAULT;
  // Make everything less error prone
  if (walkaddr(pagetable, addr) != 0) {
    if (ignore_allocated)
      return ALLOCATE_OK;
    else
      panic("uvmlazy: lazily allocating an allocated page");
  }
  // Get a page from kernel
  void *allocated_mem = kalloc();
  if (allocated_mem == 0) // OOM!
    return ALLOCATE_OOM;
  memset(allocated_mem, 0, PGSIZE);
  // Register this page
  uint64 page_begin = PGROUNDDOWN(addr);
  if (mappages(pagetable, page_begin, PGSIZE, (uint64)allocated_mem, PTE_W|PTE_R|PTE_U) != 0) {
    kfree(allocated_mem);
    printf("mappages OOM\n");
    return ALLOCATE_OOM;
  }
  return ALLOCATE_OK;
}

// Deallocate user pages to bring the process size from oldsz to
// newsz.  oldsz and newsz need not be page-aligned, nor does newsz
// need to be less than oldsz.  oldsz can be larger than the actual
// process size.  Returns the new process size.
uint64
uvmdealloc(pagetable_t pagetable, uint64 oldsz, uint64 newsz)
{
  if(newsz >= oldsz)
    return oldsz;

  if(PGROUNDUP(newsz) < PGROUNDUP(oldsz)){
    int npages = (PGROUNDUP(oldsz) - PGROUNDUP(newsz)) / PGSIZE;
    uvmunmap(pagetable, PGROUNDUP(newsz), npages, 1);
  }

  return newsz;
}

// Recursively free page-table pages.
// All leaf mappings must already have been removed.
void
freewalk(pagetable_t pagetable)
{
  // there are 2^9 = 512 PTEs in a page table.
  for(int i = 0; i < 512; i++){
    pte_t pte = pagetable[i];
    if((pte & PTE_V) && (pte & (PTE_R|PTE_W|PTE_X)) == 0){
      // this PTE points to a lower-level page table.
      uint64 child = PTE2PA(pte);
      freewalk((pagetable_t)child);
      pagetable[i] = 0;
    } else if(pte & PTE_V){
      panic("freewalk: leaf");
    }
  }
  kfree((void*)pagetable);
}

// Free user memory pages,
// then free page-table pages.
void
uvmfree(pagetable_t pagetable, uint64 sz)
{
  if(sz > 0)
    uvmunmap(pagetable, 0, PGROUNDUP(sz)/PGSIZE, 1);
  freewalk(pagetable);
}

// Given a parent process's page table, copy
// its memory into a child's page table with cow.
// Copies both the page table only and just creates a reference
// to physical pages.
// returns 0 on success, -1 on failure.
// Panics if on failure!
void
uvm_cow_copy(pagetable_t old, pagetable_t new, uint64 sz)
{
  pte_t *pte;
  uint64 pa, i;
  uint flags;

  for(i = 0; i < sz; i += PGSIZE){
    pte = walk(old, i, 0);
    // Read the explaination in uvmunmap
    if((pte == 0) || (*pte & PTE_V) == 0)
      continue;
    pa = PTE2PA(*pte);
    
    flags = PTE_FLAGS(*pte);
    if (flags & PTE_W) { // if this is a writable page, ...
      flags = (flags | PTE_COW) & (~PTE_W); // add the cow flag and remove the write flag to copied page table
      *pte = (*pte | PTE_COW) & (~PTE_W); // add the cow flag and remove the write flag to initial page table
    }
    // No need to copy otherwise, these pages will have the same immulatble reference

    // Just increase the reference counter
    krc_clone((void*) pa);
    
    // Map the physical address AGAIN
    if(mappages(new, i, PGSIZE, pa, flags) != 0)
      panic("uvm_cow_copy: mappages");
  }
}

// Try to do a CoW on the address of a page table.
// Returns 0 if the cow is done, otherwise 1.
enum MemoryAllocatationStatus
uvmtrycow(pagetable_t pagetable, uint64 addr)
{
  // Validate the address
  if (myproc()->sz <= addr)
    return ALLOCATE_SEGFAULT; // SEGFAULT
  
  // Is the CoW flag set?
  pte_t *pte = walk(pagetable, addr, 0);
  if (pte == 0 || (*pte & PTE_COW) == 0)
    return ALLOCATE_SEGFAULT; // lol. no cow, just segfault
  
  // If we are here, this is a CoW!
  // First, check if this is the last reference
  uint64 pa = PTE2PA(*pte);
  if (krc_count((void *) pa) == 1) {
    // Last reference, just remove the COW flag
    *pte = (*pte | PTE_W) & (~PTE_COW);
    return ALLOCATE_OK;
  }
  // Now we allocate a page
  void *new_page = kalloc();
  if (new_page == 0)
    return ALLOCATE_OOM;
  // Now, copy the page into new page
  memmove(new_page, (const void *)pa, PGSIZE);
  // Change the pte: change physical address, add W flag, remove CoW
  *pte = (PA2PTE(new_page) | PTE_FLAGS(*pte) | PTE_W) & (~PTE_COW);
  // Reduce the reference counter of the old physical page
  kfree((void *)pa);
  return ALLOCATE_OK;
}

// mark a PTE invalid for user access.
// used by exec for the user stack guard page.
void
uvmclear(pagetable_t pagetable, uint64 va)
{
  pte_t *pte;
  
  pte = walk(pagetable, va, 0);
  if(pte == 0)
    panic("uvmclear");
  *pte &= ~PTE_U;
}

// We are using lazy page allocation right?
// What if we use a sbrk followed by a read syscall?
// The kernel will consider the pages unallocated in copyout and thus
// will fail the syscall.
// Using this function, we can allocate those pages if they are located in heap.
// Some bound checking should be done before it though.
static void
try_allocate_missing_pages(pagetable_t pagetable, uint64 dstva, uint64 len)
{
  uint64 end_address = dstva + len;
  uint64 top_of_heap = myproc()->sz;
  if (end_address >= top_of_heap) // Overflow. Will be caught later
    return;
  // Now we do something like uvmalloc
  uint64 start = PGROUNDDOWN(dstva);
  for (uint64 current_address = start; start < end_address; start += PGSIZE)
    // TODO: check result
    uvmlazy(pagetable, current_address + 1, 1);
}

// Copy from kernel to user.
// Copy len bytes from src to virtual address dstva in a given page table.
// Return 0 on success, -1 on error.
int
copyout(pagetable_t pagetable, uint64 dstva, char *src, uint64 len)
{
  uint64 n, va0, pa0;

  try_allocate_missing_pages(pagetable, dstva, len);
  while(len > 0){
    va0 = PGROUNDDOWN(dstva);
    pa0 = walkaddr(pagetable, va0);
    if(pa0 == 0)
      return -1;
    n = PGSIZE - (dstva - va0);
    if(n > len)
      n = len;
    memmove((void *)(pa0 + (dstva - va0)), src, n);

    len -= n;
    src += n;
    dstva = va0 + PGSIZE;
  }
  return 0;
}

// Copy from user to kernel.
// Copy len bytes to dst from virtual address srcva in a given page table.
// Return 0 on success, -1 on error.
int
copyin(pagetable_t pagetable, char *dst, uint64 srcva, uint64 len)
{
  uint64 n, va0, pa0;

  try_allocate_missing_pages(pagetable, srcva, len);
  while(len > 0){
    va0 = PGROUNDDOWN(srcva);
    pa0 = walkaddr(pagetable, va0);
    if(pa0 == 0)
      return -1;
    n = PGSIZE - (srcva - va0);
    if(n > len)
      n = len;
    memmove(dst, (void *)(pa0 + (srcva - va0)), n);

    len -= n;
    dst += n;
    srcva = va0 + PGSIZE;
  }
  return 0;
}

// Copy a null-terminated string from user to kernel.
// Copy bytes to dst from virtual address srcva in a given page table,
// until a '\0', or max.
// Return 0 on success, -1 on error.
int
copyinstr(pagetable_t pagetable, char *dst, uint64 srcva, uint64 max)
{
  uint64 n, va0, pa0;
  int got_null = 0;
  // Hirbod: fuck try_allocate_missing_pages. Probably has a wrong usage here

  while(got_null == 0 && max > 0){
    va0 = PGROUNDDOWN(srcva);
    pa0 = walkaddr(pagetable, va0);
    if(pa0 == 0)
      return -1;
    n = PGSIZE - (srcva - va0);
    if(n > max)
      n = max;

    char *p = (char *) (pa0 + (srcva - va0));
    while(n > 0){
      if(*p == '\0'){
        *dst = '\0';
        got_null = 1;
        break;
      } else {
        *dst = *p;
      }
      --n;
      --max;
      p++;
      dst++;
    }

    srcva = va0 + PGSIZE;
  }
  if(got_null){
    return 0;
  } else {
    return -1;
  }
}
