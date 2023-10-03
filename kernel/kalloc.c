// Physical memory allocator, for user processes,
// kernel stacks, page-table pages,
// and pipe buffers. Allocates whole 4096-byte pages.

#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "spinlock.h"
#include "riscv.h"
#include "defs.h"

void freerange(void *pa_start, void *pa_end);

extern char end[]; // first address after kernel.
                   // defined by kernel.ld.

struct run {
  struct run *next;
};

struct {
  struct spinlock lock;
  struct run *freelist;
} kmem;

// How many pages does the memory have?
#define TOTAL_PAGES ((PHYSTOP - KERNBASE) / PGSIZE)

// The macro to get the index in the page_ref_counter for a page
#define PAGE_REF_INDEX(ADDR) ((((uint64)ADDR) - KERNBASE) / PGSIZE)

// How many page tables are referencing a specific page. This is a direct map.
// OpenBSD and other stuff use more sophisticated methods such as something like
// a page table. But this is an educational OS not an industrial grade OS so
// fuck it.
// Here is a link to OpenBSD implementation:
// https://github.com/openbsd/src/blob/d54b5b53305f0fa3933354b63e23774d3e1b956f/sys/uvm/uvm_amap.c#L1233
uint8 page_ref_counter[TOTAL_PAGES];

// We set a soft upperlimit for number of references to a page.
// Why? Because fuck you that's why.
// Jokes aside, we need to detect overflow somehow. And I think it's better to
// leave a little space instead of capping it to UINT8_MAX.
// Maybe I want some special values later.
#define MAX_PAGE_REFERENCES 250

void
kinit()
{
  initlock(&kmem.lock, "kmem");
  freerange(end, (void*)PHYSTOP);
}

// A slightly modified version of kfree which does nothing
// with the reference counting.
// It runs some checks in which the make sure that all of the pages
// belong to the page_ref_counter
void
kinitfree(void *pa)
{
  struct run *r;
  int page_ref_counter_index;

  if(((uint64)pa % PGSIZE) != 0 || (char*)pa < end || (uint64)pa >= PHYSTOP)
    panic("kinitfree");

  page_ref_counter_index = PAGE_REF_INDEX(pa);
  if (page_ref_counter_index < 0 || page_ref_counter_index >= TOTAL_PAGES)
    panic("kinitfree out of range");
  page_ref_counter[page_ref_counter_index] = 0; // not needed but still...

  // Fill with junk to catch dangling refs.
  memset(pa, 1, PGSIZE);

  r = (struct run*)pa;

  r->next = kmem.freelist;
  kmem.freelist = r;
}

void
freerange(void *pa_start, void *pa_end)
{
  char *p;
  p = (char*)PGROUNDUP((uint64)pa_start);
  for(; p + PGSIZE <= (char*)pa_end; p += PGSIZE)
    kinitfree(p);
}

// Free the page of physical memory pointed at by pa,
// which normally should have been returned by a
// call to kalloc()
void
kfree(void *pa)
{
  struct run *r;
  int page_ref_counter_index;

  if(((uint64)pa % PGSIZE) != 0 || (char*)pa < end || (uint64)pa >= PHYSTOP)
    panic("kfree");

  // Do the reference counting
  page_ref_counter_index = PAGE_REF_INDEX(pa);
  if (page_ref_counter_index < 0 || page_ref_counter_index >= TOTAL_PAGES)
    panic("kfree out of range");

  // Note: Because we use one byte, we cant use atomics
  acquire(&kmem.lock);
  if (page_ref_counter[page_ref_counter_index] == 0)
    panic("kfree freed a free page");
  page_ref_counter[page_ref_counter_index]--;
  if (page_ref_counter[page_ref_counter_index] != 0) {
    release(&kmem.lock);
    return; // other page tables still reference this. We dont free it.
  }
  release(&kmem.lock);

  // Fill with junk to catch dangling refs.
  memset(pa, 1, PGSIZE);

  r = (struct run*)pa;

  acquire(&kmem.lock);
  r->next = kmem.freelist;
  kmem.freelist = r;
  release(&kmem.lock);
}

// Clones a physical address by increasing it's reference counter.
// Might return another value if the reference counter overflows.
// However, this is not implemented yet.
// Hirbod's Note: XV6 can only run 64 simultaneous processes.
// This means that the maximum reference counter value is 64 and
// we can never overflow the max value. 
void
krc_clone(void *pa)
{
  int page_ref_counter_index = PAGE_REF_INDEX(pa);
  if (page_ref_counter_index < 0 || page_ref_counter_index >= TOTAL_PAGES)
    panic("krc_clone out of range");
  
  acquire(&kmem.lock);

  // Error checks
  if (page_ref_counter[page_ref_counter_index] == 0) // is this page free?
    panic("krc_clone cloning a free page");
  if (page_ref_counter[page_ref_counter_index] >= MAX_PAGE_REFERENCES) // is this page has the maximum reference count?
    panic("krc_clone max references reached");
  
  // Note: Because we use one byte, we cant use atomics
  page_ref_counter[page_ref_counter_index]++;

  release(&kmem.lock);
}

// Allocate one 4096-byte page of physical memory.
// Returns a pointer that the kernel can use.
// Returns 0 if the memory cannot be allocated.
void *
kalloc(void)
{
  struct run *r;
  int page_ref_counter_index;

  acquire(&kmem.lock);
  r = kmem.freelist;
  if(r)
    kmem.freelist = r->next;
  release(&kmem.lock);

  if(r) {
    memset((char*)r, 5, PGSIZE); // fill with junk

    // Reference counting
    page_ref_counter_index = PAGE_REF_INDEX(r);
    if (page_ref_counter_index < 0 || page_ref_counter_index >= TOTAL_PAGES)
      panic("kalloc out of range page");
    // Note: Because we use one byte, we cant use atomics
    acquire(&kmem.lock);
    if (page_ref_counter[page_ref_counter_index] != 0)
      panic("kalloc allocated a non free page");
    page_ref_counter[page_ref_counter_index] = 1;
    release(&kmem.lock);
  }
  return (void*)r;
}

// Gets the number of free pages in kernel.
// Kinda goes hand in hand with number of times you
// can call kalloc without running out of memory.
uint64 count_free_pages(void) {
  uint64 counter;
  struct run *r;

  counter = 0;
  acquire(&kmem.lock);
  // Check how much we can go into the pages
  r = kmem.freelist;
  while (r) {
    counter++;
    r = r->next;
  }
  release(&kmem.lock);
  return counter;
}

// Returns the free memory space in bytes
uint64 sys_mem_free(void) {
  return count_free_pages() * PGSIZE;
}