#include "userprog/exception.h"
#include <inttypes.h>
#include <stdio.h>
#include "userprog/gdt.h"
#include "userprog/syscall.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/page.h"

/* Number of page faults processed. */
static long long page_fault_cnt;

static void kill (struct intr_frame *);
static void page_fault (struct intr_frame *);

/* Registers handlers for interrupts that can be caused by user
   programs.

   In a real Unix-like OS, most of these interrupts would be
   passed along to the user process in the form of signals, as
   described in [SV-386] 3-24 and 3-25, but we don't implement
   signals.  Instead, we'll make them simply kill the user
   process.

   Page faults are an exception.  Here they are treated the same
   way as other exceptions, but this will need to change to
   implement virtual memory.

   Refer to [IA32-v3a] section 5.15 "Exception and Interrupt
   Reference" for a description of each of these exceptions. */
void
exception_init (void)
{
  /* These exceptions can be raised explicitly by a user program,
     e.g. via the INT, INT3, INTO, and BOUND instructions.  Thus,
     we set DPL==3, meaning that user programs are allowed to
     invoke them via these instructions. */
  intr_register_int (3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
  intr_register_int (4, 3, INTR_ON, kill, "#OF Overflow Exception");
  intr_register_int (5, 3, INTR_ON, kill,
                     "#BR BOUND Range Exceeded Exception");

  /* These exceptions have DPL==0, preventing user processes from
     invoking them via the INT instruction.  They can still be
     caused indirectly, e.g. #DE can be caused by dividing by
     0.  */
  intr_register_int (0, 0, INTR_ON, kill, "#DE Divide Error");
  intr_register_int (1, 0, INTR_ON, kill, "#DB Debug Exception");
  intr_register_int (6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
  intr_register_int (7, 0, INTR_ON, kill,
                     "#NM Device Not Available Exception");
  intr_register_int (11, 0, INTR_ON, kill, "#NP Segment Not Present");
  intr_register_int (12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
  intr_register_int (13, 0, INTR_ON, kill, "#GP General Protection Exception");
  intr_register_int (16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
  intr_register_int (19, 0, INTR_ON, kill,
                     "#XF SIMD Floating-Point Exception");

  /* Most exceptions can be handled with interrupts turned on.
     We need to disable interrupts for page faults because the
     fault address is stored in CR2 and needs to be preserved. */
  intr_register_int (14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

/* Prints exception statistics. */
void
exception_print_stats (void)
{
  printf ("Exception: %lld page faults\n", page_fault_cnt);
}

/* Handler for an exception (probably) caused by a user process. */
static void
kill (struct intr_frame *f)
{
  /* This interrupt is one (probably) caused by a user process.
     For example, the process might have tried to access unmapped
     virtual memory (a page fault).  For now, we simply kill the
     user process.  Later, we'll want to handle page faults in
     the kernel.  Real Unix-like operating systems pass most
     exceptions back to the process via signals, but we don't
     implement them. */

  /* The interrupt frame's code segment value tells us where the
     exception originated. */
  switch (f->cs)
    {
    case SEL_UCSEG:
      /* User's code segment, so it's a user exception, as we
         expected.  Kill the user process.  */
      printf ("%s: dying due to interrupt %#04x (%s).\n",
              thread_name (), f->vec_no, intr_name (f->vec_no));
      intr_dump_frame (f);
      sys_exit (-1); // terminate. no more wait, parent

    case SEL_KCSEG:
      /* Kernel's code segment, which indicates a kernel bug.
         Kernel code shouldn't throw exceptions.  (Page faults
         may cause kernel exceptions--but they shouldn't arrive
         here.)  Panic the kernel to make the point.  */
      intr_dump_frame (f);
      PANIC ("Kernel bug - unexpected interrupt in kernel");

    default:
      /* Some other code segment?  Shouldn't happen.  Panic the
         kernel. */
      printf ("Interrupt %#04x (%s) in unknown segment %04x\n",
             f->vec_no, intr_name (f->vec_no), f->cs);
      sys_exit (-1); // terminate. no more wait, parent
    }
}

/* Page fault handler.  This is a skeleton that must be filled in
   to implement virtual memory.  Some solutions to project 2 may
   also require modifying this code.

   At entry, the address that faulted is in CR2 (Control Register
   2) and information about the fault, formatted as described in
   the PF_* macros in exception.h, is in F's error_code member.  The
   example code here shows how to parse that information.  You
   can find more information about both of these in the
   description of "Interrupt 14--Page Fault Exception (#PF)" in
   [IA32-v3a] section 5.15 "Exception and Interrupt Reference". */
static void
page_fault (struct intr_frame *f)
{
  bool not_present;  /* True: not-present page, false: writing r/o page. */
  bool write;        /* True: access was write, false: access was read. */
  bool user;         /* True: access by user, false: access by kernel. */
  bool isHandled = false;
  void *fault_addr;  /* Fault address. */

  /* Obtain faulting address, the virtual address that was
     accessed to cause the fault.  It may point to code or to
     data.  It is not necessarily the address of the instruction
     that caused the fault (that's f->eip).
     See [IA32-v2a] "MOV--Move to/from Control Registers" and
     [IA32-v3a] 5.15 "Interrupt 14--Page Fault Exception
     (#PF)". */

  asm ("movl %%cr2, %0" : "=r" (fault_addr));
  /* Turn interrupts back on (they were only off so that we could
     be assured of reading CR2 before it changed). */
  intr_enable ();

  /* Count page faults. */
  page_fault_cnt++;

  /* Determine cause. */
  not_present = (f->error_code & PF_P) == 0;
  write = (f->error_code & PF_W) != 0;
  user = (f->error_code & PF_U) != 0;
  bool is_user_page = is_user_vaddr(fault_addr);

  if(user && fault_addr == NULL){
    printf("user try to access NULL.\n");
    sys_exit(-1);
  }
  if(!user && fault_addr == NULL){
    printf("kernel try to access NULL. Should be fixed\n");
    printf("fault addr : %x, eip : %x\n",fault_addr,f->eip);
    kill(f);
  }
  //printf ("Page fault at %p: %s error %s page in %s context.\n",fault_addr,not_present ? "not present" : "rights violation",write ? "writing" : "reading",user ? "user" : "kernel");printf("eip : 0x%x esp : 0x%x eap : 0x%x\n", (uint32_t)f->eip, (uint32_t)f->esp, (uint32_t)f->eax);
  /* (3.1.5) a page fault in the kernel merely sets eax to 0xffffffff
   * and copies its former value into eip */
  struct thread * cur_thre = thread_current();
  uint32_t *pd = cur_thre->pagedir;
  bool is_writable_page =pagedir_is_writable(pd,fault_addr);
  struct vm_entry * found_entry ;//= find_vm_entry_from(cur_thre,fault_addr);
  if(!user && !is_user_page) { // kernel mode
    f->eip = (void *) f->eax;
    f->eax = 0xffffffff;
    return;
  }
  else if(!user && is_user_page){
    printf("unhandled user page at kernel code : no way to recover this because we don't have intr_frame of user. should be fixed\n");
    sys_exit(-1);
  }
  else if(user && fault_addr >= PHYS_BASE){
    sys_exit(-1);
  }
  else if(!not_present && !is_writable_page && write){// instruction (null part) try write pt-write-code2
    sys_exit(-1);
  }
  else if(!(found_entry = find_vm_entry_from(cur_thre,fault_addr))){ //invalid access
    printf("Can't find vm_entry - target_Addr : %x\n",fault_addr);
    kill(f);
  }
  bool alloc_result;
  bool retry_alloc_result;
  bool is_upper_stack = fault_addr >= f->esp -32;
  switch(found_entry->entry_status){
    case PAGE_STACK_SWAPPED:
      isHandled = true;
      break;
    case PAGE_STACK_UNINIT:
      if(is_upper_stack){
        print_entry_info(found_entry);
        alloc_result = vm_handle_stack_alloc(thread_current(),f,fault_addr,1);
        if(alloc_result == false){
          printf("stack_alloc_fail at pagefault_PAGE_STACK_UNINIT\N");
          print_entry_info(found_entry);
          sys_exit(-1);
        }
        isHandled = true;
      }
      break;
    case PAGE_FILE_INDISK:
    case PAGE_FILE_SWAPPED:
      alloc_result =vm_swap_in_page(thread_current(),found_entry);
      if(alloc_result == false){
        vm_swap_out_LRU(thread_current());
        retry_alloc_result = vm_swap_in_page(thread_current(),found_entry);
        if(retry_alloc_result == false){
          print_entry_info(found_entry);
          sys_exit(-1);
        }
      }
      isHandled = true;
      break;
    default:
      printf("unexpected status at page fault\n");
      print_entry_info(found_entry);
      break;
  }

  /*struct vm_entry * target_entry = find_vm_entry_from(thread_current(),fault_addr);
  if(!isHandled && !(target_entry->flags & VF_IsInitial)){
    printf("install new pages");
    bool is_install_success = vm_install_new_page(thread_current(),target_entry);
    if( is_install_success){
        isHandled = true;
    }
  }*/


  if(!isHandled){
    print_entry_info(found_entry);
    printf ("Page fault at %p: %s error %s page in %s context.\n",
            fault_addr,
            not_present ? "not present" : "rights violation",
            write ? "writing" : "reading",
            user ? "user" : "kernel");
    printf("eip : 0x%x esp : 0x%x eap : 0x%x\n", (uint32_t)f->eip, (uint32_t)f->esp, (uint32_t)f->eax);
    kill (f);
  }
  else{
    return;
  }
  /* To implement virtual memory, delete the rest of the function
     body, and replace it with code that brings in the page to
     which fault_addr refers. */
}


