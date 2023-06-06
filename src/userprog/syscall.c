#include "devices/shutdown.h"
#include "devices/input.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/palloc.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "lib/kernel/list.h"
#include "vm/page.h"

#define STDIN 0
#define STDOUT 1
#define STDERR 2


static struct lock mmap_lock;
static struct list mmap_list;

struct mmap_entry{
  int mapid;
  uint32_t vm_address;
  size_t mmap_size;
  struct list_elem mmap_elem;
  struct thread * mmap_thread;
  int fd;
};


static void syscall_handler (struct intr_frame *);

static void check_user (const uint8_t *uaddr);
static int32_t get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
static int memread_user (void *src, void *des, size_t bytes);

static struct file_desc* find_file_desc(struct thread *, int fd);

void sys_halt (void);
void sys_exit (int);
pid_t sys_exec (const char *cmdline);
int sys_wait (pid_t pid);

bool sys_create(const char* filename, unsigned initial_size);
bool sys_remove(const char* filename);
int sys_open(const char* file);
int sys_filesize(int fd);
void sys_seek(int fd, unsigned position);
unsigned sys_tell(int fd);
void sys_close(int fd);
int sys_read(int fd, void *buffer, unsigned size);
int sys_write(int fd, const void *buffer, unsigned size);
int sys_mmap(int fd, void * addr);
void sys_munmap(int mapping);

static struct mmap_entry * find_mmap_entry(int mapid,struct thread * target_thread);
static struct mmap_entry * find_mmap_entry_by_FD(int fd, struct thread * target_thread);
static void swap_out_every_mmap_for_cur_thread();
static int allocate_mapid_t (void);

struct lock filesys_lock;

void
syscall_init (void)
{
  lock_init (&filesys_lock);
  lock_init (&mmap_lock);
  list_init (&mmap_list);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

// in case of invalid memory access, fail and exit.
static void fail_invalid_access(void) {
  if (lock_held_by_current_thread(&filesys_lock))
    lock_release (&filesys_lock);

  sys_exit (-1);
  NOT_REACHED();
}

static void
syscall_handler (struct intr_frame *f)
{
  int syscall_number;
  int intsize = 4;
  int ptrsize = 4;
  int fd;
  ASSERT( sizeof(syscall_number) == 4 ); // assuming x86

  // The system call number is in the 32-bit word at the caller's stack pointer.
  memread_user(f->esp, &syscall_number, intsize);


  // Dispatch w.r.t system call number
  // SYS_*** constants are defined in syscall-nr.h
  switch (syscall_number) {
  case SYS_HALT: // 0
    {
      sys_halt();
      NOT_REACHED();
      break;
    }

  case SYS_EXIT: // 1
    {
      int exitcode;
      memread_user(f->esp + 4, &exitcode, intsize);

      sys_exit(exitcode);
      NOT_REACHED();
      break;
    }

  case SYS_EXEC: // 2
    {
      void* cmdline;
	    memread_user(f->esp + 4, &cmdline, ptrsize);

      uint32_t return_code = sys_exec((const char*) cmdline);
      f->eax = return_code;
      break;
    }

  case SYS_WAIT: // 3
    {
      pid_t pid;
  	  memread_user(f->esp + 4, &pid, sizeof(pid));

      uint32_t return_code = sys_wait(pid);
      f->eax = return_code;
      break;
    }

  case SYS_CREATE: // 4
    {
      const char* filename;
      unsigned initial_size;
      bool return_code;
	    int sizek = sizeof(initial_size);
      memread_user(f->esp + 4, &filename, ptrsize);
      memread_user(f->esp + 8, &initial_size, sizek);

      return_code = sys_create(filename, initial_size);
      f->eax = return_code;
      break;
    }

  case SYS_REMOVE: // 5
    {
      const char* filename;
      bool return_code;
      memread_user(f->esp + 4, &filename, ptrsize);

      return_code = sys_remove(filename);
      f->eax = return_code;
      break;
    }

  case SYS_OPEN: // 6
    {
      const char* filename;
      int return_code;

      memread_user(f->esp + 4, &filename,ptrsize);

      return_code = sys_open(filename);
      f->eax = return_code;
      break;
    }

  case SYS_FILESIZE: // 7
    {
      int return_code;
      memread_user(f->esp + 4, &fd, intsize);

      return_code = sys_filesize(fd);
      f->eax = return_code;
      break;
    }

  case SYS_READ: // 8
    {
      uint32_t return_code;
      void *buffer;
      unsigned size;
	    int sizek =sizeof(size);
      memread_user(f->esp + 4, &fd, intsize);
      memread_user(f->esp + 8, &buffer, ptrsize);
      memread_user(f->esp + 12, &size, sizek);
      bool handle_result = vm_handle_syscall_alloc(thread_current(),f,buffer,size);
      if(!handle_result){
        sys_exit(-1);
      }

      return_code = sys_read(fd, buffer, size);
      f->eax = return_code;
      break;
    }

  case SYS_WRITE: // 9
    {
      uint32_t return_code;
      const void *buffer;
      unsigned size;
	    int sizek2 = sizeof(buffer);
	    int sizek = sizeof(size);
      memread_user(f->esp + 4, &fd, intsize);
      memread_user(f->esp + 8, &buffer, sizek2);
      memread_user(f->esp + 12, &size, sizek);

      return_code = sys_write(fd, buffer, size);
      f->eax = return_code;
      break;
    }

  case SYS_SEEK: // 10
    {
      unsigned position;
	    int sizek = sizeof(position);
      memread_user(f->esp + 4, &fd, intsize);
      memread_user(f->esp + 8, &position, sizek);

      sys_seek(fd, position);
      break;
    }

  case SYS_TELL: // 11
    {
      uint32_t return_code;

      memread_user(f->esp + 4, &fd, intsize);

      return_code = sys_tell(fd);
      f->eax = return_code;
      break;
    }

  case SYS_CLOSE: // 12
    {
      memread_user(f->esp + 4, &fd, intsize);

      sys_close(fd);
      break;
    }
  case SYS_MMAP:
    {
      int fd;
      void *addr;
      memread_user(f->esp+4, &fd, intsize);
      memread_user(f->esp+8, &addr, ptrsize);
      f->eax = sys_mmap(fd,addr);
      break;
    }
  case SYS_MUNMAP:
    {
      int mapping;
      memread_user(f->esp+4, &mapping, intsize);
      sys_munmap(mapping);
      break;
    }
  /* unhandled case */
  default:
    printf("[ERROR!] system call %d is unimplemented!\n", syscall_number);
    // ensure that waiting (parent) process should wake up and terminate.
    sys_exit(-1);
    break;
  }

}

/****************** System Call Implementations ********************/

void sys_halt(void) {
  shutdown_power_off();
}

void sys_exit(int status) {
  struct thread *current = thread_current ();
  printf("%s: exit(%d)\n", current->name, status);
  swap_out_every_mmap_for_cur_thread();
  struct process_control_block *pcb = current->pcb;
  if(pcb != NULL) {
    pcb->exited = 1;
    pcb->exitcode = status;
  }

  thread_exit();
}

pid_t sys_exec(const char *cmdline) {
  const uint8_t* cmd = (const uint8_t*) cmdline;
  check_user(cmd);

  lock_acquire (&filesys_lock); // load() uses filesystem
  pid_t pid = process_execute(cmdline);
  lock_release (&filesys_lock);
  return pid;
}

int sys_wait(pid_t pid) {
  return process_wait(pid);
}

bool sys_create(const char* filename, unsigned initial_size) {
  if(filename == NULL){
    sys_exit(-1);
  }
  bool return_code;
  const uint8_t* file = (const uint8_t*)filename;
  check_user(file);

  lock_acquire (&filesys_lock);
  return_code = filesys_create(filename, initial_size);
  lock_release (&filesys_lock);
  return return_code;
}

bool sys_remove(const char* filename) {
  bool return_code;
  const uint8_t* file = (const uint8_t*)filename;
  check_user(file);

  lock_acquire (&filesys_lock);
  return_code = filesys_remove(filename);
  lock_release (&filesys_lock);
  return return_code;
}

int sys_open(const char* file) {
  check_user((const uint8_t*) file);
  if(file == NULL){
    sys_exit(-1);
  }

  struct file* file_opened;
  struct file_desc* fd = palloc_get_page(0);
  if (!fd) {
    return -1;
  }

  lock_acquire (&filesys_lock);
  file_opened = filesys_open(file);
  if (!file_opened) {
    palloc_free_page (fd);
    lock_release (&filesys_lock);
    return -1;
  }

  fd->file = file_opened; //file save
  struct thread *current = thread_current();
  struct list* fd_list = &current->file_descriptors;
  struct thread *back;
  bool empty = list_empty(fd_list);
  if ( empty ) fd->id = 3;
  else {
	fd->id = (list_entry(list_back(fd_list),struct file_desc, elem)->id)+1;
	//fd->id = (back->id) + 1;
  }
  list_push_back(fd_list, &(fd->elem));

  lock_release (&filesys_lock);
  return fd->id;
}

int sys_filesize(int fd) {
  struct file_desc* file_d;

  lock_acquire (&filesys_lock);
  file_d = find_file_desc(thread_current(), fd);

  if(file_d == NULL) {
    lock_release (&filesys_lock);
    return -1;
  }

  int ret = file_length(file_d->file);
  lock_release (&filesys_lock);
  return ret;
}

void sys_seek(int fd, unsigned position) {
  lock_acquire (&filesys_lock);
  struct file_desc* file_d = find_file_desc(thread_current(), fd);

  if(file_d && file_d->file) {
    file_seek(file_d->file, position);
  }
  else
    return;

  lock_release (&filesys_lock);
}

unsigned sys_tell(int fd) {
  lock_acquire (&filesys_lock);
  struct file_desc* file_d = find_file_desc(thread_current(), fd);

  unsigned ret;
  if(file_d && file_d->file) {
    ret = file_tell(file_d->file);
  }
  else
    ret = -1;

  lock_release (&filesys_lock);
  return ret;
}

void sys_close(int fd) {
  lock_acquire (&filesys_lock);
  struct file_desc* file_d = find_file_desc(thread_current(), fd);
  struct mmap_entry * swap_target_entry = find_mmap_entry_by_FD(fd,thread_current());
  if(swap_target_entry){
    struct vm_entry * swap_target_vm_entry = find_vm_entry_from(thread_current(), swap_target_entry->vm_address);
    ASSERT(swap_target_vm_entry);
    if(!is_entry_inmem(swap_target_vm_entry)){
      vm_swap_in_page(thread_current(),swap_target_vm_entry);
    }
  }

  if(file_d && file_d->file) {
    file_close(file_d->file);
    list_remove(&(file_d->elem));
    palloc_free_page(file_d);
  }
  lock_release (&filesys_lock);
}

int sys_read(int fd, void *buffer, unsigned size) {
  check_user((const uint8_t*) buffer);
  check_user((const uint8_t*) buffer + size - 1);

  lock_acquire (&filesys_lock);
  int ret;

  if(fd == STDIN) {
    int i;
    for(i = 0; i < size; ++i) {
      if(! put_user(buffer + i, input_getc()) ) {
        lock_release (&filesys_lock);
        sys_exit(-1); // segfault
      }
    }
    ret = size;
  }
  else {
    // read from file
    struct file_desc* file_d = find_file_desc(thread_current(), fd);

    if(file_d && file_d->file) {
      ret = file_read(file_d->file, buffer, size);
    }
    else // no such file or can't open
      ret = -1;
  }

  lock_release (&filesys_lock);
  return ret;
}

int sys_write(int fd, const void *buffer, unsigned size) {
  check_user((const uint8_t*) buffer);
  check_user((const uint8_t*) buffer + size - 1);

  lock_acquire (&filesys_lock);
  int ret;

  if(fd == STDOUT) { // write to stdout
    putbuf(buffer, size);
    ret = size;
  }
  else {
    // write into file
    struct file_desc* file_d = find_file_desc(thread_current(), fd);

    if(file_d && file_d->file) {
      ret = file_write(file_d->file, buffer, size);
    }
    else // no such file or can't open
      ret = -1;
  }

  lock_release (&filesys_lock);
  return ret;
}

void print_mmap_entry_info(struct mmap_entry * mmap){
  printf("------mmap info ------\n");
  printf("|mapid : %d\n",mmap->mapid);
  printf("|mapped size : %d\n",mmap->mmap_size);
  printf("|mapped_vm_addrss : %x\n",mmap->vm_address);
  printf("|fd : %x\n",mmap->fd);
  printf("|thread_name : %x\n",mmap->mmap_thread->name);
}

int sys_mmap(int fd, void * addr){
  struct thread * current_thread = thread_current();
  struct list * fd_list = &current_thread->file_descriptors;
  if(fd <3){
    return -1;
  }
  if(!addr || addr >= PHYS_BASE){
    return -1;
  }
  if(!(addr == pg_round_down(addr))){
    return -1;
  }
  struct file_desc * target_file_desc = find_file_desc(current_thread,fd);
  if(!target_file_desc){
    return -1;
  }

  size_t size_of_file = file_length(target_file_desc->file);
  size_t left_size = size_of_file;
  size_t written_file_size = 0;
  if(size_of_file == 0){
    return -1;
  }

  void * target_addr = addr;
  while(left_size > 0){
    struct vm_entry * found_entry = find_vm_entry_from(current_thread,target_addr);
    if(found_entry || target_addr >= PHYS_BASE - MAX_STACK_SIZE){
      return -1;
    }
    struct vm_entry * target_entry = add_new_vm_entry_at(current_thread,PAGE_MMAP_INDISK,target_addr);
    size_t current_page_write_size = left_size > PGSIZE ? PGSIZE : left_size;
    target_entry->file_left_size = current_page_write_size;
    target_entry->swap_file = target_file_desc->file;
    target_entry->swap_file_offset = written_file_size;

    target_addr += PGSIZE;
    left_size -= current_page_write_size;
    written_file_size -= current_page_write_size;
  }
  struct mmap_entry * map_target_entry = malloc(sizeof(struct mmap_entry));
  map_target_entry->mapid = allocate_mapid_t();
  map_target_entry->mmap_size = size_of_file;
  map_target_entry->vm_address = addr;
  map_target_entry->mmap_thread = current_thread;
  map_target_entry->fd = fd;
  list_push_front(&mmap_list,&map_target_entry->mmap_elem);
  return map_target_entry->mapid;
}

void sys_munmap(int mapping){
  struct mmap_entry * found_mmap_entry = find_mmap_entry(mapping, thread_current());
  if(!found_mmap_entry){
    sys_exit(-1);
  }
  struct thread * current = thread_current();
  size_t mmap_size = found_mmap_entry->mmap_size;
  size_t left_size = mmap_size;
  void * target_addr = (void *)found_mmap_entry->vm_address;
  while(left_size > 0){
    struct vm_entry * found_vm_entry = find_vm_entry_from(current,target_addr);
    if(!found_vm_entry){
      printf("MUMMAP failed\n");
      sys_exit(-1);
    }
    if(is_entry_inmem(found_vm_entry)){
      vm_swap_out_page(current,found_vm_entry);
    }
    hash_delete(&current->vm_list,&found_vm_entry->vm_list_elem);
    vm_destroy(&found_vm_entry->vm_list_elem,NULL);
    hash_first(&current->vm_LRU_iterator,&current->vm_list);
    target_addr += PGSIZE;
    left_size -= left_size > PGSIZE ? PGSIZE : left_size;
  }
  list_remove(&found_mmap_entry->mmap_elem);
}



/****************** Helper Functions on Memory Access ********************/


static void
check_user (const uint8_t *uaddr) {
  // check uaddr range or segfaults
  int32_t result = get_user(uaddr);
  if( result  == -1)
  	fail_invalid_access();
}

static int32_t
get_user (const uint8_t *uaddr) {
  int result;
  if (! ((void*)uaddr < PHYS_BASE)) {
      result = -1;
	  return result;
  }

  asm ("movl $1f, %0; movzbl %1, %0; 1:"
      : "=&a" (result) : "m" (*uaddr));
  return result;
}

static bool
put_user (uint8_t *udst, uint8_t byte) {
  if (! ((void*)udst < PHYS_BASE)) {
    return 0;
  }

  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
      : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  bool result = (error_code != -1);
  return result;
}
static int
memread_user (void *src, void *dst, size_t bytes)
{
  int32_t value;
  size_t i,t;
  for(i=0; i<bytes; i++) {
    t = src+i;
    value = get_user(t);
    if(value != -1) {
		*(char*)(dst + i) = value & 0xff;
	}
	else{
		fail_invalid_access();
	}
  }
  return (int)bytes;
}

/****** Helper Function on File Access ********************/

static struct file_desc*
find_file_desc(struct thread *t, int fd)
{
  ASSERT (t != NULL);

  if (fd < 3) {
    return NULL;
  }


  bool empty = list_empty(&t -> file_descriptors);
  if (!empty) {
    struct list_elem *e = list_begin(&t->file_descriptors);
    for(e;e != list_end(&t->file_descriptors); e = list_next(e))
    {
      struct file_desc *desc = list_entry(e, struct file_desc, elem);
      if(desc->id == fd) {
        return desc;
      }
    }
  }
  return NULL;
}
static struct mmap_entry * find_mmap_entry(int mapid,struct thread * target_thread){
  bool empty = list_empty(&mmap_list);
  if (!empty){
    struct list_elem *e  = list_begin(&mmap_list);
    for(e; e!= list_end(&mmap_list); e = list_next(e)){
      struct mmap_entry * finding_entry = list_entry(e, struct mmap_entry, mmap_elem);
      if(finding_entry->mapid == mapid && finding_entry->mmap_thread == target_thread){
        return finding_entry;
      }
    }
  }
  return NULL;
}
static struct mmap_entry * find_mmap_entry_by_FD(int fd, struct thread * target_thread){
  bool empty = list_empty(&mmap_list);
  if (!empty){
    struct list_elem *e  = list_begin(&mmap_list);
    for(e; e!= list_end(&mmap_list); e = list_next(e)){
      struct mmap_entry * finding_entry = list_entry(e, struct mmap_entry, mmap_elem);
      if(finding_entry->fd == fd && finding_entry->mmap_thread == target_thread){
        return finding_entry;
      }
    }
  }
  return NULL;
}
static void swap_out_every_mmap_for_cur_thread(){
  struct thread * target_thread = thread_current();
  bool empty = list_empty(&mmap_list);
  if (!empty){
    struct list_elem *e  = list_begin(&mmap_list);
    for(e; e!= list_end(&mmap_list); e = list_next(e)){
      struct mmap_entry * finding_entry = list_entry(e, struct mmap_entry, mmap_elem);
      if(finding_entry->mmap_thread == target_thread){
        sys_munmap(finding_entry->mapid);
      }
    }
  }
  return;

}
/******** Helper Function on MMAP*****************************/
static int
allocate_mapid_t (void)
{
  static int next_mapid_t = 1;
  int mapid_t;

  lock_acquire (&mmap_lock);
  mapid_t = next_mapid_t++;
  lock_release (&mmap_lock);

  return mapid_t;
}

