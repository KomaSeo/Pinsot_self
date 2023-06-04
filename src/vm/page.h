

#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "devices/block.h"
#include "filesys/off_t.h"
#include <hash.h>
enum page_status {
  PAGE_STACK_UNINIT,
  PAGE_STACK_INMEM,
  PAGE_STACK_SWAPPED,
  PAGE_FILE_INDISK,
  PAGE_FILE_INMEM,
  PAGE_FILE_SWAPPED,
  PAGE_UNEXPECTED
};


struct swap_pool{
  struct lock swap_lock;
  struct bitmap * used_map;
  struct block * target_block;
};

struct vm_entry{
    uint32_t vm_address;
    struct hash_elem vm_list_elem;
    enum page_status entry_status;
    //use only when IsFile is false;
    struct swap_pool * stored_swap_pool;
    block_sector_t stored_swap_sector;
    //use only when IsFile is true;
    struct file * swap_file;
    off_t swap_file_offset;
    off_t file_left_size;
    bool is_file_writable;

};
bool vm_swap_out_LRU_Global();
void vm_swap_init();
bool vm_swap_out_LRU(struct thread * target_thread);
bool vm_swap_out_page(struct thread * target_thread, struct vm_entry * target_entry);
bool vm_swap_in_page(struct thread * target_thread, struct vm_entry * target_entry);



struct vm_entry * add_new_vm_entry_at(struct thread * target, enum page_status status, uint32_t vm_address);
bool vm_handle_syscall_alloc(struct thread * target_thread, struct intr_frame *f, uint8_t* addr, uint32_t byte_to_handle);
bool vm_install_new_stack(struct thread * target,struct vm_entry * target_entry);
struct vm_entry * find_entry(uint32_t vm_address, struct hash * vm_list);
struct vm_entry * get_new_vm_entry(enum page_status , uint32_t );
unsigned vm_hash_func (struct hash_elem *, void *);
bool vm_less_func (struct hash_elem *, struct hash_elem *,void *);
struct vm_entry * find_vm_entry_from(struct thread * target, uint32_t vm_address);
void vm_destroy (struct hash_elem *, void *);
