

#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "devices/block.h"
#include "filesys/off_t.h"
#include <hash.h>
#define VF_IsInitial 0x1 //initialize mask
#define VF_IsFile 0x2 //is vm_entry originally from file
#define VF_Write 0x4// is writable.
#define VF_InMemory 0x8


struct swap_pool{
  struct lock * swap_lock;
  struct bitmap * used_map;
  struct block * target_block;
};

struct vm_entry{
    uint32_t vm_address;
    struct hash_elem vm_list_elem;
    char flags;
    //use only when IsFile is false;
    struct swap_pool * stored_swap_pool;
    block_sector_t stored_swap_sector;
    //use only when IsFile is true;
    struct file * swap_file;
    off_t swap_file_offset;
    off_t file_left_size;

};
void vm_swap_init();
bool vm_swap_out_LRU(struct thread * target_thread);
bool vm_swap_out_page(struct thread * target_thread, struct vm_entry * target_entry);
bool vm_swap_in_page(struct thread * target_thread, struct vm_entry * target_entry);



bool vm_handle_stack_alloc(struct thread * target_thread, struct intr_frame *f, uint8_t* addr, uint32_t byte_to_handle);
bool vm_install_new_page(struct thread * target,struct vm_entry * target_entry);
struct vm_entry * find_entry(uint32_t vm_address, struct hash * vm_list);
struct vm_entry * get_new_vm_entry(char , uint32_t );
unsigned vm_hash_func (struct hash_elem *, void *);
bool vm_less_func (struct hash_elem *, struct hash_elem *,void *);
struct vm_entry * find_vm_entry_from(struct thread * target, uint32_t vm_address);
void vm_destroy (struct hash_elem *, void *);
