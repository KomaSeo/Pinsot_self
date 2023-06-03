#include "vm/page.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "threads/interrupt.h"
#include "filesys/file.h"
#include <bitmap.h>
#include "devices/block.h"
#include <hash.h>

static struct swap_pool * page_swap_pool;

void vm_swap_init(){
  page_swap_pool = malloc(sizeof(struct swap_pool));
  struct block * target_block = block_get_role(BLOCK_SWAP);
  block_sector_t target_block_size = block_size(target_block);
  page_swap_pool->target_block = target_block;
  page_swap_pool->used_map = bitmap_create(target_block_size);
}
bool vm_swap_out_LRU(struct thread * target_thread){
  struct hash_elem * iter_elem;
  if(target_thread->vm_LRU_iterator.hash ==NULL){
    hash_first(&target_thread->vm_LRU_iterator,&target_thread->vm_list);
    iter_elem = hash_cur(&target_thread->vm_LRU_iterator);
  }
  else{
    iter_elem = hash_next(&target_thread->vm_LRU_iterator);
  }
  if(iter_elem == NULL){
    hash_first(&target_thread->vm_LRU_iterator,&target_thread->vm_list);
    iter_elem = hash_cur(&target_thread->vm_LRU_iterator);
  }
  while(true){
    struct vm_entry * target_entry = hash_entry(iter_elem,struct vm_entry, vm_list_elem);
    pagedir_is_accessed(target_thread->pagedir,target_entry->vm_address);
    if(target_entry->flags & VF_InMemory){
      if(pagedir_is_accessed(target_thread->pagedir,target_entry->vm_address)){
        pagedir_set_accessed(target_thread->pagedir,target_entry->vm_address,false);
      }
      else{
        return vm_swap_out_page(target_thread,target_entry);
      }
    }
    iter_elem = hash_next(&target_thread->vm_LRU_iterator);
    if(iter_elem == NULL){
      hash_first(&target_thread->vm_LRU_iterator,&target_thread->vm_list);
      iter_elem = hash_cur(&target_thread->vm_LRU_iterator);
    }
  }
  return false;
}
bool vm_swap_out_page(struct thread * target_thread, struct vm_entry * target_entry){
  ASSERT(target_entry->flags & VF_InMemory);
  uint32_t * pd = target_thread->pagedir;
  uint32_t targetAddr = target_entry->vm_address;
  uint32_t * target_paddr = pagedir_get_page(pd,targetAddr);
  if(target_paddr == (uint32_t *)NULL){
    printf("In vm swap out page : finding physical address of target in pagedirectory is failed\n");
    return false;
  }
  struct swap_pool * target_pool = target_entry->stored_swap_pool;
  if(target_entry->flags & !VF_IsFile){
    block_sector_t need_block_size = PGSIZE/ BLOCK_SECTOR_SIZE;
    lock_acquire(target_pool->swap_lock);
    block_sector_t block_index = bitmap_scan_and_flip(target_pool->used_map,0,need_block_size,0);
    lock_release(target_pool->swap_lock);
    if(block_index == BITMAP_ERROR){
      return false;
    }
    else {
      int i;
      for(i = 0; i < need_block_size;i++){
        block_write(target_pool->target_block,block_index + i,targetAddr + BLOCK_SECTOR_SIZE * i);
      }
      target_entry->stored_swap_pool = page_swap_pool;
      target_entry->stored_swap_sector = block_index;
    }
  }
  else {
    if(pagedir_is_dirty(target_thread->pagedir,target_entry->vm_address))
      file_write_at(target_entry->swap_file,target_entry->vm_address,target_entry->file_left_size,target_entry->swap_file_offset);
  }
  pagedir_clear_page(target_thread->pagedir,target_entry->vm_address);
  palloc_free_page(target_paddr);
  target_entry->flags = target_entry->flags & ~VF_InMemory;
  return true;
}

bool vm_swap_in_page(struct thread * target_thread, struct vm_entry * target_entry){
  ASSERT(target_entry->flags & !VF_InMemory);
  uint8_t * vpage = palloc_get_page(PAL_USER|PAL_ZERO);
  if(vpage == NULL){
    return false;
  }
  if(target_entry->flags & !VF_IsFile){
    struct swap_pool * target_pool = target_entry->stored_swap_pool;
    block_sector_t target_block_sector = target_entry->stored_swap_sector;
    struct block * target_block = target_pool->target_block;
    block_read(target_block,target_block_sector,vpage);
    block_read(target_block,target_block_sector+1,vpage+BLOCK_SECTOR_SIZE);
    lock_acquire(target_pool->swap_lock);
    bitmap_set_multiple(target_pool->used_map,target_block_sector,2,0);
    lock_release(target_pool->swap_lock);
  }
  else{
    file_read_at(target_entry->swap_file,vpage,target_entry->file_left_size,target_entry->swap_file_offset);
  }
  pagedir_set_page(target_thread->pagedir,target_entry->vm_address,vpage,target_entry->flags & VF_Write);
  target_entry->flags = target_entry->flags | VF_InMemory;
}












/* above is region for swap handling*/
bool vm_handle_stack_alloc(struct thread * target_thread, struct intr_frame *f, uint8_t* addr, uint32_t byte_to_handle){
  if(pg_round_down(addr)==NULL){
    return false;
  }
  uint8_t* target_addr = pg_round_down(addr);
  uint8_t* max_addr = pg_round_down(addr + byte_to_handle);
  while(target_addr <= max_addr){
    struct vm_entry * found_entry = find_vm_entry_from(target_thread,target_addr);
    if(found_entry == NULL){
      return false;
    }
    bool is_page_initialize = found_entry->flags&VF_IsInitial;
    bool is_upper_stack  = (target_addr >= (f->esp - 32));
    bool is_stack_need = !is_page_initialize && is_upper_stack;
    bool is_page_inMem = found_entry->flags & VF_InMemory;
    if(is_page_inMem){
      //do notiong;
    }
    else if(is_stack_need){
      vm_install_new_page(target_thread,found_entry);
    }
    else{
      return false;
    }
    target_addr += PGSIZE;
  }
  return true;
}

bool vm_install_new_page(struct thread * target,struct vm_entry * target_entry){
    ASSERT(target_entry != (void *)NULL);
    ASSERT(target_entry->vm_address != NULL);
    ASSERT(!(target_entry->flags & VF_IsInitial));
    uint8_t* vm_Address = (uint8_t*)target_entry->vm_address;
    void* new_page = palloc_get_page(PAL_USER|PAL_ZERO);
    bool getResult = pagedir_get_page (target->pagedir, vm_Address) == NULL;
    bool setResult = false;
    if(getResult){
      setResult = pagedir_set_page (target->pagedir, vm_Address, new_page, !!(target_entry->flags&VF_Write));
    }
    if(setResult){
      target_entry->flags = target_entry->flags | VF_IsInitial | VF_InMemory;
    }
    return getResult && setResult;
}

void add_new_vm_entry_at(struct thread * target, char flags, uint32_t vm_address){
    struct vm_entry * new_entry = get_new_vm_entry(flags, vm_address);
    struct hash* vm = &target->vm_list;
    hash_insert(vm, &new_entry->vm_list_elem);
    return;
}

struct vm_entry * get_new_vm_entry(char flags, uint32_t vm_address){
    uint32_t maskedAddress = (uint32_t)pg_round_down(vm_address);
    ASSERT(maskedAddress != NULL);
    struct vm_entry * entry = malloc(sizeof(struct vm_entry));
    ASSERT(entry);
    if(entry == (struct vm_entry*)NULL){
      return entry;
    }
    entry->flags = flags;
    entry->vm_address = maskedAddress;
    return entry;
}
struct vm_entry * find_vm_entry_from(struct thread * target, uint32_t vm_address){
  struct hash* vm = &target->vm_list;
  struct vm_entry * found_entry = find_entry(vm_address,vm);
  return found_entry;
}
struct vm_entry * find_entry(uint32_t vm_address, struct hash * vm_list){
  if(vm_address == NULL){
    return NULL;
  }
  struct vm_entry * dummy_entry = get_new_vm_entry((char)0, vm_address);//hash consider two element as same when hash result is same.
  struct hash_elem* found_elem = hash_find(vm_list, &dummy_entry->vm_list_elem);
  if(!found_elem){
    return NULL;
  }
  struct vm_entry * found_entry = hash_entry(found_elem,struct vm_entry, vm_list_elem);
  free(dummy_entry);
  return found_entry;
}
void vm_destroy(struct hash_elem *e, void * aux UNUSED){
    struct vm_entry * target = hash_entry(e, struct vm_entry, vm_list_elem);
    /*if(target->flags & VF_InMemory){
      palloc_free_page(pagedir_get_page(thread_current()->pagedir, target->vm_address));
      pagedir_clear_page(thread_current()->pagedir, target->vm_address);
    }*/
    free(target);
}
unsigned vm_hash_func (struct hash_elem *e, void *aux UNUSED){
    struct vm_entry * target = hash_entry(e, struct vm_entry, vm_list_elem);
    return hash_int(target-> vm_address);
}

bool vm_less_func (struct hash_elem *a, struct hash_elem *b,void *aux UNUSED){
    struct vm_entry * A = hash_entry(a, struct vm_entry, vm_list_elem);
    struct vm_entry * B = hash_entry(b, struct vm_entry, vm_list_elem);
    return A->vm_address < B->vm_address;
}
