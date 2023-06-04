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
bool is_status_inmem(enum page_status);
bool is_status_file(enum page_status);
bool is_status_inblock(enum page_status);
bool is_entry_inmem(struct vm_entry *);
bool is_entry_file(struct vm_entry *);
bool is_entry_inblock(struct vm_entry *);

bool is_status_inmem(enum page_status status){
  return status == PAGE_FILE_INMEM||status == PAGE_STACK_INMEM;
}
bool is_entry_inmem(struct vm_entry * entry){
  return is_status_inmem(entry->entry_status);
}
bool is_status_file(enum page_status status){
  return status == PAGE_FILE_INDISK|| status == PAGE_FILE_INMEM;
}
bool is_entry_file(struct vm_entry * entry){
  return is_status_file(entry->entry_status);
}
bool is_status_inblock(enum page_status status){
  return status == PAGE_STACK_SWAPPED|| status == PAGE_FILE_INDISK || status == PAGE_FILE_SWAPPED;
}
bool is_entry_inblock(struct vm_entry * entry){
  return is_status_inblock(entry->entry_status);
}
void print_status(enum page_status status){
  char * _str;
  switch(status){
    case PAGE_FILE_INDISK:
      _str = "PAGE_FILE_INDISK";
      break;
    case PAGE_FILE_INMEM:
      _str = "PAGE_FILE_INMEM";
      break;
    case PAGE_FILE_SWAPPED:
      _str = "PAGE_FILE_SWAPPED";
      break;
    case PAGE_STACK_INMEM:
      _str = "PAGE_STACK_INMEM";
      break;
    case PAGE_STACK_SWAPPED:
      _str = "PAGE_STACK_SWAPPED";
      break;
    case PAGE_STACK_UNINIT:
      _str = "PAGE_STACK_UNINIT";
      break;
    default:
      _str = "unexpected state";
      break;
  }
  printf("status : %s, %d\n", _str, status);
}
void print_entry_info(struct vm_entry * entry){
  printf("-----ENTRY_INFO -----\n");
  printf("|entry_address : %x\n",entry->vm_address);
  print_status(entry->entry_status);

  printf("|entry_stored_pool : %x\n",entry->stored_swap_pool);
  printf("|entry_stored_sector : %d\n", entry->stored_swap_sector);

  printf("|swap file : %x\n",entry->swap_file);
  printf("|swap file offset : %d\n",entry->swap_file_offset);
  printf("|file left size : %d\n",entry->file_left_size);
  printf("|is file writable : %d\n",entry->is_file_writable);
}





void vm_swap_init(){//should be called lazily
  if(page_swap_pool == NULL){
    page_swap_pool = malloc(sizeof(struct swap_pool));
    struct block * target_block = block_get_role(BLOCK_SWAP);
    if(target_block == NULL){
      struct block * find_block = block_first();
      while(target_block == NULL){
        if(block_type(find_block) == BLOCK_SWAP){
          block_set_role(BLOCK_SWAP,find_block);
          target_block = find_block;
        }
        else{
          find_block = block_next(find_block);
        }
      }
    }
    ASSERT(target_block);
    block_set_role(BLOCK_SWAP,target_block);
    block_sector_t target_block_size = block_size(target_block);
    page_swap_pool->target_block = target_block;
    page_swap_pool->used_map = bitmap_create(target_block_size);
    lock_init(&page_swap_pool->swap_lock);
  }
}

bool vm_swap_out_LRU_Global(){
    struct list_elem *e;
    for (e = list_begin (&all_list); e != list_end (&all_list);e = list_next (e)){
      struct thread *target_thread = list_entry (e, struct thread, allelem);
      if(vm_swap_out_LRU(target_thread)){
        return true;
      }
    }
    return false;
}

bool vm_swap_out_LRU(struct thread * target_thread){
  struct hash_elem * iter_elem;
  if(hash_size(&target_thread->vm_list) == 0){
    return false;
  }
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
  int roll_index = 0;
  while(roll_index < 2){
    struct vm_entry * target_entry = hash_entry(iter_elem,struct vm_entry, vm_list_elem);
    if(is_entry_inmem(target_entry)){
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
      roll_index += 1;
    }
  }
  return false;
}
bool vm_swap_out_page(struct thread * target_thread, struct vm_entry * target_entry){
  ASSERT(is_entry_inmem(target_entry));
  uint32_t * pd = target_thread->pagedir;
  uint32_t targetAddr = target_entry->vm_address;
  uint32_t * target_paddr = pagedir_get_page(pd,targetAddr);
  if(target_paddr == (uint32_t *)NULL){
    printf("In vm swap out page : finding physical address of target in pagedirectory is failed\n");
    return false;
  }
  ASSERT(target_entry);
  struct swap_pool * target_pool = NULL;
  switch(target_entry->entry_status){
    case PAGE_STACK_INMEM:
      vm_swap_init();
      target_pool = page_swap_pool;
      ASSERT(target_pool);
      block_sector_t need_block_size = PGSIZE/ BLOCK_SECTOR_SIZE;
      lock_acquire(&target_pool->swap_lock);
      block_sector_t block_index = bitmap_scan_and_flip(target_pool->used_map,0,need_block_size,0);
      lock_release(&target_pool->swap_lock);
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
      target_entry->entry_status = PAGE_STACK_SWAPPED;
      break;
    case PAGE_FILE_INMEM:
      if(target_entry->is_file_writable){
        vm_swap_init();
        target_pool = page_swap_pool;
        block_sector_t need_block_size = PGSIZE/ BLOCK_SECTOR_SIZE;
        lock_acquire(&target_pool->swap_lock);
        block_sector_t block_index = bitmap_scan_and_flip(target_pool->used_map,0,need_block_size,0);
        lock_release(&target_pool->swap_lock);
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
        target_entry->entry_status = PAGE_FILE_SWAPPED;
      }
      else{
        target_entry->entry_status = PAGE_FILE_INDISK;
      }
      break;
    default:
     printf("unexpected entry status at swap out- ");
     print_status(target_entry->entry_status);
     return false;
     break;

  }
  pagedir_clear_page(target_thread->pagedir,target_entry->vm_address);
  palloc_free_page(target_paddr);
  return true;
}

bool vm_swap_in_page(struct thread * target_thread, struct vm_entry * target_entry){
  ASSERT(is_entry_inblock(target_entry));//assert target entry is anon entry that once loaded or it came from file.
  uint8_t * ppage = palloc_get_page(PAL_USER|PAL_ZERO);
  if(ppage == NULL){
    return false;
  }

  bool writable;
  int need_block_size = PGSIZE/BLOCK_SECTOR_SIZE;
  switch(target_entry->entry_status){
    case PAGE_FILE_INDISK:{
      size_t read_length = file_read_at(target_entry->swap_file,ppage,target_entry->file_left_size,target_entry->swap_file_offset);
      ASSERT(read_length == target_entry->file_left_size);
      size_t page_zero_bytes = PGSIZE - target_entry->file_left_size;
      memset (ppage + target_entry->file_left_size, 0, page_zero_bytes);
      target_entry->entry_status = PAGE_FILE_INMEM;
      writable = target_entry->is_file_writable;
      break;
    }
    case PAGE_FILE_SWAPPED:{
      struct swap_pool * target_pool = target_entry->stored_swap_pool;
      block_sector_t target_block_sector = target_entry->stored_swap_sector;
      struct block * target_block = target_pool->target_block;
      int i = 0;
      for(i = 0; i < need_block_size; i ++){
        block_read(target_block,target_block_sector + i, ppage+BLOCK_SECTOR_SIZE * i);
      }
      lock_acquire(&target_pool->swap_lock);
      int need_block_size = PGSIZE/BLOCK_SECTOR_SIZE;
      bitmap_set_multiple(target_pool->used_map,target_block_sector,need_block_size,0);
      lock_release(&target_pool->swap_lock);
      target_entry->entry_status = PAGE_FILE_INMEM;
      writable = target_entry->is_file_writable;
      break;
    }
    case PAGE_STACK_SWAPPED:{
      struct swap_pool * target_pool = target_entry->stored_swap_pool;
      block_sector_t target_block_sector = target_entry->stored_swap_sector;
      struct block * target_block = target_pool->target_block;
      int i = 0;
      for(i = 0; i < need_block_size; i ++){
        block_read(target_block,target_block_sector + i, ppage+BLOCK_SECTOR_SIZE * i);
      }
      lock_acquire(&target_pool->swap_lock);
      int need_block_size = PGSIZE/BLOCK_SECTOR_SIZE;
      bitmap_set_multiple(target_pool->used_map,target_block_sector,need_block_size,0);
      lock_release(&target_pool->swap_lock);
      target_entry->entry_status = PAGE_STACK_INMEM;
      writable = true;
      break;
    }
    default:
      printf("unexpected state at swap_in\n");
      return false;
      break;
  }
      pagedir_set_page(target_thread->pagedir,target_entry->vm_address,ppage,writable);
  return true;
}












/* above is region for swap handling*/
bool vm_handle_stack_alloc(struct thread * target_thread, struct intr_frame *f, uint8_t* addr, uint32_t byte_to_handle){//TODO need to imple auto swap out, swap in.
  if(pg_round_down(addr)==NULL){
    printf("vm_handle_stack_alloc_failed: reason - passed address is NULL, which is not stack address\n");
    return false;
  }
  uint8_t* target_addr = pg_round_down(addr);
  uint8_t* max_addr = pg_round_down(addr + byte_to_handle-1);
  while(target_addr <= max_addr){
    struct vm_entry * found_entry = find_vm_entry_from(target_thread,target_addr);
    if(found_entry == NULL){
      printf("vm_handle_stack_alloc_failed: reason - cannot find vm_entry from vm_list : addr - %x",addr);
      return false;
    }
    switch(found_entry->entry_status){
      case PAGE_STACK_UNINIT:{
        bool is_upper_stack  = (addr >= (f->esp - 32));
        if(is_upper_stack){
          vm_install_new_stack(target_thread,found_entry);
        }
        else{
          return false;
        }
        break;
      }
      case PAGE_STACK_SWAPPED:
        vm_swap_in_page(target_thread,found_entry);
        break;
      case PAGE_STACK_INMEM:
        break;
      default:
        return false;
        break;
    }
    target_addr += PGSIZE;
  }
  return true;
}

bool vm_install_new_stack(struct thread * target,struct vm_entry * target_entry){
    ASSERT(target_entry != (void *)NULL);
    ASSERT(target_entry->entry_status == PAGE_STACK_UNINIT);
    uint8_t* vm_Address = (uint8_t*)target_entry->vm_address;
    void* new_page = palloc_get_page(PAL_USER|PAL_ZERO);
    bool getResult = pagedir_get_page (target->pagedir, vm_Address) == NULL;
    bool setResult = false;
    if(getResult){
      setResult = pagedir_set_page (target->pagedir, vm_Address, new_page, true);
    }
    if(setResult){
      target_entry->entry_status = PAGE_STACK_INMEM;
    }
    return getResult && setResult;
}

struct vm_entry * add_new_vm_entry_at(struct thread * target, enum page_status status, uint32_t vm_address){
    struct vm_entry * new_entry = get_new_vm_entry(status, vm_address);
    struct hash* vm = &target->vm_list;
    hash_insert(vm, &new_entry->vm_list_elem);
    return new_entry;
}

struct vm_entry * get_new_vm_entry(enum page_status status, uint32_t vm_address){
    uint32_t maskedAddress = (uint32_t)pg_round_down((uint8_t*)vm_address);
    struct vm_entry * entry = malloc(sizeof(struct vm_entry));
    memset(entry,0,sizeof(struct vm_entry));
    ASSERT(entry);
    if(entry == (struct vm_entry*)NULL){
      return entry;
    }
    entry->entry_status = status;
    entry->vm_address = maskedAddress;
    return entry;
}
struct vm_entry * find_vm_entry_from(struct thread * target, uint32_t vm_address){
  struct hash* vm = &target->vm_list;
  struct vm_entry * found_entry = find_entry(vm_address,vm);
  return found_entry;
}
struct vm_entry * find_entry(uint32_t vm_address, struct hash * vm_list){
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
    //free(target);
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
