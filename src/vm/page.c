#include "vm/page.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include <hash.h>

bool vm_install_new_page(struct thread * target,struct vm_entry * target_entry){
    ASSERT(target_entry != (void *)NULL);
    ASSERT(target_entry->vm_address != NULL);
    ASSERT(!(target_entry->flags & VF_IsInitial));
    uint8_t* vm_Address = (uint8_t*)target_entry->vm_address;
    void* new_page = palloc_get_page(PAL_USER|PAL_ZERO);
    return (pagedir_get_page (target->pagedir, vm_Address) == NULL
          && pagedir_set_page (target->pagedir, vm_Address, new_page, !!(target_entry->flags&VF_Write)));
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
