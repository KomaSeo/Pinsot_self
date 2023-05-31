

#include "threads/malloc.h"
#include "threads/thread.h"
#include <hash.h>
#define VF_IsInitial 0x1 //initialize mask
#define VF_InDIsk 0x2 //in disk
#define VF_Write 0x4// is writable.
struct vm_entry{
    uint32_t vm_address;
    struct hash_elem vm_list_elem;
    char flags;
};


bool vm_install_new_page(struct thread * target,struct vm_entry * target_entry);
struct vm_entry * find_entry(uint32_t vm_address, struct hash * vm_list);
struct vm_entry * get_new_vm_entry(char , uint32_t );
unsigned vm_hash_func (struct hash_elem *, void *);
bool vm_less_func (struct hash_elem *, struct hash_elem *,void *);
struct vm_entry * find_vm_entry_from(struct thread * target, uint32_t vm_address);
void vm_destroy (struct hash_elem *, void *);
