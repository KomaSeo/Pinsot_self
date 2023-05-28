#include "vm/page.h"
#include "threads/malloc.h"
#include <hash.h>


struct hash_elem * get_new_vm_entry(char flags, uint32_t vm_address){
    struct vm_entry * entry = malloc(sizeof(struct vm_entry));
    entry->flags = flags;
    entry->vm_address = vm_address;
    return entry;
}
void vm_destroy(struct hash_elem *e, void * aux){
    struct vm_entry * target = hash_entry(e, struct vm_entry, vm_list_elem);
    free(target);
}
unsigned vm_hash_func (struct hash_elem *e, void *aux){
    struct vm_entry * target = hash_entry(e, struct vm_entry, vm_list_elem);
    return hash_int(target-> vm_address);
}

bool vm_less_func (struct hash_elem *a, struct hash_elem *b,void *aux){
    struct vm_entry * A = hash_entry(a, struct vm_entry, vm_list_elem);
    struct vm_entry * B = hash_entry(b, struct vm_entry, vm_list_elem);
    return A->vm_address < B->vm_address;
}
