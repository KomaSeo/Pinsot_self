
#include <hash.h>
#define VF_IsInitial 0x1 //initialize mask
#define VF_InDIsk 0x2 //in disk
#define VF_Write 0x4// is writable.
struct vm_entry{
    uint32_t vm_address;
    struct hash_elem vm_list_elem;
    char flags;
};
struct hash_elem * get_new_vm_entry(char flags, uint32_t vm_address);
unsigned vm_hash_func (struct hash_elem *e, void *aux);
bool vm_less_func (struct hash_elem *a, struct hash_elem *b,void *aux);

void vm_destroy (struct hash_elem *e, void *aux);
