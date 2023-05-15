#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/file.h"
#include "devices/input.h"
#include <string.h>

#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);
int stack_pop(struct intr_frame *, int);
void sys_halt();
void sys_write(struct intr_frame *);
void sys_read(struct intr_frame *);
void sys_filesize(struct intr_frame *);
void sys_seek(struct intr_frame *);
void sys_exec(struct intr_frame *);
void sys_wait(struct intr_frame *);
void sys_tell(struct intr_frame *);
void sys_create(struct intr_frame *f);
void sys_remove(struct intr_frame *f);
void sys_open(struct intr_frame *f);
void sys_close(struct intr_frame *f);
void storeReturnVal(struct intr_frame * f, int a);
bool isAddressUpperPHYS(char*, off_t);

bool isAddressUpperPHYS(char * pointer, off_t offset){
  return pointer + offset >= PHYS_BASE ? true : false;
}
void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}
static void
syscall_handler (struct intr_frame *f UNUSED)
{
  //uint32_t segment_start = 0x08084000;//TODO
  uint32_t segment_start = PHYS_BASE - PGSIZE;//TODO
  if(f->esp > PHYS_BASE-4){
    sys_unexpected_exit();
  }
  int checkbytes = 0;
  int syscall_num = stack_pop(f,0);
  switch (syscall_num){
    case SYS_HALT : checkbytes = 4; break;
    case SYS_EXIT : ;
    case SYS_EXEC : ;
    case SYS_REMOVE : ;
    case SYS_TELL: ;                    /* Report current position in a file. */
    case SYS_CLOSE: ;
    case SYS_FILESIZE : ;               /* Obtain a file's size. */
    case SYS_OPEN : ;                  /* Open a file. */
    case SYS_WAIT : checkbytes = 8; break;                   /* Wait for a child process to die. */
    case SYS_CREATE : ;                 /* Delete a file. */
    case SYS_READ : ;                   /* Read from a file. */
    case SYS_SEEK: checkbytes = 12;break;                   /* Change position in a file. */
    case SYS_WRITE : checkbytes = 16; break;                 /* Write to a file. */
  }
  if(f->esp > PHYS_BASE-checkbytes){
    sys_unexpected_exit();
  }



  //if(f->esp < segment_start){
  //  sys_unexpected_exit();
  //}
  switch (syscall_num){
    case SYS_HALT : sys_halt(); break;
    case SYS_EXIT : sys_exit(f); break;
    case SYS_EXEC : sys_exec(f); break;                   /* Start another process. */
    case SYS_WAIT : sys_wait(f); break;                   /* Wait for a child process to die. */
    case SYS_CREATE : sys_create(f); break;                 /* Create a file. */
    case SYS_REMOVE : sys_remove(f); break;                 /* Delete a file. */
    case SYS_OPEN : sys_open(f); break;                  /* Open a file. */
    case SYS_FILESIZE : sys_filesize(f);break;               /* Obtain a file's size. */
    case SYS_READ : sys_read(f); break;                   /* Read from a file. */
    case SYS_WRITE : sys_write(f); break;                 /* Write to a file. */
    case SYS_SEEK: sys_seek(f); break;                   /* Change position in a file. */
    case SYS_TELL: sys_tell(f); break;                    /* Report current position in a file. */
    case SYS_CLOSE: sys_close(f); break;                 /* Close a file. */

    default :{
        printf ("Unimplemented system call!\n syscall num : %d\n", syscall_num);
        thread_exit ();
    }
  }
}
void sys_halt(){
  shutdown_power_off();
}
void sys_exit(struct intr_frame * f){
  thread_current()->exit_status = stack_pop(f, 1);
  printf ("%s: exit(%d)\n", thread_current()->name,thread_current()->exit_status);
  thread_exit();//TODO after wait();
}
void sys_unexpected_exit(){
  thread_current()->exit_status = -1;
  printf ("%s: exit(%d)\n", thread_current()->name,thread_current()->exit_status);
  thread_exit();
}
void sys_exec(struct intr_frame * f){
  tid_t tid;
  char * file_name = stack_pop(f, 1);

  if(file_name == NULL|| isAddressUpperPHYS(file_name,0) ){
    storeReturnVal(f, -1);
    return;
  }

  int file_name_length = strlen(file_name);
  char cp_str[file_name_length + 1];
  char cp_str2[file_name_length + 1];

  strlcpy(cp_str,file_name,file_name_length + 1);

  strlcpy(cp_str2,file_name,file_name_length + 1);
  char * token, savePtr;
  token = strtok_r(cp_str," ",&savePtr);

  struct file* opened_file = filesys_open(token);
  if(opened_file){
    file_close(opened_file);
    tid = process_execute(cp_str2);
    storeReturnVal(f,tid);
    return;
  }
  else{
    storeReturnVal(f,-1);
    return;
  }
}
void sys_wait(struct intr_frame * f){
  tid_t target_tid = stack_pop(f,1);
  int return_val = sys_wait_W(target_tid);
  storeReturnVal(f, return_val);
}
int sys_wait_W(tid_t target_tid){

  enum intr_level old_level = intr_disable();
  struct list_elem * e;
  struct thread * target_child = NULL;
  int returnVal = -1;
  for(e = list_begin(&thread_current()->child_list); e!= list_end(&thread_current()->child_list);e = list_next(e)){
    struct thread * e_thread = list_entry(e,struct thread,child_list_elem);
    if(e_thread->tid == target_tid){
      target_child = e_thread;
    }
  }

  if(target_child == NULL || target_child->is_parent_waiting == true){
    returnVal = -1;
  }
  else if(target_child->status == THREAD_DYING){
    returnVal = target_child->exit_status;
    thread_reap(target_child);
  }
  else if(target_child->status != THREAD_DYING){
    target_child->is_parent_waiting = true;
    thread_block();
    returnVal = target_child->exit_status;
    thread_reap(target_child);

  }
  else{
    printf("unexpected wait condition\n");
  }
  intr_set_level (old_level);
  //printf("exit_status : %d\n\n", target_child->exit_status);
  //printf("returnVal : %d\n\n", returnVal);
  return returnVal;
}
void sys_create(struct intr_frame *f){
  char* fileName = stack_pop(f, 1);
  off_t initial_size = stack_pop(f,2);
  if(fileName == NULL || isAddressUpperPHYS(fileName,0)){
    sys_unexpected_exit();
  }
  bool success = filesys_create(fileName,initial_size);
  storeReturnVal(f, (int)success);
}
void sys_remove(struct intr_frame *f){
  char* fileName = stack_pop(f, 1);
  if(fileName == NULL||isAddressUpperPHYS(fileName,0)){
    sys_unexpected_exit();
  }
  bool success = filesys_remove(fileName);
  storeReturnVal(f, (int)success);
}
void sys_open(struct intr_frame *f){
  char* fileName = stack_pop(f, 1);
  if(fileName == NULL||isAddressUpperPHYS(fileName,0)){
    sys_unexpected_exit();
  }
  struct file * result = filesys_open(fileName);
  if(result == NULL){
    storeReturnVal(f, -1);
    return;
  }

  struct file ** FDT = thread_current()->FDT;
  int i = 0;
  for(; i < 128; i++){
    if(FDT[i] == NULL){
      FDT[i] = result;
      storeReturnVal(f, i+2);
      return;
    }
  }
}
void sys_close(struct intr_frame *f){
  int fileIndex = stack_pop(f, 1);
  struct thread * current_thread = thread_current();
  struct file ** FDT = &current_thread->FDT;
  if(fileIndex < 2 || fileIndex > 130){
    sys_unexpected_exit();
  }
  else if(FDT[fileIndex-2] == NULL){
    sys_unexpected_exit();
  }
  else{
    file_close(FDT[fileIndex-2]);
    FDT[fileIndex-2] = NULL;
  }
}
void sys_read(struct intr_frame * f ){
  int fileIndex = stack_pop(f,1);
  char * buffer = stack_pop(f,2);
  int readSize = stack_pop(f,3);
  struct file ** FDT = thread_current() ->FDT;
  if(isAddressUpperPHYS(buffer,readSize)){
    sys_unexpected_exit();
  }
  if(fileIndex == 0){
    int i = -1;
    do{
      i++;
      buffer[i] = input_getc();
    }while (i< readSize && buffer[i]);
    storeReturnVal(f, i+1);
  }
  else if(fileIndex == 1 || fileIndex < 0 ||fileIndex > 130|| FDT[fileIndex-2] == NULL){
    sys_unexpected_exit();
  }
  else{
    int read_size;
    read_size = file_read(FDT[fileIndex-2], buffer,readSize);
    storeReturnVal(f,readSize);
  }
}
void sys_write (struct intr_frame *f){
  int fileIndex = stack_pop(f,1);
  char * buffer = stack_pop(f,2);
  int writeSize = stack_pop(f,3);
  struct file ** FDT = thread_current() ->FDT;
  if(isAddressUpperPHYS(buffer,writeSize)){
    sys_unexpected_exit();
  }
  if(fileIndex == 1){
    putbuf(buffer, writeSize);
    storeReturnVal(f,writeSize);
  }
  else if(fileIndex == 0 || fileIndex < 0 ||fileIndex > 130|| FDT[fileIndex-2] == NULL){
    sys_unexpected_exit();
  }
  else{
  int offset_max = file_length(FDT[fileIndex-2]);
  int offset_current = file_tell(FDT[fileIndex-2]);
    if(offset_current + writeSize > offset_max ){
        writeSize = offset_max - offset_current;
    }
    writeSize = file_write(FDT[fileIndex-2],buffer,writeSize);
    storeReturnVal(f,writeSize);
  }
}
void sys_filesize(struct intr_frame *f){
  int fileIndex = stack_pop(f,1);
  struct thread * current_thread = thread_current();
  struct file ** FDT = &current_thread ->FDT;
  if(fileIndex == 0){
    sys_unexpected_exit();
  }
  else if(fileIndex == 1 || fileIndex < 0 ||fileIndex > 130|| FDT[fileIndex-2] == NULL){
    sys_unexpected_exit();
  }
  else{
    storeReturnVal(f,file_length(FDT[fileIndex-2]));
  }
}
void sys_seek(struct intr_frame *f){
  int fileIndex = stack_pop(f,1);
  unsigned offset = stack_pop(f,2);
  struct thread * current_thread = thread_current();
  struct file ** FDT = &current_thread ->FDT;
  if(fileIndex == 0){
    sys_unexpected_exit();
  }
  else if(fileIndex == 1 || fileIndex < 0 ||fileIndex > 130|| FDT[fileIndex-2] == NULL){
    sys_unexpected_exit();
  }
  else{
    file_seek(FDT[fileIndex-2],offset);
  }
}
void sys_tell(struct intr_frame *f){
  int fileIndex = stack_pop(f,1);
  struct thread * current_thread = thread_current();
  struct file ** FDT = &current_thread ->FDT;
  if(fileIndex == 0){
    sys_unexpected_exit();
  }
  else if(fileIndex == 1 || fileIndex < 0 ||fileIndex > 130|| FDT[fileIndex-2] == NULL){
    sys_unexpected_exit();
  }
  else{
    storeReturnVal(f,file_tell(FDT[fileIndex-2]));
  }
}
int stack_pop(struct intr_frame *f, int index){
    return *((int *)(f->esp)+index);
}
void storeReturnVal(struct intr_frame * f, int a){
  f->eax = a;
}
