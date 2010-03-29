#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <string.h>
#include <malloc.h>

#define STACKSIZE 32768

void print_regs(struct user_regs_struct *regs) {
  fprintf(stderr, "Register Contents: eax: %lu ebx: %ld ecx: %ld edx: %ld\n", 
          regs->eax, regs->ebx, regs->ecx, regs->edx);

  return;
}

void getdata(pid_t child, long addr,char *str)
{  

  char *laddr;
  int i, j;
  const int long_size = sizeof(long);

  union u {
          long val;
          char chars[long_size];
  }data;

  i = 0;
  laddr = str;
  while(1) {
    data.val = ptrace(PTRACE_PEEKDATA,
                      child, addr + i * 4,
                      NULL);
    memcpy(laddr, data.chars, long_size);
   
    for(j = 0; j < long_size; j++) {
      if(data.chars[i] == '\0')
        break;
    }

    laddr += long_size;
    ++i;

    if(j < long_size)
      break;
  }
}

void worker_thread(void *arg) {
  pid_t traced_proc;
  struct user_regs_struct regs;
  int status;
  long orig_eax;
  int in_clone_call = 0, in_open_call = 0;
  int child_id = 0;
  void **child_stack = NULL;  
  char str[80];
    
  traced_proc = (pid_t)arg;
  printf("Traced proc: %d\n", traced_proc);
  
  if(ptrace(PTRACE_ATTACH, traced_proc, NULL, NULL) == -1) {
    printf("Unable to attach to process %d\n", traced_proc);
    _exit(1);
  }

  while(1) {

    /*child_id = wait(&status);
      
    if(child_id == traced_proc) {
      if(WIFEXITED(status)) 
        break;     
    } else {
      continue;
    }*/

    waitpid(traced_proc, &status, 0);
    if(WIFEXITED(status)) 
        break;     

    orig_eax = ptrace(PTRACE_PEEKUSER, traced_proc, 4 * ORIG_EAX, NULL);

    if(orig_eax == __NR_clone) {
      if(in_clone_call == 0) {
        in_clone_call = 1;
        ptrace(PTRACE_GETREGS, traced_proc, NULL, &regs);    
        print_regs(&regs);
        //getdata(traced_proc, regs.ebx, str);
        //printf("Filename: %s\n", str);
      } else {
        //fprintf(stderr, "exiting clone call..\n");
        write(2, "exit clone", 11);
        in_clone_call = 0;
        ptrace(PTRACE_GETREGS, traced_proc, NULL, &regs);    
        print_regs(&regs);
        
        child_stack = (void **)malloc(STACKSIZE);
        if(child_stack == NULL) {
          perror("Unable to create child stack. Exiting\n");
          _exit(1);
        }

        child_stack = (void **)(STACKSIZE + (char *)child_stack);

        child_id = clone(worker_thread, child_stack, SIGCHLD, (void *)regs.eax);

        if(child_id <= 0) {
          perror("Clone call failed. Exiting\n");
          _exit(1);
        }

        fprintf(stderr, "PID: %d - Cloned child with id: %d for process %d\n", getpid(), child_id, traced_proc);

        child_id = 0;
        child_stack = NULL;
      }
    } else if(orig_eax == __NR_open) {
       if(in_open_call == 0) {
        in_open_call = 1;
        ptrace(PTRACE_GETREGS, traced_proc, NULL, &regs);    
        print_regs(&regs);
        getdata(traced_proc, regs.ebx, str);
        fprintf(stderr, "Filename: %s\n", str);
      } else {
        fprintf(stderr, "exiting open call..\n");
        write(2, "exit open", 10);
        in_open_call = 0;
        ptrace(PTRACE_GETREGS, traced_proc, NULL, &regs);    
        //print_regs(&regs);
      }
    }

    ptrace(PTRACE_SYSCALL, traced_proc, NULL, NULL);
  }
}


int main(int argc, char **argv) {

  pid_t vftp_pid;

  if(argc != 2) {
    printf("Usage: %s <pid>", argv[0]);
    _exit(1);
  }

  vftp_pid = atoi(argv[1]);

  worker_thread((void *)vftp_pid);

  return 0;
}

