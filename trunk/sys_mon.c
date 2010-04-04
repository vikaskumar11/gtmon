/* 
 * sysmon.c - RBAC implementation over vsftpd
 * Authors:
 *  venkat
 *  vikas
*/
	

#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <string.h>
#include <malloc.h>
#include <signal.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>

#include "file.c"

#define STACKSIZE 32768

const int long_size = sizeof(long);

void print_regs(struct user_regs_struct *regs) {
  fprintf(stderr, "Register Contents: eax: %lu ebx: %ld ecx: %ld edx: %ld\n", 
          regs->eax, regs->ebx, regs->ecx, regs->edx);

  return;
}

void setdata(pid_t child, long addr, char *str, int len)
{   char *laddr;
    int i, j;
    union u {
            long val;
            char chars[long_size];
    }data;
    i = 0;
    j = len / long_size;
    laddr = str;
    while(i < j) {
        memcpy(data.chars, laddr, long_size);
        ptrace(PTRACE_POKEDATA, child,
               addr + i * 4, data.val);
        ++i;
        laddr += long_size;
    }
    j = len % long_size;
    if(j != 0) {
        memcpy(data.chars, laddr, j);
        ptrace(PTRACE_POKEDATA, child,
               addr + i * 4, data.val);
    }
}



void getdata(pid_t child, long addr,char *str)
{  

  char *laddr;
  int i, j;

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
  char in_clone_call = 0, in_open_call = 0;
  char in_uid_call = 0, in_gid_call = 0;
  char in_write_call = 0;
  char trace_open = 0;
  int child_id = 0;
  void **child_stack = NULL;  
  struct group *grp_ptr;
  struct passwd *pwd_ptr;
  char *usr_name = NULL, *grp_name = NULL;
  char str[80];
    
  traced_proc = (pid_t)arg;
  printf("Tracing Proc: %d\n", traced_proc);
  
  if(ptrace(PTRACE_ATTACH, traced_proc, NULL, NULL) == -1) {
    printf("Unable to attach to process %d\n", traced_proc);
    _exit(1);
  }

  waitpid(traced_proc, &status, 0);
  ptrace(PTRACE_SYSCALL, traced_proc, NULL, NULL);

  while(1) {

    child_id = wait(&status);
      
    if(child_id == traced_proc) {
      if(WIFEXITED(status)) 
        break;     
      if(WIFSTOPPED(status)) {
        if(WSTOPSIG(status) != SIGTRAP) 
          goto child_cont;
      }
    } else {
      continue;
    }

    ptrace(PTRACE_GETREGS, traced_proc, NULL, &regs);

    switch(regs.orig_eax) {
      case __NR_clone:
        {
          if(in_clone_call == 0) {
            in_clone_call = 1;
          } else {
            in_clone_call = 0;	

            child_stack = (void **)malloc(STACKSIZE);
            if(child_stack == NULL) {
              perror("Unable to create child stack. Exiting\n");
              _exit(1);
            }

            if(regs.eax > 0) {
              child_stack = (void **)(STACKSIZE + (char *)child_stack);
              child_id = clone(worker_thread, child_stack, SIGCHLD, (void *)regs.eax);
            }

            if(child_id <= 0) {
              perror("Clone call failed. Exiting\n");
              _exit(1);
            }
                        
            child_id = 0;
            child_stack = NULL;
          }   
        } 
        break;
      case __NR_open: 
        {
          if(trace_open) {
            if(in_open_call == 0) {
              int flags = 0, ret = 0;

              in_open_call = 1;
              printf("Open:\n");              

              /* 
                 ebx: addr of filename
                 ecx: flags
                 edx: mode
              */
              
              getdata(traced_proc, regs.ebx, str);
              fprintf(stderr, "Filename: %s ecx: %ld\n", str, regs.ecx);
	      
              if((regs.ecx & O_CREAT) == O_CREAT) 
                flags = 4;
              else if((regs.ecx & O_RDWR) == O_RDWR)
                flags = 3;
              else if((regs.ecx & O_WRONLY) == O_WRONLY)
                flags = 2;
              else if((regs.ecx & O_RDONLY) == O_RDONLY) 
                flags = 1;
              else
                flags = 0;

	      printf("Flags: %d\n", flags);
              if(!(ret=is_access_allowed(str, usr_name, grp_name, flags)) ||
			ret == -1) {
                setdata(traced_proc, regs.ebx, "1", 9);              
              }

            } else {
              in_open_call = 0;
            }          
          }
        }
        break; 
  
      case __NR_setuid32:
        {
          if(in_uid_call == 0) {
            pwd_ptr = NULL;
            pwd_ptr = getpwuid(regs.ebx);

            if(pwd_ptr != NULL) {
              printf("Proc: %d UID: %s ebx: %ld\n", traced_proc, pwd_ptr->pw_name, regs.ebx);
            }
            else {
              printf("UID does not exist\n");
              break;
            }

            if(usr_name != NULL)
              free(usr_name);

            usr_name = malloc(strlen(pwd_ptr->pw_name)+1);
            strcpy(usr_name, pwd_ptr->pw_name);

            in_uid_call = 1;
          } else {
            in_uid_call = 0;
          }
        }
        break;

      case __NR_setgid32:
        {
          if(in_gid_call == 0) {
            grp_ptr = NULL;
            grp_ptr = getgrgid(regs.ebx);

            if(grp_ptr != NULL) {
              //printf("Proc: %d GID: %s ebx: %d\n", traced_proc, grp_ptr->gr_name, regs.ebx);
            }
            else {
              printf("Group does not exist\n");
              break;
            }

            if(grp_name != NULL)
              free(grp_name);

            grp_name = malloc(strlen(grp_ptr->gr_name)+1);
            strcpy(grp_name, grp_ptr->gr_name);

            in_gid_call = 1;
          } else {
            in_gid_call = 0;
          }
        }
        break;

      case __NR_write:
        {
          if(!trace_open || in_write_call) {
            if(in_write_call == 0) {
              getdata(traced_proc, regs.ecx, str);
              
              if(strstr(str, "Login successful")) {           
                trace_open = 1;
                printf("PID: %d Write: %s\n", traced_proc, str);
              }

              in_write_call = 1;
            } else {
              in_write_call = 0;
            }
          }
        }
        break;

      default:
        //perror("Unknown system call\n");
        break;
    }


child_cont:
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

