#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NUM_ROLES 3

char *super_user = "super_user";
char *engineer = "engineer";
char *normal_user = "normal_user";

typedef struct _role_set
{
     char *role[NUM_ROLES];
}role_set;


void find_roles(role_set *r, char* usr_name, char* group_name)
{
     FILE *fp;
     char role[50] = "";
     char usr[50] = "";
     char group[50] = "";
     char c;              //char read from file
     int i;               //index to usr


     
     fp = fopen("rbac.txt", "r");
     if(NULL == fp)
     {
	  perror("fopen");
	  exit(1);
     }
     
     while(1)
     {
	  memset(role, 0, 50);
	  fscanf(fp,"%s\n", role);
	  printf("\ncurrent role = [%s]\n\n", role);
	  i = 0;

	  while(1)
	  {
	       c = fgetc(fp);
	       if( c == '\n' || c == ' ')
	       {
		    usr[i] = '\0';
		    i = 0;
		    printf("user =[%s] ", usr);
		    if(0 == strcmp(usr, usr_name))
		    {
			 printf("user match\n");
			 if(0 == strcmp (super_user, role))
			      r->role[0] = super_user;
			 else if(0 == strcmp (engineer, role))
			      r->role[1] = engineer;
			 else if (0 == strcmp (normal_user, role))
			      r->role[2] = normal_user;
		    }
		    memset(usr, 0, 50);
		    if(c == '\n')
			 break;
	       }
	       else  usr[i++] = c;		   	       
	  }

	  while(1)
	  {
	       c = fgetc(fp);
	       if( c == '\n' || c == ' ')
	       {
		    group[i] = '\0';
		    printf("group =[%s] ", group);
		    i = 0;
		    if(0 == strcmp(group, group_name))
		    {
			  printf("group match\n");
			 if(0 == strcmp (super_user, role))
			      r->role[0] = super_user;
			 else if(0 == strcmp (engineer, role))
			      r->role[1] = engineer;
			 else if (0 == strcmp (normal_user, role))
			      r->role[2] = normal_user;
		    }
		    memset(group, 0 ,50);

		    if(c == '\n')
			 break;
	       }
	       else  group[i++] = c;		   	       
	  }
	  
	  c = fgetc(fp);
	  if(c != '\n')
	       break;
     }
}

int check_permissions(char *role, char *file_name, int operation)
{
     char role_file[50] = "";
     char fname[50] = "";
     FILE *fp;
     int ret;
     int op, orig_op = 0;
     int allow;

     sprintf(role_file, "%s.txt", role);
     fp = fopen(role_file, "r");
     if(NULL == fp)
     {
      perror("fopen");
      exit(1);
     }     
	
     printf("flags=[%d]\n", operation);     

     while(1)
     {
        ret = fscanf(fp, "%s %d %d \n", fname, &op, &allow);
        printf("%s %d %d", fname, op, allow);
        if(0 == strcmp(fname, file_name))
        {
            printf("matched\n");

            if(operation == 4 && (op && 8))
              return allow;
            else if((op & operation))
              return allow;
        }	

        memset(fname, 0, 50);
        if(EOF == ret)
        {
           if(operation == 4 && allow == 1)
              return allow;
           else
             return -1;
        }
     }
}

int is_access_allowed(char *filename, char *usr_name, char *grp_name, int flags)
{
     int i;
     role_set r;
     int allow;
     

     if(filename == NULL || usr_name == NULL || grp_name == NULL) {
       printf("%s(): Invalid parameters\n", __FUNCTION__);
       return 0;
     }

     memset(&r, 0, sizeof(r));

     find_roles(&r, usr_name, grp_name);

     for(i = 0; i < 3; i++)
     {
	  if(NULL != r.role[i])
	  {
	       printf("\nrole=[%s]\n", r.role[i]);
	       allow = check_permissions(r.role[i], filename, flags);
	       if(-1 == allow)
	       {
		    printf("Requested file [%s] not found in RBAC\n", filename);
	       }
	       else if (0 == allow)
		    break;
	  }
     }

     printf("allowed = [%d]\n", allow);     

     return allow;
}
