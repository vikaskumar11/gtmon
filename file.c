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

#define ALLOW_READ   2
#define ALLOW_WRITE  4
#define DENY_READ    8
#define DENY_WRITE   16

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
	  //printf("\ncurrent role = [%s]\n\n", role);
	  i = 0;

	  while(1)
	  {
	       c = fgetc(fp);
	       if( c == '\n' || c == ' ')
	       {
		    usr[i] = '\0';
		    i = 0;
		    //printf("user =[%s] ", usr);
		    if(0 == strcmp(usr, usr_name))
		    {
			 //printf("user match\n");
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
		    //printf("group =[%s] ", group);
		    i = 0;
		    if(0 == strcmp(group, group_name))
		    {
			 //printf("group match\n");
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
     int ret, result;
     int op;
     int allow;

     sprintf(role_file, "%s.txt", role);
     fp = fopen(role_file, "r");
     if(NULL == fp)
     {
       perror("fopen");
       exit(1);
     }     
	
     //printf("flags=[%d]\n", operation);     

     //printf("Checking Role %s..\n", role);

     result = 0;
     while(1)
     {
        ret = fscanf(fp, "%s %d %d \n", fname, &op, &allow);
        if(0 == strcmp(fname, file_name))
        {
             //printf("matched ");
             //printf("%s %d %d\n", fname, op, allow);

             if((op & 1) == 1) {
               result = result | (allow ? ALLOW_READ : DENY_READ);
             }

             if((op & 2) == 2) {
               result = result | (allow ? ALLOW_WRITE : DENY_WRITE) ;
             }

             return result;
        }	

        memset(fname, 0, 50);
        if(EOF == ret)
        {
             printf("\t\tNo entry for requested file\n");
             result |= ALLOW_READ;
             result |= ALLOW_WRITE;

             return result;
        }
     }
}

int is_access_allowed(char *filename, char *usr_name, char *grp_name, int flags)
{
     int i;
     role_set r;
     int ret = 0, read = 0, write = 0;
     

     if(filename == NULL || usr_name == NULL || grp_name == NULL) {
        printf("%s(): Invalid parameters\n", __FUNCTION__);
        return 0;
     }

     memset(&r, 0, sizeof(r));

     find_roles(&r, usr_name, grp_name);

     read = write = 0;
     for(i = 0; i < NUM_ROLES; i++)
     {
        if(NULL != r.role[i])
        {
             ret = 0;
             printf("\tChecking allowed access for role=[%s]\n", r.role[i]);
             ret = check_permissions(r.role[i], filename, flags);

             if((ret & ALLOW_READ)) {
               printf("\t\t->READ\n");
               read = 1;
             }
             
             if((ret & ALLOW_WRITE)) {
               printf("\t\t->WRITE\n");
               write = 1;
             }

             if(((flags & 1) == 1) && (ret & DENY_READ)) {
               printf("\t\t->Deny READ\n");
               printf("\tInsufficient read permission. Access denied to file %s\n", filename);
               return 0;
             }

             if(((flags & 2) == 2) && (ret & DENY_WRITE)) {
               printf("\t\t->Deny Write\n");
               printf("\tInsufficient write permission. Access denied to file %s\n", filename);
               return 0;
             }

        }
     }

     if(!read && ((flags & 1) == 1)) {
       printf("\tInsufficient read permission. Access denied to file %s\n", filename);
       return 0;
     }

     if(!write && ((flags & 2) == 2)) {
       printf("\tInsufficient write permission. Access denied to file %s\n", filename);
       return 0;
     }

     printf("\tAccess granted to file %s\n", filename);

     return 1;

     //printf("allowed = [%d]\n", allow);     
}
