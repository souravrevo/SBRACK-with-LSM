struct user_role{
	int uid;
	char *roles;
  char *active_role;
	struct user_role *next;
} *tail, *head;

struct rule{
  char *role;
  char *accessible_roles;
  struct rule *next;
} *tail_rule, *head_rule;

struct file_role{
    long ino;
    char *role;
    struct file_role *next;
} *tail_file, *head_file;


void init_queue(void){

	head = NULL;
	tail = NULL;
}

void init_queue_rule(void){

  head_rule = NULL;
  tail_rule = NULL;
}

void init_queue_file(void){

    head_file = NULL;
    tail_file = NULL;
}

void deinit_queue(void){
	struct user_role *temp, *buf;

	while(head != NULL){
		temp = head;
		buf = head->next;
		free(temp);
		head = buf;
	}
}

void deinit_queue_rule(void){
  struct rule *temp, *buf;

  while(head_rule != NULL){
    temp = head_rule;
    buf = head_rule->next;
    free(temp);
    head_rule = buf;
  }
}

void deinit_queue_file(void){
    struct file_role *temp, *buf;

    while(head_file != NULL){
        temp = head_file;
        buf = head_file->next;
        if(temp->role){
          free(temp->role);
        }
        free(temp);
        head_file = buf;
    }
}

int enQueue(int uid, char *roles, char *active_role)
{
    struct  user_role *temp = NULL;
	int err = 0;	
	temp=malloc(sizeof(struct user_role));
	if(!temp){
                printf("ptr allocation failed \n");
                err = -1;
                goto out;
        }
	temp->uid = uid;
	temp->roles = roles;	
  temp->active_role = active_role;
	
     if(head == NULL)
     {
           tail=temp;
           tail->next=NULL;
           head=tail;
     }
     else
     {
           tail->next=temp;
           tail=temp;
           tail->next=NULL;
     }

out:

	return err;
}

int enQueue_file(long ino, char *role)
{
    struct  file_role *temp = NULL;
    int err = 0;    
    temp=malloc(sizeof(struct file_role));
    if(!temp){
                printf("ptr allocation failed \n");
                err = -1;
                goto out;
        }

    temp->ino = ino;
    temp->role = role;    
 
     if(head_file == NULL)
     {
           tail_file=temp;
           tail_file->next=NULL;
           head_file=tail_file;
     }
     else
     {
           tail_file->next=temp;
           tail_file=temp;
           tail_file->next=NULL;
     }

out:

    return err;
}

int enQueue_rule(char *role, char *accessible_roles)
{
    struct  rule *temp = NULL;
    int err = 0;  
    temp=malloc(sizeof(struct rule));
    if(!temp){
                printf("ptr allocation failed \n");
                err = -1;
                goto out;
        }
    temp->role = role; 
    temp->accessible_roles = accessible_roles;
  
     if(head_rule == NULL)
     {
           tail_rule = temp;
           tail_rule->next = NULL;
           head_rule = tail_rule;
     }
     else
     {
           tail_rule->next = temp;
           tail_rule = temp;
           tail_rule->next = NULL;
     }

out:

  return err;
}


void display(void)
{
     struct user_role *var=head;
     if(var!=NULL)
     {
        while(var!=NULL)
        {
			printf("%d \t",var->uid);
			printf("%s\t",var->roles);
      printf("%s",var->active_role);
      printf("\n");
			var=var->next;
           }
     printf("\n");
     } 
     else
     	printf("\nQueue is Empty \n");
}

void display_rule(void)
{
     struct rule *var=head_rule;
     if(var!=NULL)
     {
        while(var!=NULL)
        {
      printf("%s \t",var->role);
      printf("%s",var->accessible_roles);
      printf("\n");
      var=var->next;
           }
     printf("\n");
     } 
     else
      printf("\nQueue is Empty \n");
}

void display_file(void)
{
     struct file_role *var = head_file;

     if(var!=NULL)
     {
        while(var!=NULL)
        {
            printf("%lu \t",var->ino);
            printf("%s",var->role);
            printf("\n");
            var=var->next;
           }
     printf("\n");
     } 
     else
        printf("\nQueue is Empty \n");
}

bool check_uid(int uid)
{
     bool exists = false; 
     struct user_role *var=head;

     if(var!=NULL)
     {
        while(var!=NULL)
        {

        if(var->uid == uid){
          exists = true;
        }
        var=var->next;
           }
     } 

     return exists; 
}

void deQueue_inode(long ino){

    struct file_role *temp, *prev;
    temp=head_file;
    while(temp!=NULL)
    {
      if(temp->ino == ino)
      {
        if(temp==head_file)
        {
          head_file=temp->next;
          free(temp);
          return;
        }
        else
        {
        prev->next=temp->next;
        free(temp);
        return;
        }
      }
    else
    {
        prev=temp;
        temp= temp->next;
    }
  }
}

void deQueue_uid(long uid){

    struct user_role *temp, *prev;
    temp=head;
    while(temp!=NULL)
    {
      if(temp->uid == uid)
      {
        if(temp==head)
        {
          head = temp->next;
          free(temp);
          return;
        }
        else
        {
        prev->next=temp->next;
        free(temp);
        return;
        }
      }
    else
    {
        prev=temp;
        temp= temp->next;
    }
  }
}


bool check_ino(long ino)
{
     bool exists = false; 
     struct file_role *var=head_file;

     if(var!=NULL)
     {
        while(var!=NULL)
        {
        if(var->ino == ino){
          exists = true;
        }
        var=var->next;
           }
     } 

     return exists; 
}

bool check_role(char *role)
{
     bool exists = false; 
     struct rule *var=head_rule;

     if(var!=NULL)
     {
        while(var!=NULL)
        {

        if(strcmp(var->role, role) == 0){
          exists = true;
        }
        var=var->next;
           }
     } 

     return exists; 
}

void add_replace_role(int uid, char *role){

  char *role_struct;

  struct user_role *var=head;
     if(var!=NULL)
     {
        while(var!=NULL)
        {
        if(var->uid == uid){
          role_struct = var->roles;

          if(strstr(role_struct, role) != NULL){
              printf("Role already exists for the user : %d \n", uid);
          }
          else{
              strcat(var->roles, ":");
              strcat(var->roles, role);
          }
        }

        var=var->next;
           }
     } 
}

void change_active_role(int uid, char *active_role){

  struct user_role *var=head;
     if(var!=NULL)
     {
        while(var!=NULL)
        {
        if(var->uid == uid){

          if(strstr(var->roles, active_role) != NULL){
            var->active_role = "";
            var->active_role = active_role;
            printf("Changed active role for uid: %d\n", uid);
          }
          else{
            printf("Active role not fund in list of roles for uid: %d \n", uid);
          }
        }

        var=var->next;
           }
     } 
}

void __change_rule(char *role, char *new_accessible_roles){

  struct rule *var=head_rule;
     if(var!=NULL)
     {
        while(var!=NULL)
        {
        if(strcmp(var->role, role) == 0){
            var->accessible_roles = "";
            var->accessible_roles = new_accessible_roles;
        }
        var=var->next;
           }
     } 
}

void write_user_role(){

  struct user_role *var=head;
  FILE *filp = fopen("/var/user_role.ups", "w");

  if(var!=NULL)
     {
        while(var!=NULL)
        {
          fprintf(filp, "%d,%s,%s\n", var->uid, var->roles, var->active_role);
          var=var->next;
      }
    }
    fclose(filp);
}

void write_file_role(){

  struct file_role *var=head_file;
  FILE *filp = fopen("/var/file_role.fps", "w");

  if(var!=NULL)
     {
        while(var!=NULL)
        {
          fprintf(filp, "%lu,%s\n", var->ino, var->role);
          var=var->next;
      }
    }
    fclose(filp);
}


void write_rule(){

  struct rule *var=head_rule;
  FILE *filp = fopen("/var/rule.rps", "w");

  if(var!=NULL)
     {
        while(var!=NULL)
        { 
          fprintf(filp, "%s,%s\n", var->role, var->accessible_roles);
          var=var->next;
      }
    }
    fclose(filp);
}

void delete_inode(long ino){

  if(check_ino(ino)){
    deQueue_inode(ino);
    write_file_role();
    printf("Inode deleted \n");
  }
  else{
    printf("Inode don't exist\n");
    return;
  }
}
 
void __change_inode_role(long ino, char *role){

  struct file_role *var=head_file;

     if(var!=NULL)
     {
        while(var!=NULL)
        {
        if(var->ino == ino){
            var->role = "";
            var->role = role;
            printf("Changed inode role for inode: %lu\n", ino);
          }
          else{
            printf("Role not found for ino: %lu \n", ino);
          }
          var=var->next;
        }
           }
     } 

void delete_user_role(int uid){

  if(check_uid(uid)){
    deQueue_uid(uid);
    write_user_role();
    printf("Uid deleted \n");
  }
  else{
    printf("Uid don't exist\n");
    return;
  }  
}