//static struct timespec t;

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

void init_queue_file(void){

    head_file = NULL;
    tail_file = NULL;
}

void init_queue_rule(void){

    head_rule = NULL;
    tail_rule = NULL;
}

void deinit_queue(void){
	struct user_role *temp, *buf;

	while(head != NULL){
		temp = head;
		buf = head->next;
        if(temp->roles){
		  kfree(temp->roles);
        }
        if(temp->active_role){
		  kfree(temp->active_role);
        }
		kfree(temp);
		head = buf;
	}
}

void deinit_queue_file(void){
    struct file_role *temp, *buf;

    while(head_file != NULL){
        temp = head_file;
        buf = head_file->next;
        if(temp->role){
          kfree(temp->role);
        }
        kfree(temp);
        head_file = buf;
    }
}

void deinit_queue_rule(void){
    struct rule *temp, *buf;

    while(head_rule != NULL){
        temp = head_rule;
        buf = head_rule->next;
        if(temp->role){
          kfree(temp->role);
        }
        if(temp->accessible_roles){
          kfree(temp->accessible_roles);
        }
        kfree(temp);
        head_rule = buf;
    }
}

int enQueue(int uid, char *roles, char *active_role)
{
    struct  user_role *temp = NULL;
	int err = 0;	
	temp=kmalloc(sizeof(struct user_role), GFP_KERNEL);
	if(!temp){
                printk("ptr allocation failed \n");
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
    temp=kmalloc(sizeof(struct file_role), GFP_KERNEL);
    if(!temp){
                printk("ptr allocation failed \n");
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
    temp=kmalloc(sizeof(struct rule), GFP_KERNEL);
    if(!temp){
                printk("ptr allocation failed \n");
                err = -1;
                goto out;
        }

    temp->role = role;    
    temp->accessible_roles = accessible_roles;
 
     if(head_rule == NULL)
     {
           tail_rule=temp;
           tail_rule->next=NULL;
           head_rule=tail_rule;
     }
     else
     {
           tail_rule->next=temp;
           tail_rule=temp;
           tail_rule->next=NULL;
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
			printk("%d \t",var->uid);
			printk("%s\t",var->roles);
            printk("%s",var->active_role);
            printk("\n");
			var=var->next;
           }
     printk("\n");
     } 
     else
     	printk("\nQueue is Empty \n");
}

void display_file(void)
{
     struct file_role *var = head_file;

     if(var!=NULL)
     {
        while(var!=NULL)
        {
            printk("%lu \t",var->ino);
            printk("%s\t",var->role);
            printk("\n");
            var=var->next;
           }
     printk("\n");
     } 
     else
        printk("\nQueue is Empty \n");
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
          kfree(temp);
          return;
        }
        else
        {
        prev->next=temp->next;
        kfree(temp);
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


void display_rule(void)
{
     struct rule *var=head_rule;
     if(var!=NULL)
     {
        while(var!=NULL)
        {
            printk("%s\t",var->role);
            printk("%s",var->accessible_roles);
            printk("\n");
            var=var->next;
           }
     printk("\n");
     } 
     else
        printk("\nQueue is Empty \n");
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

bool check_role(int uid, char *file_role){

     bool grant_access = false; 
     struct user_role *var=head;

     if(var!=NULL)
     {
        while(var!=NULL)
        {
        if(var->uid == uid){
          if(strcmp(var->active_role, file_role) == 0){
            grant_access = true;
          }
        }
        var=var->next;
           }
     } 

     return grant_access;
}

char *get_role(int uid){

    char *role = NULL;
    struct user_role *var=head;

     if(var!=NULL)
     {
        while(var!=NULL)
        {
        if(var->uid == uid){
          role = var->active_role;
        }
        if(var){
          var=var->next;
        }
           }
     } 
     return role;
}

char *get_role_inode(long ino){

    char *role = NULL;
    struct file_role *var=head_file;

     if(var!=NULL)
     {
        while(var!=NULL)
        {
        if(var->ino == ino){
          role = var->role;
        }
        if(var){
          var=var->next;
        }
           }
     } 
     return role;
}

bool check_permission(char *u_role, char *i_role){

     bool grant_access = false; 
     struct rule *var=head_rule;

     if(var!=NULL)
     {
        while(var!=NULL)
        {
        if(strcmp(u_role, var->role) == 0){
          if(strstr(var->accessible_roles, i_role) != NULL){
            grant_access = true;
          }
        }
        var=var->next;
           }
     } 

     return grant_access;


}

/*bool check_version(char *fname){

    struct kstat fileStat;
    boo*l version_change = false;

    vfs_stat("/var/user_role.ur", &fileStat);

    if(first_time){
        printk("First Time \n");
        t.tv_sec = fileStat.mtime.tv_sec;
        version_change = true;
        first_time = false;
    }
    else{
        if((t.tv_sec/fileStat.mtime.tv_sec) == 1){
            version_change = true;
            //Update current time
            t.tv_sec = fileStat.mtime.tv_sec;
        }
    }
    return version_change;
}*/

void parse_file_user(void){
	struct file *filp = NULL;
	mm_segment_t oldfs;
	void *buf = NULL;
	int len;
	char *token, *strpos, *token_single;
	int flag = 0;
	long uid = 0;
    char *roles = NULL, *active_role = NULL;

    /*if(check_version("/var/user_role.ur")){
        printk("Version changed\n");
    }
    else{
        printk("Version not changed\n");
        display();
        return;
    }*/

    if(head != NULL){
        deinit_queue();
    }

	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if(!buf){
		printk("Error in allocating buf \n");
	}

	memset(buf, 0, PAGE_SIZE);
	
	oldfs=get_fs();
	set_fs(KERNEL_DS);
	filp = filp_open("/var/user_role.ups", O_RDONLY,0);
	len = PAGE_SIZE;
	filp->f_pos = 0;
	
	if(!IS_ERR(filp)){
		filp->f_op->read(filp,buf,len,&filp->f_pos);
	}
	else{
		printk("Error in opening filp errno: %lu \n", PTR_ERR(filp));
	}

	set_fs(oldfs);
	strpos = buf;

	while ((token=strsep(&strpos,"\n")) != NULL){
    	if(strlen(token) <= 1){
    		//printk("breaking loop \n");
    		break;
    	}
        roles = kmalloc(50 , GFP_KERNEL);
        active_role = kmalloc(50, GFP_KERNEL);
        memset(roles, 0, 50);
        memset(active_role, 0, 50);
    	flag = 1;
    	while ((token_single=strsep(&token,",")) != NULL){
    		if(flag == 1){
    			kstrtol(token_single, 10, &uid);
    		}
    		else if(flag == 2){
    			strcpy(roles, token_single);
    		}
    		else if(flag == 3){
    			strcpy(active_role, token_single);
    		}
    		flag++;
    	}
    	enQueue(uid , roles, active_role);
	}

	if(filp && !IS_ERR(filp)){
		filp_close(filp,NULL);
	}
	if(buf){
		kfree(buf);
	}
}

void parse_file_file(void){
    struct file *filp = NULL;
    mm_segment_t oldfs;
    void *buf = NULL;
    int len;
    char *token, *strpos, *token_single;
    int flag = 0;
    long ino = 0;
    char *role = NULL;

    /*if(check_version("/var/user_role.ur")){
        printk("Version changed\n");
    }
    else{
        printk("Version not changed\n");
        display();
        return;
    }*/

    if(head_file != NULL){
        deinit_queue_file();
    }

    buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if(!buf){
        printk("Error in allocating buf \n");
    }

    memset(buf, 0, PAGE_SIZE);
    
    oldfs=get_fs();
    set_fs(KERNEL_DS);
    filp = filp_open("/var/file_role.fps", O_RDONLY,0);
    len = PAGE_SIZE;
    filp->f_pos = 0;
    
    if(!IS_ERR(filp)){
        filp->f_op->read(filp,buf,len,&filp->f_pos);
    }
    else{
        printk("Error in opening filp errno: %lu \n", PTR_ERR(filp));
    }

    set_fs(oldfs);
    strpos = buf;

    while ((token=strsep(&strpos,"\n")) != NULL){
        if(strlen(token) <= 1){ 
            break;
        }
        role = kmalloc(50 , GFP_KERNEL);
        memset(role, 0, 50);
        flag = 1;
        while ((token_single=strsep(&token,",")) != NULL){
            if(flag == 1){
                kstrtol(token_single, 10, &ino);
            }
            else if(flag == 2){
                strcpy(role, token_single);
            }
            flag++;
        }
        enQueue_file(ino , role);
    }

    if(filp && !IS_ERR(filp)){
        filp_close(filp,NULL);
    }
    if(buf){
        kfree(buf);
    }
}

void parse_file_rule(void){
    struct file *filp = NULL;
    mm_segment_t oldfs;
    void *buf = NULL;
    int len;
    char *token, *strpos, *token_single;
    int flag = 0;
    char *role = NULL, *accessible_roles = NULL;

    /*if(check_version("/var/user_role.ur")){
        printk("Version changed\n");
    }
    else{
        printk("Version not changed\n");
        display();
        return;
    }*/

    if(head_rule != NULL){
        deinit_queue_rule();
    }

    buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if(!buf){
        printk("Error in allocating buf \n");
    }

    memset(buf, 0, PAGE_SIZE);
    
    oldfs=get_fs();
    set_fs(KERNEL_DS);
    filp = filp_open("/var/rule.rps", O_RDONLY,0);
    len = PAGE_SIZE;
    filp->f_pos = 0;
    
    if(!IS_ERR(filp)){
        filp->f_op->read(filp,buf,len,&filp->f_pos);
    }
    else{
        printk("Error in opening filp errno: %lu \n", PTR_ERR(filp));
    }

    set_fs(oldfs);
    strpos = buf;

    while ((token=strsep(&strpos,"\n")) != NULL){
        if(strlen(token) <= 1){
            //printk("breaking loop \n");
            break;
        }
        role = kmalloc(50 , GFP_KERNEL);
        accessible_roles = kmalloc(50, GFP_KERNEL);
        memset(role, 0, 50);
        memset(accessible_roles, 0, 50);
        flag = 1;
        while ((token_single=strsep(&token,",")) != NULL){
            if(flag == 1){
                strcpy(role, token_single);
            }
            else if(flag == 2){
                strcpy(accessible_roles, token_single);
            }
            flag++;
        }
        enQueue_rule(role, accessible_roles);
    }

    if(filp && !IS_ERR(filp)){
        filp_close(filp,NULL);
    }
    if(buf){
        kfree(buf);
    }
}

void write_file_role(void){
    struct file *filp = NULL;
    mm_segment_t oldfs;
    struct file_role *var = head_file;
    //char *temp = NULL;
    char buf[50] = {0};

    if(head_file == NULL){
        printk("Nothing to write \n");
        return;
    }
    
    oldfs=get_fs();
    set_fs(KERNEL_DS); 

    filp = filp_open("/var/file_role.fps", O_WRONLY | O_TRUNC, 0);
    
    if(!IS_ERR(filp)){

    if(var!=NULL)
    {
        while(var!=NULL)
        {
            memset(&buf, 0, 50);
            sprintf(buf, "%lu", var->ino);
            strcat(buf, ",");
            strcat(buf , var->role);
            strcat(buf, "\n");
            strcat(buf, "\0");
            filp->f_op->write(filp, buf, strlen(buf), &filp->f_pos);
            var=var->next;
        }
    }
    }
    else{
        printk("Error in opening filp errno: %lu \n", PTR_ERR(filp));
    }

    set_fs(oldfs);

    if(filp && !IS_ERR(filp)){
        filp_close(filp,NULL);
    }
}



void init_all(void){
    init_queue();
    init_queue_rule();
    init_queue_file();
}

void parse_all(void){
    parse_file_user();
    parse_file_rule();
    parse_file_file();
}

void deinit_all(void){
    deinit_queue();
    deinit_queue_rule();
    deinit_queue_file();
}

void deQueue_d_inode(long d_ino){

    if(check_ino(d_ino)){
        printk("rmdir inode d_inode found\n");
        deQueue_inode(d_ino);
        write_file_role();
    }
    else{
        printk("rmdir inode d_inode not found\n");
    }
}