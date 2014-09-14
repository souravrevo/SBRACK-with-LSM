#include <stdio.h>
#include <stdlib.h>
#include <string.h>    
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include "utils.h"

const char* getfield(char* line, int num)
{
    const char* tok;
    for (tok = strtok(line, ",");
            tok && *tok;
            tok = strtok(NULL, ",\n"))
    {
        if (!--num)
            return tok;
    }
    return NULL;
}

void user_role_make_list(){

	FILE *read = fopen("/var/user_role.ups", "r");
	int uid = 0;
	char line[1024];
	char *roles = NULL, *active_role = NULL;

	if(read == NULL){
		printf("user_role.ups cannot be opened \n");
		return;
	}

	while (fgets(line, 1024, read)){

		if(strlen(line) <= 1)
			break;

		uid = 0;
		roles = NULL;

		char *tmp = NULL;
		tmp = strdup(line); 
		sscanf(getfield(tmp, 1), "%d", &uid);
		free(tmp);

		tmp = NULL;
		tmp = strdup(line);
		roles = strdup(getfield(tmp, 2)); 
		free(tmp);

		tmp = NULL;
		tmp = strdup(line);
		active_role = strdup(getfield(tmp, 3)); 
		free(tmp);
		enQueue(uid, roles, active_role);
	}  
	fclose(read); 	
}

void file_make_list(){

FILE *read = fopen("/var/file_role.fps", "r");
	long ino = 0;
	char line[1024];
	char *role = NULL;

	if(read == NULL){
		printf("file_role.fps cannot be opened \n");
		return;
	}

	while (fgets(line, 1024, read)){

		if(strlen(line) <= 1)
			break;

		ino = 0;
		role = NULL;

		char *tmp = NULL;
		tmp = strdup(line); 
		sscanf(getfield(tmp, 1), "%lu", &ino);
		free(tmp);

		tmp = NULL;
		tmp = strdup(line);
		role = strdup(getfield(tmp, 2)); 
		free(tmp);

		enQueue_file(ino, role);
	}  
	fclose(read); 	
}

void rule_make_list(){

	FILE *read = fopen("/var/rule.rps", "r");
	int uid = 0;
	char line[1024];
	char *role = NULL, *accessible_roles = NULL;

	if(read == NULL){
		printf("rule.rps cannot be opened \n\n");
		return;
	}

	while (fgets(line, 1024, read)){

		if(strlen(line) <= 1)
			break;

		role = NULL;

		char *tmp = NULL;    
		tmp = strdup(line);
		role = strdup(getfield(tmp, 1)); 
		free(tmp);

		tmp = NULL;
		tmp = strdup(line);
		accessible_roles = strdup(getfield(tmp, 2)); 
		free(tmp);
		enQueue_rule(role, accessible_roles);
	}  
	fclose(read); 	
}

void disp_user_role(){

	FILE *read = fopen("user_role.ur", "r");
	int uid = 0;
	char line[1024];
	char *roles = NULL;
	printf("\n");
	printf("UserId\tRoles\tActiveRole\n\n");

	while (fgets(line, 1024, read)){

		uid = 0;
		roles = NULL;

		char *tmp = NULL;
		tmp = strdup(line); 
		printf("%s \n", tmp);
		free(tmp);
	}  
	fclose(read); 	
}

void add_user_role(int uid, char *roles){

	char *active_role;

	if(!check_role(roles)){
		printf("No rule for this role found, Enter another role \n");
		return;
	}

	if(check_uid(uid))
	{
		add_replace_role(uid, roles);
	}
	else{
		active_role = roles;
		enQueue(uid, roles, active_role);
	}
	write_user_role();
}

void change_user_role(int uid, char *active_role){

	printf("uid: %d\n", uid);
	
	if(check_uid(uid)){
		
		change_active_role(uid, active_role);
		write_user_role();
	}
	else{
		printf("Uid %d is not present, enter a valid entry \n", uid);
	}
}

void change_inode_role(long ino, char *role){
	
	if(check_ino(ino)){
		
		__change_inode_role(ino, role);
		write_file_role();
	}
	else{
		printf("ino %lu is not present, enter a valid entry \n", ino);
	}
}

void add_rule(char *role, char *accessible_roles){

	if(check_role(role)){
		printf("Role already exists \n\n");
		return;
	}
	else{
		enQueue_rule(role, accessible_roles);
		write_rule();
		printf("New rule added \n");
	}
}


void change_rule(char *role, char *new_accessible_roles){

	if(!check_role(role)){
		printf("Role doesn't exists Enter an existing role \n\n");
		return;
	}
	else{
		__change_rule(role, new_accessible_roles);
		write_rule();
		printf("Rule has been changed \n"); 
	}
}

int main(int argc, char *argv[]){

	char ch = ' ';
	int option = 0;

	if(getuid() != 0){
		printf("Unauthorized user, you cannot access the secuirty panel\n");
		return;
	}
	init_queue();
	init_queue_rule();
	init_queue_file();

	do{
		deinit_queue();
    	deinit_queue_rule();
    	deinit_queue_file();
		user_role_make_list();
		rule_make_list();
		file_make_list();

        printf("********Gnuplot Menu**************\n\n");
        printf("1. Display list of roles\n");
        printf("2. Display  rules\n");
        printf("3. Display file inode roles\n");
        printf("4. Add new User to Role\n");
        printf("5. Change user role\n");
        printf("6. Delete user\n");
        printf("7. Add new rule\n");
        printf("8. Change existing rule\n");
        printf("9. Change file inode role\n");
        printf("10. Delete file inode entry\n");

        printf("\n\n");
        printf("********************************** \n\n");
        printf("Enter a choice :");
        scanf("%d",&option);

        switch(option){

        	case 1:{display();
        			break;
        		}
        	case 2:{display_rule();
        			break;
        	}
        	case 3:{display_file();
        			break;
        	}
            case 4:{int uid = 0;
            		char *roles;
            		printf("Enter uid : ");
            		scanf("%d",&uid);
            		printf("\nEnter role : ");
            		roles = malloc(sizeof(char *));
            		scanf("%s",roles);
            		add_user_role(uid, roles);
                    break;} 
           	case 5: {
           			int uid = 0;
           			char *active_role;
           			printf("Enter uid : ");
            		scanf("%d",&uid);
            		printf("\nEnter new active_role : ");
            		active_role = malloc(sizeof(char *));
            		scanf("%s",active_role);
           			change_user_role(uid, active_role);
                    break;} 
            case 6: {
            		int uid = 0;
           			printf("Enter uid to delete : ");
            		scanf("%d",&uid);
           			delete_user_role(uid);
            		return;
            	}
            case 7: {char *role = NULL;
            		char *accessible_roles = NULL;
            		role = malloc(50);
            		accessible_roles = malloc(50);
            		memset(role, 0, 50);
            		memset(accessible_roles, 0, 50);
            		printf("\nEnter new role : ");
            		scanf("%s", role);
            		printf("\nEnter accessible roles : ");
            		scanf("%s", accessible_roles);
            		add_rule(role, accessible_roles);
            		break;
            	}
            case 8: {char *role = NULL;
            		char *accessible_roles = NULL;
            		role = malloc(50);
            		accessible_roles = malloc(50);
            		memset(role, 0, 50);
            		memset(accessible_roles, 0, 50);
            		printf("\nEnter role : ");
            		scanf("%s", role);
            		printf("\nEnter new accessible roles : ");
            		scanf("%s", accessible_roles);
            		change_rule(role, accessible_roles);
            		break;
            	}
            case 9:{
            		long ino = 0;
            		char *role = NULL;
            		role = malloc(50);
            		memset(role, 0, 50);
            		printf("\nEnter inode to change role : ");
            		scanf("%lu", &ino);
            		printf("\nEnter new role : ");
            		scanf("%s", role);
            		change_inode_role(ino, role);
            		break;
            	}
            	case 10:{
            		long ino = 0;
            		printf("\nEnter inode to delete : ");
            		scanf("%lu", &ino);
            		delete_inode(ino);
            		break;
            	}
            default: {printf("Enter a valid option \n");
                    break;}
        }

        printf("Do you want to continue ? :");
        scanf(" %c",&ch);
    }while((ch == 'y') || (ch == 'Y')); 

    deinit_queue();
    deinit_queue_rule();
    deinit_queue_file();
}
