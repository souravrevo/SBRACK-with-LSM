STONYBROOK ID: 109597685
NAME: Kumar Sourav


1. INTRODUCTION:

This README is about Role Based Access Control sytem which is implemented in Linux Kernel 3.14.17 (vanilla).
There is a user program and LSM module to exploit hooks for makeing RBAC model. The key in the assignment 
is to put proper functions in LSM to interceptcalls before they actually hit the object.

RBAC is a security model which is quiet close to SELinux. In RBAC there are roles insead of access control
lists. Each user is assigned a given role by the system administrator. Each file is also assigned a role 
upon creation which is retained for future actions. There are rules which tell which role can access which
role. All these roles and rules according to roles are stored in the policy store.

2. HOW TO COMPILE AND RUN CODE:

Following are the steps to compile and run the code:

a) User Program: To compile user program follow following steps:

		 i) run compile_user.sh with root permissions
		 ii) It will also copy 3 files namely file_role.fps, user_role.ups and rule.rps to /var.
		     The policy store resides under /var.    

b) Kernel files: To compile the kernel code downlod kernel 3.14.17 from kernel.org. The folllwoing files and
   		 folders need to be placed under 3.14.17:

		 i) Put sbrack folder under 3.14.17/security/
		 ii) Put modified Kconfig and MAKEFILE under 3.14.17/security/   

c) Integrate and run: To run the sbrack follow following steps:
		 
		 i) Goto make menuconfig and select sbrack as default security option.
		 ii) Also check sbrack option in security in make menuconfig
		 iii) make
		 iv) make modules_install
		 v) make install.
 

3. SYSTEM DESIGN:

I have implemented policy store using three files namely file_role.fps, user_role.ups and rule.rps. The 
admin can change the policy store from user program. Only root can make changes to policy store. Whenever
and event like touch, mkdir, rmdir etc occur the monitor intercepts the call, checks the role of the inode
involved in the call with the active role of the user who made the event. If the rule specified in rule.rps 
says that the user can perform the operation then access is granted else appropriate error is returned.
There are similar checks in functions implemnted. The hooks given in security.h have been used to achieve
this functionality. 

4. SYSTEM ELEMENTS:

The system design consits of the following parts:

a) Files: There are three files namely file_role.fps, user_role.ups and rules.rps. Here ps stands for 
	  policy store. file_role.fs contains file inode and their roles, user_role.ups contain user
	  id, set of possible roles that can be alloted and active role, rule.rps contains rules which
	  tell which role can access which other role.

b) User program: User program is controlled by the admin or the root user. Admin can create new user role
		 mappings by adding new user and his active role to user_role.ups. It can also delete and
		 change active role of users. Admin can create new rules by making entry into ruleprps file.
		 Admin can also change or delete file inode to role mapping in file_role.fps file. Note
		 all the three files belong to the policy store of RBAC.

c) Kernel level reference monitor: Kernel level reference monitor is implemented as a kernel module which
		 used the LSM API's. This reference monitor periodically reads all the three files from
		 the policy store makes a linked list which it retains in memory for comparing roles.
		 When a user makes an inode specific event like mkdir, touch etc, these calls are intercepted
		 by the LSM hooks mentioned in security.h. After a call is intercepted the monitor compares 
		 the roles and makes a decision if the access should be granted or not.

5. FEATURES SUPPORTED:

In this design if a user has permission to do something then it can do all operations like read, write, execute,
delete etc and if the user don't have the permission then it cannot perform any operation. Permission is decided
by comparing the role of the file inode with the active role of the user. If the rule says that the active role
of user has permission to access files associated with the given role then the access is granted.

Following are some of the features implemented: 

a) Mkdir: This can be done by mkdir command. SBRACK will first compare the role of parent directory inode with
	  that of the user if it has permission then the user will be able to create the directory in a given 
	  folder. In case the parent directory has been assigned a role then the permission is granted. The inode
	  is assigned the active role of the current user and an entry is made into file_role.fps. 

b) Rmdir: This can be done by rmdir command. SBRACK will straigh away compare the role of file inode with the 
	  active role of the user and decide if it can delete the directory or not. The corresponding entry is
	  deleted from file_role.fps.

c) Create file: This can be done by touch command. SBRACK will compare the role of the parent directory inode with that
	  of the user and decide if the access is granted.  The inode is assigned the active role of the current user 
	  and an entry is made into file_role.fps. 

d) Delete file: This can be done by rm command. SBRACK will compare the role of the file inode to be deleted with that
	  of the user and decide if the access is granted. The corresponding entry is deleted from file_role.fps.

e) Hardlink: This can be done by ln command. SBRACK will compare the role of inode of which link is to be created with
	  role of the user and give access accordingly. No entry is made for hardlink ink file_role.fps as hardlink has
	  no inode of its own and only points to the inode of another file.

f) Read/Write permission: When you try to read/write a file SBRACK will compare the file inode role with the user active
	  role and decide whether to give permission to read/write or not.


6. LSM hooks exploited:  

Following is the struct of the inode operations implemented by SBRACK

static struct security_operations sbrack_ops = {
	.name =				"s",
	.inode_init_security =		sbrack_inode_init_security,
	.inode_create =			sbrack_inode_create,
	.inode_link =			sbrack_inode_link,
	.inode_unlink =			sbrack_inode_unlink,
	.inode_mkdir =			sbrack_inode_mkdir, 
	.inode_rmdir =			sbrack_inode_rmdir,
	.inode_permission =		sbrack_inode_permission
};

a) sbrack_inode_init_security: Assigns role to inode and saves it to file_role.fps
b) sbrack_inode_create: Checks for permission before file gets created
c) sbrack_inode_link: Checks for permission before hardlink is created
d) sbrack_inode_unlink: Deletes an inode and removes its entry from file_role.fps
e) sbrack_inode_mkdir: Checks for permission before directory gets created
f) sbrack_inode_rmdir: Checks for permission before directory gets deleted
g) sbrack_inode_permission: Checks for permission before read/write operations.

7. List of files for submission:

Kernel files:

3.14.17/security/sbrack/Kconfig: SBRACK Kconfig
3.14.17/security/sbrack/Makefile: SBRACK MAKEFILE
3.14.17/security/sbrack/modules.builtin
3.14.17/security/sbrack/modules.order
3.14.17/security/sbrack/sbrack.c : Main SBRACK program implementing LSM
3.14.17/security/sbrack/utils_kernel.h: Header file for functions

3.14.17/security/MAKEFILE: Security MAKEFILE
3.14.17/security/Kconfig: Security Kconfig


User files:

user_program/rbac_panel.c
user/program/utils.h

Policy store files:

file_role.fps
user_file.ups 
rule.rps
