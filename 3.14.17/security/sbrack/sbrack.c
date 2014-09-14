

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/tracehook.h>
#include <linux/security.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/buffer_head.h>
#include <linux/slab.h>
#include <linux/xattr.h>
#include "utils_kernel.h"

#define UDBG printk(KERN_DEFAULT "DBG:%s:%s:%d\n", __FILE__, __func__, __LINE__)

#ifdef CONFIG_SECURITY_SBRACK 


static int sbrack_inode_init_security(struct inode *inode, struct inode *dir, const struct qstr *qstr, const char **name, void **value, size_t *len)
{
	
	//UDBG; 
	char *temp = NULL;

	if(get_current_user()->uid.val >= 1000){

		if(inode){
			//continue
		}
		else{
			goto out;
		}

		parse_all();
		if(check_uid(get_current_user()->uid.val)){
			//printk("Uid exists\n");
		}
		else{
			printk("Uid don't exist\n");
			goto out;
		}
		if(check_ino(inode->i_ino)){
			//printk("Inode already exists\n");
			goto out;
		}
		else{
			//printk("making inode entry into file\n");
			temp = kmalloc(10, GFP_KERNEL);
			memset(temp, 0, 10);
			strcpy(temp, get_role(get_current_user()->uid.val));
			//strcpy(temp, "MGR");
			enQueue_file(inode->i_ino, temp);
    		write_file_role();
		}
	}

out:
	return 0;
}

static int sbrack_inode_create(struct inode *inode, struct dentry *dentry, umode_t mode)
{
	int ret = 0;
	char *i_role = NULL, *u_role = NULL;

	if(get_current_user()->uid.val >= 1000){
	
		if(inode){
			//continue
		}
		else{
			goto out;
		}

		parse_all();
		if(check_uid(get_current_user()->uid.val)){
			if(check_ino(inode->i_ino)){
				u_role = get_role(get_current_user()->uid.val);
				i_role = get_role_inode(inode->i_ino);

				if(u_role == NULL){
					goto out;
				}
				if(i_role == NULL){
					goto out;
				}

				if(check_permission(u_role, i_role)){
					//printk("inode create permission granted\n");
				}
				else{
					ret = -EPERM;
					goto out;
				}
			}
			else{
				//printk("inode create No parent inode mapping found\n");
				goto out;
			}
		}
		else{
			printk("inode create User has no mapping \n");
			//ret = -EPERM;
			goto out;
		}
	}
	
out:
	return ret;
}

static int sbrack_inode_link(struct dentry *old_dentry, struct inode *inode,
			  struct dentry *new_dentry)
{
	int ret = 0;
	char *i_role = NULL, *u_role = NULL;

	if(get_current_user()->uid.val >= 1000){
		
		if(old_dentry->d_inode){
			//continue
		}
		else{
			goto out;
		}

		parse_all();
		if(check_uid(get_current_user()->uid.val)){
			if(check_ino(old_dentry->d_inode->i_ino)){
				u_role = get_role(get_current_user()->uid.val);
				i_role = get_role_inode(old_dentry->d_inode->i_ino);

				if(u_role == NULL){
					goto out;
				}
				if(i_role == NULL){
					goto out;
				}

				if(check_permission(u_role, i_role)){
					//printk("hard_link permission granted\n");
				}
				else{
					ret = -EPERM;
					goto out;
				}
			}
			else{
				//printk("hard_lin No inode mapping found\n");
				goto out;
			}
		}
		else{
			printk("hard_lin User has no mapping \n");
			//ret = -EPERM;
			goto out;
		}
	} 

out:
	return ret;
}

static int sbrack_inode_unlink(struct inode *inode, struct dentry *dentry)
{
	int ret = 0;
	char *i_role = NULL, *u_role = NULL;

	if(get_current_user()->uid.val >= 1000){

		if(inode){
			//continue
		}
		else{
			goto out;
		}
		
		parse_all();
		if(check_uid(get_current_user()->uid.val)){
			if(dentry->d_inode){
				//continue
			}
			else{
				goto out;
			}

			if(check_ino(dentry->d_inode->i_ino)){
				u_role = get_role(get_current_user()->uid.val);
				i_role = get_role_inode(dentry->d_inode->i_ino);

				if(u_role == NULL){
					goto out;
				}
				if(i_role == NULL){
					goto out;
				}
				if(check_permission(u_role, i_role)){
					//printk("inode_unlink permission granted\n");

					deQueue_d_inode(dentry->d_inode->i_ino);
				}
				else{
					ret = -EPERM;
					goto out;
				}
			}
			else{
				//printk("inode_unlink No inode mapping found\n");
				goto out;
			}
		}
		else{
			printk("inode_unlink User has no mapping \n");
			//ret = -EPERM;
			goto out;
		}
	} 

out:
	return ret;
}

static int sbrack_inode_mkdir(struct inode *inode, struct dentry *dentry,
			   umode_t mode)
{
	int ret = 0;
	char *i_role = NULL, *u_role = NULL;

	if(get_current_user()->uid.val >= 1000){
		
		parse_all();
		if(check_uid(get_current_user()->uid.val)){
			if(check_ino(inode->i_ino)){
				u_role = get_role(get_current_user()->uid.val);
				i_role = get_role_inode(inode->i_ino);

				if(u_role == NULL){
					goto out;
				}
				if(i_role == NULL){
					goto out;
				}

				if(check_permission(u_role, i_role)){
					//printk("mkdir permission granted\n");
				}
				else{
					ret = -EPERM;
					goto out;
				}
			}
			else{
				//printk("mkdir No parent inode mapping found\n");
				goto out;
			}
		}
		else{
			printk("mkdir User has no mapping \n");
			//ret = -EPERM;
			goto out;
		}
	} 

out:
	return ret;
}

static int sbrack_inode_rmdir(struct inode *inode, struct dentry *dentry)
{
	int ret = 0;
	char *i_role = NULL, *u_role = NULL;

	if(get_current_user()->uid.val >= 1000){

		if(inode){
			//continue
		}
		else{
			goto out;
		}
		
		parse_all();
		if(check_uid(get_current_user()->uid.val)){
			if(dentry->d_inode){
				//continue
			}
			else{
				goto out;
			}
			
			if(check_ino(dentry->d_inode->i_ino)){
				u_role = get_role(get_current_user()->uid.val);
				i_role = get_role_inode(dentry->d_inode->i_ino);

				if(u_role == NULL){
					goto out;
				}
				if(i_role == NULL){
					goto out;
				}
				if(check_permission(u_role, i_role)){
					//printk("rmdir permission granted\n");

					deQueue_d_inode(dentry->d_inode->i_ino);
				}
				else{
					ret = -EPERM;
					goto out;
				}
			}
			else{
				//printk("rmdir No inode mapping found\n");
				goto out;
			}
		}
		else{
			printk("rmdir User has no mapping \n");
			//ret = -EPERM;
			goto out;
		}
	} 

out:
	return ret;
}

static int sbrack_inode_permission(struct inode *inode, int mask)
{
	int ret = 0;
	char *i_role = NULL, *u_role = NULL;

	if(get_current_user()->uid.val >= 1000){
		
		if(inode){
			//continue
		}
		else{
			goto out;
		}

		if(S_ISDIR(inode->i_mode)){
			goto out;
		}

		//parse_all();
		if(check_uid(get_current_user()->uid.val)){
			if(check_ino(inode->i_ino)){
				u_role = get_role(get_current_user()->uid.val);
				i_role = get_role_inode(inode->i_ino);

				if(u_role == NULL){
					goto out;
				}
				if(i_role == NULL){
					goto out;
				}

				if(check_permission(u_role, i_role)){
					//printk("inode_permission permission granted\n");
				}
				else{
					ret = -EPERM;
					goto out;
				}
			}
			else{
				//printk("inode_permission No parent inode mapping found\n");
				goto out;
			}
		}
		else{
			printk("inode_permission User has no mapping \n");
			//ret = -EPERM;
			goto out;
		}
	} 

out:
	return ret;
}

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


static int __init sbrack_init(void){
	/* register the hooks */	
	init_all();
	if (register_security(&sbrack_ops))
		printk("sbrack: Unable to register sbrack with kernel.\n");
	else 
		printk("sbrack: registered with the kernel\n");

	return 0;
}

static void __exit sbrack_exit (void)
{	
	deinit_all();
	printk("**************Exit************** \n");
}



module_init (sbrack_init);
module_exit (sbrack_exit);

MODULE_DESCRIPTION("sbrack");
MODULE_LICENSE("GPL");
#endif /* CONFIG_SECURITY_sbrack */

