cd user_program/
gcc rbac_panel.c -o rbac_panel.o
cd ..

sudo cp policy_store/file_role.fps /var
sudo cp policy_store/user_role.ups /var
sudo cp policy_store/rule.rps /var

sudo chmod 777 /var/file_role.fps
sudo chmod 777 /var/user_role.ups
sudo chmod 777 /var/rule.rps
