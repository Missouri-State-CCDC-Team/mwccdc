#!/bin/bash

# Variables
ROOT_PASSWORD="root"              # Replace with the new root password
SYSADMIN_PASSWORD="root"      # Replace with the new sysadmin password
PRESTASHOPUSER_PASSWORD="root" # Replace with the new PrestaShop user password
COOKIE_VALUE="Cgqd54npQuGSCxZwRN6fP645XpKqcI8q7kXkNFohtQvQiso2uo7R5DXH"                    # Replace with the cookie value
NEW_ADMIN_PASSWORD="admin"        # Replace with the new admin portal password
ADMIN_EMAIL="zongxiliu@missouristate.edu"          # Replace with the admin email
ALLOWED_SSH_IP="172.20.242.12"                # Replace with the IP allowed for SSH
       # Apache configuration file
PRESTASHOP_CONF="/var/www/html/config/settings.inc.php" # Replace with the actual path



# Step 2: Update MySQL root and PrestaShop user's password
echo "Updating MySQL root and PrestaShop user passwords..."
sudo mysql -u root -p <<EOF
SET PASSWORD FOR 'root'@'localhost' = PASSWORD('$ROOT_PASSWORD');
SET PASSWORD FOR 'prestashopuser'@'localhost' = PASSWORD('$PRESTASHOPUSER_PASSWORD');
FLUSH PRIVILEGES;
EOF

# Update PrestaShop configuration file
echo "Updating PrestaShop configuration file..."
sudo sed -i "s/define('_DB_PASSWD_', .*/define('_DB_PASSWD_', '$PRESTASHOPUSER_PASSWORD');/g" $PRESTASHOP_CONF

#

# Restart services
echo "Restarting MariaDB and Apache..."
sudo systemctl restart mariadb httpd

# Step 3: Update PrestaShop admin portal password
echo "Updating PrestaShop admin portal password..."

sudo mysql -u root -p$ROOT_PASSWORD <<EOF
USE prestashop;
UPDATE ps_employee SET passwd=MD5('$COOKIE_VALUE$NEW_ADMIN_PASSWORD') WHERE email='$ADMIN_EMAIL';
EOF

# Step 4: Configure firewalld
echo "Configuring firewalld..."
sudo firewall-cmd --permanent --set-default-zone=drop
sudo firewall-cmd --permanent --add-port=80/tcp
sudo firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='$ALLOWED_SSH_IP' port port=22 protocol=tcp accept"
sudo firewall-cmd --reload

echo "Configuration completed successfully."
