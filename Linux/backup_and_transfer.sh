
DB_USER="root"
DB_NAME="prestashop"
BACKUP_FILE1="prestashop_bk.sql"
BACKUP_FILE2="prestashop.zip"
FEDORA_USER="root"              # Replace with your Fedora username
FEDORA_IP="172.20.241.42"           # Replace with your Fedora server's IP address
FEDORA_DESTINATION="/home/$FEDORA_USER" # Path to store the files on Fedora

# Step 1: Back up the database
echo "Backing up the PrestaShop database..."
mysqldump -u $DB_USER -p $DB_NAME > ~/$BACKUP_FILE1

if [ $? -ne 0 ]; then
  echo "Error: Database backup failed."
  exit 1
fi

echo "Database backup completed: $BACKUP_FILE"

# Step 2: Copy the backup file to the Fedora server
echo "Transferring backup file to Fedora server..."
scp ~/$BACKUP_FILE1 $FEDORA_USER@$FEDORA_IP:$FEDORA_DESTINATION
scp ~/$BACKUP_FILE2 $FEDORA_USER@$FEDORA_IP:$FEDORA_DESTINATION

if [ $? -ne 0 ]; then
  echo "Error: File transfer failed."
  exit 1
fi

echo "Backup file successfully transferred to Fedora server: $FEDORA_DESTINATION/$BACKUP_FILE1 & $BACKUP_FILE2"
