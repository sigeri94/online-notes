#!/bin/bash

# Database configuration (modify these values as needed)
DB_USER="root"
DB_PASS=""
DB_NAME="wordpress"

# Check if IP address is provided as an argument
if [ -z "$1" ]; then
  echo "Usage: $0 <new_site_url>"
  exit 1
fi

NEW_URL="$1"

# Execute MySQL commands to update siteurl and home
mysql -u"$DB_USER" -p"$DB_PASS" "$DB_NAME" <<EOF
UPDATE wp_options SET option_value = 'http://$NEW_URL' WHERE option_name = 'siteurl';
UPDATE wp_options SET option_value = 'http://$NEW_URL' WHERE option_name = 'home';
EOF

if [ $? -eq 0 ]; then
  echo "Successfully updated siteurl and home to http://$NEW_URL"
else
  echo "Failed to update the database. Please check the connection and credentials."
fi
