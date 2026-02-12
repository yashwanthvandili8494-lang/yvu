#!/bin/bash

# Deployment script for MyProctor.ai to Ubuntu 20.04 VPS
# Run this script on the VPS as root or with sudo

echo "Starting deployment of MyProctor.ai to Ubuntu 20.04 VPS..."

# Update system
echo "Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install Python and pip
echo "Installing Python and pip..."
sudo apt install python3 python3-pip python3-venv -y

# Install nginx
echo "Installing nginx..."
sudo apt install nginx -y

# Install MySQL
echo "Installing MySQL..."
sudo apt install mysql-server -y
sudo systemctl enable mysql
sudo systemctl start mysql

# Create project directory
echo "Creating project directory..."
sudo mkdir -p /var/www/html/myproctorai
sudo chown -R $USER:$USER /var/www/html/myproctorai

# Copy project files (assuming they are uploaded to /tmp/project)
echo "Copying project files..."
cp -r /tmp/project/* /var/www/html/myproctorai/

# Navigate to project directory
cd /var/www/html/myproctorai

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install Python dependencies
echo "Installing Python dependencies..."
pip install -r requirements.txt

# Install NLTK data
echo "Installing NLTK data..."
python -c "import nltk; nltk.download('all')"

# Set up database
echo "Setting up database..."
python setup_db.py

# Create systemd service for Flask app
echo "Creating systemd service..."
sudo tee /etc/systemd/system/myproctorai.service > /dev/null <<EOF
[Unit]
Description=MyProctor.ai Flask App
After=network.target

[Service]
User=$USER
Group=$USER
WorkingDirectory=/var/www/html/myproctorai
Environment="PATH=/var/www/html/myproctorai/venv/bin"
ExecStart=/var/www/html/myproctorai/venv/bin/python app.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Start and enable service
echo "Starting Flask service..."
sudo systemctl daemon-reload
sudo systemctl start myproctorai
sudo systemctl enable myproctorai

# Configure nginx
echo "Configuring nginx..."
sudo tee /etc/nginx/sites-available/myproctorai > /dev/null <<EOF
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location /static {
        alias /var/www/html/myproctorai/static;
    }
}
EOF

# Enable nginx site
sudo ln -s /etc/nginx/sites-available/myproctorai /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx

# Open firewall ports
echo "Configuring firewall..."
sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'
sudo ufw --force enable

echo "Deployment complete!"
echo "MyProctor.ai should now be accessible at http://your-vps-ip"
echo "Check service status: sudo systemctl status myproctorai"
echo "Check nginx status: sudo systemctl status nginx"
