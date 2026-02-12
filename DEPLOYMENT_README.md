# MyProctor.ai VPS Deployment Guide

This guide will help you deploy the MyProctor.ai online proctoring system to a new Ubuntu 20.04 VPS.

## Prerequisites

- Ubuntu 20.04 VPS with root access
- SSH access to the VPS
- Project files uploaded to the VPS

## Step-by-Step Deployment

### 1. Upload Project Files

Upload the entire project directory to your VPS, for example to `/tmp/project`:

```bash
scp -r /path/to/local/project user@vps-ip:/tmp/project
```

### 2. Run the Deployment Script

Connect to your VPS via SSH:

```bash
ssh user@vps-ip
```

Run the deployment script:

```bash
sudo bash /tmp/project/deploy_to_vps.sh
```

The script will:
- Update the system
- Install required packages (Python, nginx, MySQL)
- Set up the project in `/var/www/html/myproctorai`
- Create a virtual environment and install dependencies
- Set up the database
- Configure systemd service for the Flask app
- Configure nginx as a reverse proxy
- Open necessary firewall ports

### 3. Access the Application

Once deployment is complete, access MyProctor.ai at:

```
http://your-vps-ip
```

### 4. Post-Deployment Configuration

#### Database Setup
The script runs `setup_db.py` which creates the MySQL database `quizapp` with the required tables from `DB/quizappstructure.sql`.

#### Static Files
Static files are served directly by nginx from `/var/www/html/myproctorai/static`.

#### SSL Certificate (Optional)
For production, consider adding SSL:

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
```

## Troubleshooting

### Check Service Status
```bash
sudo systemctl status myproctorai
sudo systemctl status nginx
```

### View Logs
```bash
sudo journalctl -u myproctorai -f
sudo tail -f /var/log/nginx/error.log
```

### Restart Services
```bash
sudo systemctl restart myproctorai
sudo systemctl reload nginx
```

## Security Considerations

- Change default passwords
- Restrict SSH access (use key-based authentication)
- Keep the system updated
- Monitor logs regularly

## Features Included

- User registration and login (students and professors)
- Exam creation and management
- Real-time proctoring with behavioral monitoring
- Question generation (objective and subjective)
- Results publishing
- Live monitoring dashboard

The application runs on port 5000 behind nginx reverse proxy on port 80.
