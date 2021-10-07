#!/bin/bash

# install PostgreSQL

# Install the repository RPM:
sudo dnf install -y https://download.postgresql.org/pub/repos/yum/reporpms/F-34-x86_64/pgdg-fedora-repo-latest.noarch.rpm

# Install PostgreSQL:
sudo dnf install -y postgresql14-server

# Optionally initialize the database and enable automatic start:
sudo /usr/pgsql-14/bin/postgresql-14-setup initdb
sudo systemctl enable postgresql-14
sudo systemctl start postgresql-14

# configure firewalld when running
sudo firewall-cmd --add-service=postgresql --permanent
sudo firewall-cmd --reload

# config file - listen_addresses = '*'
sudo cat /var/lib/pgsql/14/data/postgresql.conf | grep listen_addresses

# alter administrator password
sudo su - postgres 
psql -c "alter user postgres with password '12345'"

# create test user
createuser testuser
createdb testdb -O testuser

