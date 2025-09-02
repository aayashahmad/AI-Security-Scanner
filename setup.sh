#!/bin/bash

# AI Security Agent Setup Script

echo "Setting up AI Security Agent..."

# Install dependencies
echo "Installing dependencies..."
npm install

# Create results directory
echo "Creating results directory..."
mkdir -p results

# Copy .env.example to .env if .env doesn't exist
if [ ! -f .env ]; then
  echo "Creating .env file from .env.example..."
  cp .env.example .env
  echo "Please edit .env file to configure your target domain and other settings."
fi

echo "Setup complete! You can now run the security agent with 'npm start'."
echo "Make sure to edit the .env file to set your target domain before running."