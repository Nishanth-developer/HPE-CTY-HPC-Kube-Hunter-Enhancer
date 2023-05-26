
#!/bin/bash

# Check if Git is installed and install it if not
if ! command -v git &> /dev/null; then
    echo "Git not found. Installing Git..."
    sudo apt-get update
    sudo apt-get install git -y
fi

# Create the target directory in Documents folder
mkdir -p ~/Documents/target_directory

# Clone the private repository
git clone https://github.com/Nishanth-developer/HPE-CTY-HPC-Kube-Hunter-Enhancer.git

# Copy the contents of kube-hunter-enhancer directory to the target directory
cp -r HPE-CTY-HPC-Kube-Hunter-Enhancer/kube-hunter-enhancer/* ~/Documents/target_directory/

# Navigate to the app directory
cd ~/Documents/target_directory

# Clear the contents of yaml directory
rm -rf ~/Documents/target_directory/yaml/*

# Clear the contents of file.json and kube-hunter-logs.txt
echo "" > ~/Documents/target_directory/file.json
echo "" > ~/Documents/target_directory/kube-hunter-logs.txt

# Install the necessary packages using pip
pip install -r requirements.txt

# Run the main.py file
python3 main.py
