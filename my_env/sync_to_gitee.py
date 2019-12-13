import os
import sys
import datetime
import yaml
import argparse
import multiprocessing
curr_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(curr_dir, '../'))

os.chdir(curr_dir)

#git remote add my_work git@gitee.com:sisyphus12/my_work.git

def install_tool():
    tools = ['openssh-server','g++-6','gdb','syncthing']
    for tool in tools:
        cmd = 'apt -y install ' + tool
        print cmd
        print os.popen(cmd).read()

#cmds = ['git push ']
config_files = ['~/.vimrc','/etc/ssh/sshd_config']
for config_file in config_files:
    cmd = 'cp ' + config_file + " ~/my_work/my_env"
    print cmd
    print os.popen(cmd).read()

print curr_dir
