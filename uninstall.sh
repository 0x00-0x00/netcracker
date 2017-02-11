#!/bin/bash
# Uninstall script for python packages installed with setup.py
# Written by zc00l

PYTHON_VER="python3.6"
PROGRAM_NAME="netcracker"
PYTHON_FOLDER="/usr/local/lib/${PYTHON_VER}/site-packages/${PROGRAM_NAME}*"
uid=$(id -u);

function check_root
{
    if [[ $1 != 0 ]]; then
        echo "[!] You do not have enough permissions to run this script.";
        exit;
    fi
    return 0;
}

function check_folder
{
    if [[ -e "$1" ]]; then
        echo "FAIL";
    else
        echo "OK";
    fi
    return 0;
}

function delete_package
{
    echo -n "[*] Deleting package '${PROGRAM_NAME}' ... ";
    rm -r $1;
    check_folder $1;
    return 0;
}

check_root ${uid};
delete_package ${PYTHON_FOLDER};
exit;
