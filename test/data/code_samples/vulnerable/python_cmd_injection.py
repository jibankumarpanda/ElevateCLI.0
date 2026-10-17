import os
import subprocess


def run_user_command(user_input):
    # Vulnerable: executes arbitrary shell input.
    os.system("echo " + user_input)
    return eval(user_input)
