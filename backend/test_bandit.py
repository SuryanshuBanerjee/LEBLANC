
import subprocess

def executeCommand():
    command = input('Enter a command: ')
    try:
        output = subprocess.check_output(command, shell=True)
        print(output.decode('utf-8'))
    except Exception as e:
        print(e)
