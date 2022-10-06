import getopt
import sys
from utils.login import login

def main(argv):
    help_meg = "usage:python main.py -u your_account_name -p your_password"
    try:
        opts,args = getopt.getopt(args=argv, shortopts="-u:-p:-h")
    except Exception as e:
        print(help_meg)
        return -1
    state = {"show-help":False}
    for opt in opts:
        if opt[0] == "-u":
            state["username"] = opt[1]
        elif opt[0] == "-p":
            state["password"] = opt[1]
        elif opt[0] == "-h":
            state["show-help"] = True
    if state["show-help"]:
        print(help_meg)
        return 0
    if login(state):
        print("login successfully")

if __name__ == "__main__":
    main(sys.argv[1:])