import argparse
#from pwn import *

parser = argparse.ArgumentParser()
parser.add_argument('param', help='<Help text>')
parser.add_argument('-s', '--start', type=int, help='Initial byte to check.')

args = parser.parse_args()


