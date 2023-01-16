from argparse import ArgumentParser


def argument():
    arg = ArgumentParser()
    arg.add_argument('-t', '--target', type=str,
                     required=True, help='Enter the ip target')
    arg.add_argument('-g', '--gateway', type=str,
                     required=True, help='Enter the ip gateway')
    return arg.parse_args()
