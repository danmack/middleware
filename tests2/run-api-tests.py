import argparse
import ipaddress
import json
import pathlib
import subprocess
import sys

from constants import API_CFG_FILE


def validate_vm_ips(args, info):
    # shouldn't happen
    assert any((args.ips is not None, args.ip is not None))

    is_ha = args.ips is not None
    info.update({'ip1': None, 'ip2': None, 'vip': None, 'is_ha': is_ha})
    idx = 0
    for ip in (args.ips if is_ha else args.ip):
        if (ip := ip.strip()):
            if idx > 3:
                raise ValueError('No more than 3 IP addresses accepted for HA')
            else:
                idx += 1
                info[f'ip{idx}'] = ipaddress.ip_interface(ip).ip.compressed

    if is_ha and not all((info['ip1'], info['ip2'])):
        raise ValueError('2 IP addresses required for HA')
    elif not info['ip1']:
        raise ValueError('1 IP Address is required')


def validate_user_and_pass(args, info):
    if args.username is None or not args.username.strip():
        raise ValueError('Username is required')
    elif args.password is None or not args.password.strip():
        raise ValueError('Password is required')

    info['username'] = args.username
    info['password'] = args.password


def validate_args(args):
    info = dict()
    validate_user_and_pass(args, info)
    validate_vm_ips(args, info)
    return info


def generate_api_config_file(args, info):
    """Write this file to whatever directory we're
    in. This file is a json formatted file that gets
    read in and stored as global variables to be
    referenced in our API test suite. The intended
    purpose of these variables are to provide some
    initial context to the test suite run."""
    with open(API_CFG_FILE, 'w') as f:
        f.write(json.dumps(info))


def setup_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--username',
        default='root',
        required=False,
        help='The username to be used for running the API tests (default: %(default)s)',
    )
    parser.add_argument(
        '--password',
        default='testing',
        required=False,
        help='The password to be used for running the API tests (default: %(default)s)',
    )

    group1 = parser.add_mutually_exclusive_group(required=False)
    group1.add_argument(
        '--tdir',
        default=False,
        help='Relative path to the test directory (i.e. tests/smb)'
    )
    group1.add_argument(
        '--tfile',
        default=False,
        help='Relative path to the test file (i.e. tests/smb/test_blah.py)'
    )

    group2 = parser.add_argument_group('Controller IP Address(es)')
    exgrp = group2.add_mutually_exclusive_group(required=True)
    exgrp.add_argument('--ip', nargs=1, help='Controller\'s IP Address. (assumes non-HA)')
    exgrp.add_argument(
        '--ips',
        nargs='*',
        help='HA IP Addresses. Order matters! (i.e. A_IP, B_IP, VIP) (NOTE: VIP is NOT required)'
    )

    return parser.parse_args()


def setup_api_results_dir(resultsfile='results.xml'):
    # create the results directory
    path = pathlib.Path(pathlib.os.getcwd()).joinpath('results')
    path.mkdir(exist_ok=True)

    # add the file that will store the api results
    path = path.joinpath(resultsfile)
    try:
        path.unlink()
    except FileNotFoundError:
        pass

    path.touch()

    return path.as_posix()


def setup_pytest_command(args, results_path):
    # we run inside a venv so make sure to use proper pytest module
    cmd = [sys.executable, '-m', 'pytest', '-v', '-rfesp']

    # pytest is clever enough to search the "tests" subdirectory
    # and look at the argument that is passed and figure out if
    # it's a file or a directory so we don't need to do anything
    # fancy other than pass it on
    if args.tfile:
        cmd.append(args.tfile)
    elif args.tdir:
        cmd.append(args.tdir)

    cmd.extend(['-o', 'junit_family=xunit2', f'--junit-xml={results_path}'])

    return cmd


def main():
    args = setup_args()
    print('Validating Args')
    info = validate_args(args)

    print('Generating API config file')
    generate_api_config_file(args, info)

    print('Setting up API results directory')
    results_path = setup_api_results_dir()

    print('Running API tests')
    subprocess.call(setup_pytest_command(args, results_path))


if __name__ == '__main__':
    main()
