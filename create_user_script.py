import argparse
import crypt
import pwd
import os
import stat

def remove_permissions(path):
    """Remove write permissions from this path, while keeping all other permissions intact.

    Params:
        path:  The path whose permissions to alter.
    """
    NO_GROUP_WRITING = ~stat.S_IWGRP
    NO_OTHER_WRITING = ~stat.S_IWOTH
    NO_GROUP_READING = ~stat.S_IRGRP
    NO_OTHER_READING = ~stat.S_IROTH
    NO_GROUP_EXEC = ~stat.S_IXGRP
    NO_OTHER_EXEC = ~stat.S_IXOTH
    NO_USER_EXEC = ~stat.S_IXUSR
    NO_PERMISSION = NO_GROUP_WRITING & NO_OTHER_WRITING & NO_GROUP_READING & NO_OTHER_READING & NO_GROUP_EXEC & NO_OTHER_EXEC & NO_USER_EXEC

    current_permissions = stat.S_IMODE(os.lstat(path).st_mode)
    os.chmod(path, current_permissions & NO_PERMISSION)

def config_argument_parser():
    parser = argparse.ArgumentParser(description='Creating and setting up user for YandexWorkshop')
    parser.add_argument(
        '-u',
        '--user-name',
        required=True,
        help='User login'
    )
    parser.add_argument(
        '-p',
        '--user-password',
        help='User password'
    )

    parser.add_argument(
        '--ssh-key',
        help='Public SSH key'
    )
    parser.add_argument(
        '--ssh-key-file',
        help='Public SSH key file'
    )

    return parser

if __name__ == '__main__':
    parser = config_argument_parser()
    args = parser.parse_args()

    print(f'Create user "{args.user_name}"')
    print('\tCreate user profile... ', end='')
    
    user_dir = f'/home/{args.user_name}'
    ssh_dir = f'{user_dir}/.ssh'
    key_file = f'{ssh_dir}/authorized_keys'
    sudo_as_admin_file = f'{user_dir}/.sudo_as_admin_successful'

    try:
        crypt_pass = crypt.crypt(
            args.user_password if args.user_password else 'P0o9i8u7y6',
            '22'
        )
        res = os.system(f'/usr/sbin/useradd --create-home --home-dir={user_dir} --shell=/usr/bin/bash --password={crypt_pass} {args.user_name}')
        if res==0:
            print('OK')
        else:
            print(f'ERROR (code: {res})')
            exit(-1)
    except Exception as e:
        print('ERROR')
        print(e)
        exit(-1)

    user_info = pwd.getpwnam(args.user_name)

    print(f'\tCreate {ssh_dir} dir... ', end='')
    try:
        os.mkdir(ssh_dir)
        print('OK')
    except Exception as e:
        print('ERROR')
        print(e)
        exit(-1)

    print(f'\tCreate {sudo_as_admin_file} file... ', end='')
    try:
        with open(sudo_as_admin_file, 'w', encoding='utf-8'):
            pass
        print('OK')
    except Exception as e:
        print('ERROR')
        print(e)
        exit(-1)
    
    print(f'\tCreate {key_file} file... ', end='')
    try:
        with open(key_file, 'w', encoding='utf-8') as f:
            if args.ssh_key:
                f.write(args.ssh_key)
            elif args.ssh_key_file:
                with open(args.ssh_key_file,'r', encoding='utf-8') as rf:
                    lines = rf.readlines()
                    f.writelines(lines)
        
        print('OK')
    except Exception as e:
        print('ERROR')
        print(e)
        exit(-1)
    
    print(f'\tChange {ssh_dir} owner and permission... ', end='')
    try:
        os.chown(ssh_dir, uid=user_info.pw_uid, gid=user_info.pw_gid)
        remove_permissions(ssh_dir)
        print('OK')
    except Exception as e:
        print('ERROR')
        print(e)
        exit(-1)

    print(f'\tChange {key_file} owner and permission... ', end='')
    try:
        os.chown(key_file, uid=user_info.pw_uid, gid=user_info.pw_gid)
        remove_permissions(key_file)
        print('OK')
    except Exception as e:
        print('ERROR')
        print(e)
        exit(-1)

    print(f'\tChange {sudo_as_admin_file} owner and permission... ', end='')
    try:
        os.chown(sudo_as_admin_file, uid=user_info.pw_uid, gid=user_info.pw_gid)
        remove_permissions(sudo_as_admin_file)
        print('OK')
    except Exception as e:
        print('ERROR')
        print(e)
        exit(-1)

    print('Summary info:')
    print(f'\tLogin: {args.user_name}')
    print(f'\tPassword: {args.user_password if args.user_password else "P0o9i8u7y6"}')
    print(f'\tAuthorized key file: {key_file}')

