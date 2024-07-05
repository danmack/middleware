from auto_config import password, pool_name, user
from middlewared.test.integration.assets.pool import dataset as nfs_dataset
from middlewared.test.integration.assets.nfs import nfs_start
from middlewared.test.integration.utils import call
from middlewared.test.integration.utils.client import truenas_server
from protocols import SSH_NFS, nfs_share


def test_nfsv4_acl_support():
    """
    This test validates reading and setting NFSv4 ACLs through an NFSv4
    mount in the following manner for NFSv4.2, NFSv4.1 & NFSv4.0:
    1) Create and locally mount an NFSv4 share on the TrueNAS server
    2) Iterate through all possible permissions options and set them
    via an NFS client, read back through NFS client, and read resulting
    ACL through the filesystem API.
    3) Repeat same process for each of the supported ACE flags.
    4) For NFSv4.1 or NFSv4.2, repeat same process for each of the
    supported acl_flags.
    """
    acl_nfs_path = f'/mnt/{pool_name}/test_nfs4_acl'
    test_perms = {
        "READ_DATA": True,
        "WRITE_DATA": True,
        "EXECUTE": True,
        "APPEND_DATA": True,
        "DELETE_CHILD": True,
        "DELETE": True,
        "READ_ATTRIBUTES": True,
        "WRITE_ATTRIBUTES": True,
        "READ_NAMED_ATTRS": True,
        "WRITE_NAMED_ATTRS": True,
        "READ_ACL": True,
        "WRITE_ACL": True,
        "WRITE_OWNER": True,
        "SYNCHRONIZE": True
    }
    test_flags = {
        "FILE_INHERIT": True,
        "DIRECTORY_INHERIT": True,
        "INHERIT_ONLY": False,
        "NO_PROPAGATE_INHERIT": False,
        "INHERITED": False
    }
    for (version, test_acl_flag) in [(4, True), (4.1, True), (4.0, False)]:
        theacl = [
            {"tag": "owner@", "id": -1, "perms": test_perms, "flags": test_flags, "type": "ALLOW"},
            {"tag": "group@", "id": -1, "perms": test_perms, "flags": test_flags, "type": "ALLOW"},
            {"tag": "everyone@", "id": -1, "perms": test_perms, "flags": test_flags, "type": "ALLOW"},
            {"tag": "USER", "id": 65534, "perms": test_perms, "flags": test_flags, "type": "ALLOW"},
            {"tag": "GROUP", "id": 666, "perms": test_perms.copy(), "flags": test_flags.copy(), "type": "ALLOW"},
        ]
        ds_config = {"acltype": "NFSV4", "aclmode": "PASSTHROUGH"}
        with nfs_dataset("test_nfs4_acl", data=ds_config, acl=theacl):
            with nfs_share(acl_nfs_path):
                with nfs_start():
                    with SSH_NFS(truenas_server.ip, acl_nfs_path, vers=version,
                                 user=user, password=password, ip=truenas_server.ip) as n:
                        nfsacl = n.getacl(".")
                        for idx, ace in enumerate(nfsacl):
                            assert ace == theacl[idx], str(ace)

                        for perm in test_perms.keys():
                            if perm == 'SYNCHRONIZE':
                                # break in SYNCHRONIZE because Linux tool limitation
                                break

                            theacl[4]['perms'][perm] = False
                            n.setacl(".", theacl)
                            nfsacl = n.getacl(".")
                            for idx, ace in enumerate(nfsacl):
                                assert ace == theacl[idx], str(ace)

                            res = call('filesystem.getacl', acl_nfs_path, False)
                            for idx, ace in enumerate(res['acl']):
                                assert ace == nfsacl[idx], str(ace)

                        for flag in ("INHERIT_ONLY", "NO_PROPAGATE_INHERIT"):
                            theacl[4]['flags'][flag] = True
                            n.setacl(".", theacl)
                            nfsacl = n.getacl(".")
                            for idx, ace in enumerate(nfsacl):
                                assert ace == theacl[idx], str(ace)

                            res = call('filesystem.getacl', acl_nfs_path, False)
                            for idx, ace in enumerate(res['acl']):
                                assert ace == nfsacl[idx], str(ace)

                        if test_acl_flag:
                            assert 'none' == n.getaclflag(".")
                            for acl_flag in ['auto-inherit', 'protected', 'defaulted']:
                                n.setaclflag(".", acl_flag)
                                assert acl_flag == n.getaclflag(".")
                                res = call('filesystem.getacl', acl_nfs_path, False)
                                # Normalize the flag_is_set name for comparision to plugin equivalent
                                # (just remove the '-' from auto-inherit)
                                if acl_flag == 'auto-inherit':
                                    flag_is_set = 'autoinherit'
                                else:
                                    flag_is_set = acl_flag
                                # Now ensure that only the expected flag is set
                                # nfs41_flags = result.json()['nfs41_flags']
                                nfs41_flags = res['nfs41_flags']
                                for flag in ['autoinherit', 'protected', 'defaulted']:
                                    if flag == flag_is_set:
                                        assert nfs41_flags[flag], nfs41_flags
                                    else:
                                        assert not nfs41_flags[flag], nfs41_flags
