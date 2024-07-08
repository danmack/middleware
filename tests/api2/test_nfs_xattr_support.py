from auto_config import password, pool_name, user
from middlewared.test.integration.assets.pool import dataset as nfs_dataset
from middlewared.test.integration.assets.nfs import nfs_start
from middlewared.test.integration.utils.client import truenas_server
from protocols import SSH_NFS, nfs_share
from time import sleep


def test_nfs_xattr_support():
    """
    Perform basic validation of NFSv4.2 xattr support.
    Mount path via NFS 4.2, create a file and dir,
    and write + read xattr on each.
    """

    xattr_nfs_path = f'/mnt/{pool_name}/test_nfs4_xattr'
    with nfs_dataset("test_nfs4_xattr", mode="777"):
        with nfs_share(xattr_nfs_path):
            with nfs_start():
                with SSH_NFS(truenas_server.ip, xattr_nfs_path, vers=4.2,
                             user=user, password=password, ip=truenas_server.ip) as n:
                    n.create("testfile")
                    n.setxattr("testfile", "user.testxattr", "the_contents")
                    xattr_val = n.getxattr("testfile", "user.testxattr")
                    assert xattr_val == "the_contents"

                    n.create("testdir", True)
                    n.setxattr("testdir", "user.testxattr2", "the_contents2")
                    xattr_val = n.getxattr("testdir", "user.testxattr2")
                    assert xattr_val == "the_contents2"
            # Let NFS untangle itself from the dataset
            sleep(1)
