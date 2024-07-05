import contextlib
# import pytest

from auto_config import password, pool_name, user
from middlewared.test.integration.assets.pool import dataset as nfs_dataset
from middlewared.test.integration.utils import call
from middlewared.test.integration.utils.client import truenas_server
from protocols import SSH_NFS, nfs_share


# @pytest.fixture(scope="module")
@contextlib.contextmanager
def start_nfs():
    """ The exit state is managed by init_nfs """
    try:
        yield call('service.start', 'nfs', {'silent': False})
    finally:
        call('service.stop', 'nfs', {'silent': False})


# def test_nfs_xattr_support(start_nfs):
def test_nfs_xattr_support(start_nfs):
    """
    Perform basic validation of NFSv4.2 xattr support.
    Mount path via NFS 4.2, create a file and dir,
    and write + read xattr on each.
    """
    assert start_nfs is True

    xattr_nfs_path = f'/mnt/{pool_name}/test_nfs4_xattr'
    # with nfs_dataset("test_nfs4_xattr", mode="777", delete_delay=10):
    with nfs_dataset("test_nfs4_xattr", mode="777"):
        with nfs_share(xattr_nfs_path):
            with start_nfs():
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
