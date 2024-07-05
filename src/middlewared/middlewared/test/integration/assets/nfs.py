# -*- coding=utf-8 -*-
import contextlib
import logging
from copy import copy

from middlewared.test.integration.utils import call

logger = logging.getLogger(__name__)

__all__ = ["nfs_share"]


@contextlib.contextmanager
def nfs_start():
    """ Use this to return NFS server to stopped state after use """
    try:
        yield call('service.start', 'nfs', {'silent': False})
    finally:
        call('service.stop', 'nfs', {'silent': False})


@contextlib.contextmanager
def nfs_config():
    '''  Use this to restore NFS config settings after use  '''
    try:
        nfs_db_conf = call("nfs.config")
        excl = ['id', 'v4_krb_enabled', 'v4_owner_major', 'keytab_has_nfs_spn', 'managed_nfsd']
        [nfs_db_conf.pop(key) for key in excl]
        yield copy(nfs_db_conf)
    finally:
        call("nfs.update", nfs_db_conf)


@contextlib.contextmanager
def nfs_share(dataset):
    ''' Use this to remove the NFS share after use '''
    share = call("sharing.nfs.create", {
        "path": f"/mnt/{dataset}",
    })
    assert call("service.start", "nfs")

    try:
        yield share
    finally:
        call("sharing.nfs.delete", share["id"])
        call("service.stop", "nfs")


@contextlib.contextmanager
def nfs_share_config(nfsid: int):
    ''' Use this to restore the NFS share settings after use '''
    try:
        configs = call("sharing.nfs.query", [["id", "=", nfsid]])
        assert configs != []
        share_config = configs[0]
        yield copy(share_config)
    finally:
        excl = ['id', 'path', 'locked']
        [share_config.pop(key) for key in excl]
        call("sharing.nfs.update", nfsid, share_config)
