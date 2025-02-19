<%
    import itertools
    import os
    import time

    from collections import defaultdict
    from pathlib import Path

    from middlewared.service import CallError

    global_config = middleware.call_sync('iscsi.global.config')

    def existing_copy_manager_luns():
        luns = {}
        p = Path('/sys/kernel/scst_tgt/targets/copy_manager/copy_manager_tgt/luns')
        if p.is_dir():
            for lun in p.iterdir():
                if lun.is_dir() and lun.name != 'mgmt':
                    link = Path(lun, 'device')
                    if link.is_symlink():
                        target = link.readlink()
                        luns[int(lun.name)] = target.name
        return luns

    def calc_copy_manager_luns(devices, force_insert=False):
        cml = existing_copy_manager_luns()
        # Remove any devices not present
        for key in list(cml):
            if cml[key] not in devices:
                del cml[key]
        if force_insert:
            # Add any devices not yet in cml
            to_add = set(devices) - set(cml.values())
            start_count = 0
            for device in to_add:
                keys = list(cml)
                while start_count in keys:
                    start_count += 1
                cml[start_count] = device
        return cml

    targets = middleware.call_sync('iscsi.target.query')
    extents = {d['id']: d for d in middleware.call_sync('iscsi.extent.query', [['enabled', '=', True]], {'extra': {'use_cached_locked_datasets': False}})}
    portals = {d['id']: d for d in middleware.call_sync('iscsi.portal.query')}
    initiators = {d['id']: d for d in middleware.call_sync('iscsi.initiator.query')}
    authenticators = defaultdict(list)
    for auth in middleware.call_sync('iscsi.auth.query'):
        authenticators[auth['tag']].append(auth)

    # There are several changes that must occur if ALUA is enabled,
    # and these are different depending on whether this is the
    # MASTER node, or BACKUP node.
    #
    # MASTER:
    # - publish additional internal targets, only accessible on the private IP
    #
    # BACKUP:
    # - login to these internal targets
    # - access them in dev_disk HANDLER
    # - Add them to copy_manager
    # - reexport them on the same IQNs as the master, but with different
    #   rel_tgt_id.
    #
    # BOTH:
    # - Write a DEVICE_GROUP section with two TARGET_GROUPs
    # - TARGET GROUPs and rel_tgt_id are tied to the controller,
    #   *not* to whether it is currently the MASTER or BACKUP
    # - clustered_extents is used to prevent cluster_mode from being
    #   enabled on entents at startup.  We will have to explicitly
    #   write 1 to cluster_mode elsewhere.
    is_ha = middleware.call_sync('failover.licensed')
    alua_enabled = middleware.call_sync("iscsi.global.alua_enabled")
    failover_status = middleware.call_sync("failover.status")
    node = middleware.call_sync("failover.node")
    failover_virtual_aliases = []
    if alua_enabled:
        listen_ip_choices = middleware.call_sync('iscsi.portal.listen_ip_choices')
        for interface in middleware.call_sync('interface.query', [('failover_virtual_aliases', '!=', [])]):
            for addr in interface['failover_virtual_aliases']:
                if 'address' in addr:
                    failover_virtual_aliases.append(addr['address'])

    standby_node_requires_reload = False
    fix_cluster_mode = []
    cluster_mode_targets = []
    cluster_mode_luns = {}
    clustered_extents = set()
    active_extents = []
    if failover_status == "MASTER":
        local_ip = middleware.call_sync("failover.local_ip")
        dlm_ready = middleware.call_sync("dlm.node_ready")
        if alua_enabled:
            active_extents = middleware.call_sync("iscsi.extent.active_extents")
            clustered_extents = set(middleware.call_sync("iscsi.target.clustered_extents"))
            cluster_mode_targets = middleware.call_sync("iscsi.target.cluster_mode_targets")
    elif failover_status == "BACKUP":
        if alua_enabled:
            if middleware.call_sync("iscsi.alua.standby_write_empty_config"):
                logged_in_targets = {}
            else:
                retries = 5
                while retries:
                    try:
                        logged_in_targets = middleware.call_sync("iscsi.target.login_ha_targets")
                        break
                    except Exception:
                        # We might just experience a race, so attempt a quick retry
                        time.sleep(1)
                    retries -= 1
                if not retries:
                    middleware.logger.warning('Failed to login HA targets', exc_info=True)
                    logged_in_targets = {}
                    standby_node_requires_reload = True
                try:
                    _cmt_cml = middleware.call_sync(
                        'failover.call_remote', 'iscsi.target.cluster_mode_targets_luns', [], {'raise_connect_error': False}
                    )
                except Exception:
                    middleware.logger.warning('Unhandled error contacting remote node', exc_info=True)
                    standby_node_requires_reload = True
                else:
                    if _cmt_cml is not None:
                        cluster_mode_targets, cluster_mode_luns = _cmt_cml
                clustered_extents = set(middleware.call_sync("iscsi.target.clustered_extents"))
        else:
            middleware.call_sync("iscsi.target.logout_ha_targets")
            targets = []
            extents = {}
            portals = {}
            initiators = {}

    nodes = {"A" : {"other" : "B", "group_id" : 101},
             "B" : {"other" : "A", "group_id" : 102}}

    # Let's map extents to respective ios
    all_extent_names = []
    missing_extents = []
    extents_io = {'vdisk_fileio': [], 'vdisk_blockio': []}
    for extent in extents.values():
        extent['name'] = extent['name'].replace('.', '_').replace('/', '-')  # CORE ctl device names are incompatible with SCALE SCST
        if extent['locked']:
            middleware.logger.debug(
                'Skipping generation of extent %r as the underlying resource is locked', extent['name']
            )
            middleware.call_sync('iscsi.extent.generate_locked_alert', extent['id'])
            continue

        if extent['type'] == 'DISK':
            extent['extent_path'] = os.path.join('/dev', extent['disk'])
            extents_io_key = 'vdisk_blockio'
        else:
            extent['extent_path'] = extent['path']
            extents_io_key = 'vdisk_fileio'

        if not os.path.exists(extent['extent_path']):
            # We're going to permit the extent if ALUA is enabled and we're the BACKUP node
            if not alua_enabled or failover_status != "BACKUP":
                middleware.logger.debug(
                    'Skipping generation of extent %r as the underlying resource does not exist', extent['name']
                )
                missing_extents.append(extent['id'])
                continue

        extents_io[extents_io_key].append(extent)
        all_extent_names.append(extent['name'])

        extent['t10_dev_id'] = extent['serial']
        if not extent['xen']:
            extent['t10_dev_id'] = extent['serial'].ljust(31 - len(extent['serial']), ' ')

    associated_targets = defaultdict(list)
    # On ALUA BACKUP node (only) we will include associated_targets even if underlying device is missing
    if failover_status == 'BACKUP':
        if alua_enabled:
            for a_tgt in filter(
                lambda a: a['extent'] in extents and not extents[a['extent']]['locked'],
                middleware.call_sync('iscsi.targetextent.query')
            ):
                associated_targets[a_tgt['target']].append(a_tgt)
        # If ALUA not enabled then keep associated_targets as empty
    else:
        for a_tgt in filter(
            lambda a: a['extent'] in extents and not extents[a['extent']]['locked'] and a['extent'] not in missing_extents,
            middleware.call_sync('iscsi.targetextent.query')
        ):
            associated_targets[a_tgt['target']].append(a_tgt)

    # FIXME: SSD is not being reflected in the initiator, please look into it

    target_hosts = middleware.call_sync('iscsi.host.get_target_hosts')
    hosts_iqns = middleware.call_sync('iscsi.host.get_hosts_iqns')

    if alua_enabled and failover_status == "BACKUP":
        cml = calc_copy_manager_luns(list(itertools.chain.from_iterable([x for x in logged_in_targets.values() if x is not None])), True)
    else:
        cml = calc_copy_manager_luns(all_extent_names)

    def set_active_lun_to_cluster_mode(extentname):
        if extentname in active_extents and extentname in clustered_extents:
            return True
        return False

    def set_standby_lun_to_cluster_mode(device, targetname):
        if device in clustered_extents:
            if targetname in cluster_mode_luns and int(device.split(':')[-1]) in cluster_mode_luns[targetname]:
                return True
        return False

    def set_standy_target_to_enabled(targetname):
        devices = logged_in_targets.get(targetname, [])
        if devices:
            if set(devices).issubset(clustered_extents):
                return True
        return False
%>\
##
## If we are on a HA system then write out a cluster name, we'll hard-code
## it to "HA"
##
% if is_ha:
cluster_name HA
% endif
##
## Write "HANDLER dev_disk" section on any HA-capable system (to force the
## kernel module to get loaded on SCST startup), but only populate it on the
## ALUA BACKUP node.
##
% if is_ha:
HANDLER dev_disk {
%     if alua_enabled and failover_status == "BACKUP":
%         for name, devices in logged_in_targets.items():
%             if devices:
%                 for device in devices:

        DEVICE ${device} {
## We will only enter cluster_mode here if two conditions are satisfied:
## 1. We are already in cluster_mode, AND
## 2. The corresponding LUN on the MASTER is in cluster_mode
## Note we use a similar check to determine whether the target will be enabled.
%                 if set_standby_lun_to_cluster_mode(device, name):
            cluster_mode 1
%                 else:
<%
    fix_cluster_mode.append(device)
%>\
            cluster_mode 0
%                 endif
        }
%                 endfor
%             endif
%         endfor
%     endif
}
% endif
##
## Write "TARGET_DRIVER copy_manager" section as otherwise CM
## can get confused wrt LUNs present when a new target is
## added (although no problem if SCST is restarted after all
## configuration changes have been made).
##
% if len(cml):
TARGET_DRIVER copy_manager {
        TARGET copy_manager_tgt {
%       for key in sorted(cml):
                LUN ${key} ${cml[key]}
%       endfor
        }
}
% endif
##

% for handler in extents_io:
HANDLER ${handler} {
%   for extent in extents_io[handler]:
    DEVICE ${extent['name']} {
        filename ${extent['extent_path']}
        blocksize ${extent['blocksize']}
%       if extent['pblocksize']:
        lb_per_pb_exp 0
%       endif
        read_only ${'1' if extent['ro'] else '0'}
        usn ${extent['serial']}
        naa_id ${extent['naa']}
        prod_id "iSCSI Disk"
%       if extent['rpm'] != 'SSD':
        rotational 1
%       else:
        rotational 0
%       endif
        t10_vend_id ${extent['vendor']}
        t10_dev_id ${extent['t10_dev_id']}
%       if failover_status == "MASTER" and alua_enabled and dlm_ready:
%       if set_active_lun_to_cluster_mode(extent['name']):
        cluster_mode 1
%       else:
        cluster_mode 0
%       endif
%       endif
%       if failover_status == "BACKUP" and alua_enabled:
        active 0
%       endif
%       if handler == 'vdisk_blockio':
        threads_num 32
%       endif
    }

%   endfor
}
% endfor

TARGET_DRIVER iscsi {
    enabled 1
## Currently SCST only supports one iSNS server
% if global_config['isns_servers']:
    iSNSServer ${global_config['isns_servers'][0]}
% endif
## We are supposed to set iSNS server here but unfortunately that is not working
## An issue has been opened with scst regarding that and duplicating of target reporting on each new portal
## https://sourceforge.net/p/scst/tickets/38/ ( let's please fix this once we hear back from them )

<%def name="retrieve_luns(target_id, spacing='')">
    % for associated_target in associated_targets[target_id]:
        ${spacing}LUN ${associated_target['lunid']} ${extents[associated_target['extent']]['name']}
    % endfor
</%def>\
% for idx, target in enumerate(targets, start=1):
    TARGET ${global_config['basename']}:${target['name']} {
<%
    # SCST does not allow us to set authentication at a group level, so it is going to be set at
    # target level which we are moving forward with right now. Also for mutual-chap, we can only set
    # one user which the initiator can authenticate on it's end. So if any group in the target
    # desires mutual chap, we take the first one and use it's peer credentials
    alias = target.get('alias')
    mutual_chap = None
    chap_users = set()
    initiator_portal_access = set()
    has_per_host_access = False
    for host in target_hosts[target['id']]:
        for iqn in hosts_iqns[host['id']]:
            initiator_portal_access.add(f'{iqn}\#{host["ip"]}')
            has_per_host_access = True
    for group in target['groups']:
        if group['authmethod'] != 'NONE' and authenticators[group['auth']]:
            auth_list = authenticators[group['auth']]
            if group['authmethod'] == 'CHAP_MUTUAL' and not mutual_chap:
                mutual_chap = f'{auth_list[0]["peeruser"]} {auth_list[0]["peersecret"]}'

            chap_users.update(f'{auth["user"]} {auth["secret"]}' for auth in auth_list)

        for addr in portals[group['portal']]['listen']:
            if addr['ip'] in ('0.0.0.0', '::'):
                # SCST uses wildcard patterns
                # https://github.com/truenas/scst/blob/e945943861687d16ae0415207306f75a55bcfd2b/iscsi-scst/usr/target.c#L139-L138
                address = '*'
            else:
                # In an ALUA config, we may have selected the int_vip.  If so just use
                # the IP pertainng to this node.
                address = addr['ip']
                if alua_enabled and address in failover_virtual_aliases and address in listen_ip_choices and '/' in listen_ip_choices[address]:
                    pair = listen_ip_choices[address].split('/')
                    address = pair[0] if node == 'A' else pair[1]

            group_initiators = initiators[group['initiator']]['initiators'] if group['initiator'] else []
            if not has_per_host_access:
                group_initiators = group_initiators or ['*']
            for initiator in group_initiators:
                initiator_portal_access.add(f'{initiator}\#{address}')
%>\
%   if associated_targets.get(target['id']):
##
## For ALUA rel_tgt_id is tied to controller, if not ALUA write it anyway
## to avoid it changing when ALUA is toggled.
##
%       if alua_enabled:
%           if node == "A":
        rel_tgt_id ${target['rel_tgt_id']}
%           endif
%           if node == "B":
        rel_tgt_id ${target['rel_tgt_id'] + 32000}
%           endif
%       else:
        rel_tgt_id ${target['rel_tgt_id']}
%       endif
##
## For ALUA target is enabled if MASTER, disabled for BACKUP
##
%       if alua_enabled:
%           if failover_status == "MASTER":
        enabled 1
%           elif failover_status == "BACKUP" and set_standy_target_to_enabled(target['name']):
        enabled 1
%           else:
        enabled 0
%           endif
%       else:
        enabled 1
%       endif
##
## per_portal_acl always 1
##
        per_portal_acl 1
%   else:
## If no associated targets then disable
        enabled 0
%   endif
##
## alias
##
%   if alias:
        alias "${alias}"
%   endif
%   for chap_auth in chap_users:
        IncomingUser "${chap_auth}"
%   endfor
%   if mutual_chap:
        OutgoingUser "${mutual_chap}"
%   endif

        GROUP security_group {
%   for access_control in initiator_portal_access:
            INITIATOR ${access_control}
%   endfor
##
%   if alua_enabled and failover_status == "BACKUP":
<%
    devices = logged_in_targets.get(target['name'], None)
%>\
%       if devices:
%           for device in devices:
            LUN ${device.split(':')[-1]} ${device}
%           endfor
%       endif
%   else:
${retrieve_luns(target['id'], ' ' * 4)}\
%   endif
        }
    }
% endfor
##
## For the master in HA ALUA write out additional targets that will only be accessible
## from the peer node.  These will have the flipped rel_tgt_id
##
% if alua_enabled and failover_status == "MASTER":
%     for idx, target in enumerate(targets, start=1):
    TARGET ${global_config['basename']}:HA:${target['name']} {
        allowed_portal ${local_ip}
%       if node == "A":
        rel_tgt_id ${target['rel_tgt_id'] + 32000}
%       endif
%       if node == "B":
        rel_tgt_id ${target['rel_tgt_id']}
%       endif
## Mimic the enabled behavior of the base target.  Only enable if have associated extents
%   if associated_targets.get(target['id']):
        enabled 1
%   else:
        enabled 0
%   endif
        forward_dst 1
        aen_disabled 1
        forwarding 1
${retrieve_luns(target['id'],'')}\
    }
%     endfor
% endif
}
##
## If ALUA is enabled then we will want a section to setup the target portal groups
##
## Since we do NOT split ZFS pools (and their subsequent targets) across controllers
## we can just have one TPG per node.
##   - Controller A will have TPG ID of 101
##   - Controller B will have TPG ID of 102
##
## What is in each TPG depends upon which node is the MASTER and which is the BACKUP
##
## To make the code easier to read we have a different section for MASTER and BACKUP
##
% if alua_enabled:
##
## MASTER
##   - this node is active and contains the targets
##   - other node contains the "HA" targets (rel_tgt_ids 32001,..)
##
%     if failover_status == "MASTER":
DEVICE_GROUP targets {
% for handler in extents_io:
%   for extent in extents_io[handler]:
        DEVICE ${extent['name']}
%   endfor
% endfor

        TARGET_GROUP controller_${node} {
                group_id ${nodes[node]["group_id"]}
                state active

% for target in targets:
                TARGET ${global_config['basename']}:${target['name']}
% endfor
        }

        TARGET_GROUP controller_${nodes[node]["other"]} {
                group_id ${nodes[nodes[node]["other"]]["group_id"]}
                state nonoptimized

% for target in targets:
                TARGET ${global_config['basename']}:HA:${target['name']}
% endfor
        }
}
%     endif
##
## BACKUP
##   - this node is nonoptimized
##   - other node contains the "ALT" placeholder targets
##
%     if failover_status == "BACKUP":
DEVICE_GROUP targets {
%         for name, devices in logged_in_targets.items():
%             if devices:
%                 for device in devices:
        DEVICE ${device}
%                 endfor
%             endif
%         endfor

        TARGET_GROUP controller_${nodes[node]["other"]} {
                group_id ${nodes[nodes[node]["other"]]["group_id"]}
                state active

% for idx, target in enumerate(targets, start=1):
                TARGET ${global_config['basename']}:alt:${target['name']} {
%     if node == "A":
                   rel_tgt_id ${target['rel_tgt_id'] + 32000}
%     endif
%     if node == "B":
                   rel_tgt_id ${target['rel_tgt_id']}
%     endif
                }
% endfor

        }

        TARGET_GROUP controller_${node} {
                group_id ${nodes[node]["group_id"]}
                state nonoptimized

% for target in targets:
                TARGET ${global_config['basename']}:${target['name']}
% endfor
        }

}
%     endif
% endif
<%
    if standby_node_requires_reload:
        middleware.call_sync('iscsi.alua.standby_delayed_reload')
    elif fix_cluster_mode:
        middleware.call_sync('iscsi.alua.standby_fix_cluster_mode', fix_cluster_mode)
%>
