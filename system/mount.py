#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2012, Red Hat, inc
# Written by Seth Vidal
# based on the mount modules from salt and puppet
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.


from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import get_platform
from ansible.module_utils.ismount import ismount
from ansible.module_utils.pycompat24 import get_exception
from ansible.module_utils.six import iteritems
import os
import re


DOCUMENTATION = '''
---
module: mount
short_description: Control active and configured mount points
description:
  - This module controls active and configured mount points in C(/etc/fstab).
author:
  - Ansible Core Team
  - Seth Vidal
version_added: "0.6"
options:
  name:
    description:
      - Path to the mount point (e.g. C(/mnt/files))
    required: true
  src:
    description:
      - Device to be mounted on I(name). Required when I(state) set to
        C(present) or C(mounted).
    required: false
    default: null
  fstype:
    description:
      - Filesystem type. Required when I(state) is C(present) or C(mounted).
    required: false
    default: null
  opts:
    description:
      - Mount options (see fstab(5), or vfstab(4) on Solaris).
    required: false
    default: null
  dump:
    description:
      - Dump (see fstab(5)). Note that if set to C(null) and I(state) set to
        C(present), it will cease to work and duplicate entries will be made
        with subsequent runs.
      - Has no effect on Solaris systems.
    required: false
    default: 0
  passno:
    description:
      - Passno (see fstab(5)). Note that if set to C(null) and I(state) set to
        C(present), it will cease to work and duplicate entries will be made
        with subsequent runs.
      - Deprecated on Solaris systems.
    required: false
    default: 0
  state:
    description:
      - If C(mounted) or C(unmounted), the device will be actively mounted or
        unmounted as needed and appropriately configured in I(fstab).
      - C(absent) and C(present) only deal with I(fstab) but will not affect
        current mounting.
      - If specifying C(mounted) and the mount point is not present, the mount
        point will be created.
      - Similarly, specifying C(absent) will remove the mount point directory.
    required: true
    choices: ["present", "absent", "mounted", "unmounted"]
  fstab:
    description:
      - File to use instead of C(/etc/fstab). You shouldn't use that option
        unless you really know what you are doing. This might be useful if
        you need to configure mountpoints in a chroot environment.
    required: false
    default: /etc/fstab (/etc/vfstab on Solaris)
  boot:
    version_added: 2.2
    description:
      - Determines if the filesystem should be mounted on boot.
      - Only applies to Solaris systems.
    required: false
    default: yes
    choices: ["yes", "no"]
'''

EXAMPLES = '''
- name: Mount DVD read-only
  mount:
    name: /mnt/dvd
    src: /dev/sr0
    fstype: iso9660
    opts: ro
    state: present

- name: Mount up device by label
  mount:
    name: /srv/disk
    src: LABEL=SOME_LABEL
    fstype: ext4
    state: present

- name: Mount up device by UUID
  mount:
    name: /home
    src: UUID=b3e48f45-f933-4c8e-a700-22a159ec9077
    fstype: xfs
    opts: noatime
    state: present
'''


def write_fstab(lines, dest):
    fs_w = open(dest, 'w')

    for l in lines:
        fs_w.write(l)

    fs_w.flush()
    fs_w.close()


def _escape_fstab(v):
    """Escape invalid characters in fstab fields.

    space (040)
    ampersand (046)
    backslash (134)
    """

    if isinstance(v, int):
        return v
    else:
        return(
            v.
            replace('\\', '\\134').
            replace(' ', '\\040').
            replace('&', '\\046'))


def set_mount(module, args):
    """Set/change a mount point location in fstab."""

    to_write = []
    exists = False
    changed = False
    escaped_args = dict([(k, _escape_fstab(v)) for k, v in iteritems(args)])
    new_line = '%(src)s %(name)s %(fstype)s %(opts)s %(dump)s %(passno)s\n'

    if get_platform() == 'SunOS':
        new_line = (
            '%(src)s - %(name)s %(fstype)s %(passno)s %(boot)s %(opts)s\n')

    for line in open(args['fstab'], 'r').readlines():
        if not line.strip():
            to_write.append(line)

            continue

        if line.strip().startswith('#'):
            to_write.append(line)

            continue

        # Check if we got a valid line for splitting
        if (
                get_platform() == 'SunOS' and len(line.split()) != 7 or
                get_platform() != 'SunOS' and len(line.split()) != 6):
            to_write.append(line)

            continue

        ld = {}

        if get_platform() == 'SunOS':
            (
                ld['src'],
                dash,
                ld['name'],
                ld['fstype'],
                ld['passno'],
                ld['boot'],
                ld['opts']
            ) = line.split()
        else:
            (
                ld['src'],
                ld['name'],
                ld['fstype'],
                ld['opts'],
                ld['dump'],
                ld['passno']
            ) = line.split()

        # Check if we found the correct line
        if ld['name'] != escaped_args['name']:
            to_write.append(line)

            continue

        # If we got here we found a match - let's check if there is any
        # difference
        exists = True
        args_to_check = ('src', 'fstype', 'opts', 'dump', 'passno')

        if get_platform() == 'SunOS':
            args_to_check = ('src', 'fstype', 'passno', 'boot', 'opts')

        for t in args_to_check:
            if ld[t] != escaped_args[t]:
                ld[t] = escaped_args[t]
                changed = True

        if changed:
            to_write.append(new_line % ld)
        else:
            to_write.append(line)

    if not exists:
        to_write.append(new_line % escaped_args)
        changed = True

    if changed and not module.check_mode:
        write_fstab(to_write, args['fstab'])

    return (args['name'], changed)


def unset_mount(module, args):
    """Remove a mount point from fstab."""

    to_write = []
    changed = False
    escaped_name = _escape_fstab(args['name'])

    for line in open(args['fstab'], 'r').readlines():
        if not line.strip():
            to_write.append(line)

            continue

        if line.strip().startswith('#'):
            to_write.append(line)

            continue

        # Check if we got a valid line for splitting
        if (
                get_platform() == 'SunOS' and len(line.split()) != 7 or
                get_platform() != 'SunOS' and len(line.split()) != 6):
            to_write.append(line)

            continue

        ld = {}

        if get_platform() == 'SunOS':
            (
                ld['src'],
                dash,
                ld['name'],
                ld['fstype'],
                ld['passno'],
                ld['boot'],
                ld['opts']
            ) = line.split()
        else:
            (
                ld['src'],
                ld['name'],
                ld['fstype'],
                ld['opts'],
                ld['dump'],
                ld['passno']
            ) = line.split()

        if ld['name'] != escaped_name:
            to_write.append(line)

            continue

        # If we got here we found a match - continue and mark changed
        changed = True

    if changed and not module.check_mode:
        write_fstab(to_write, args['fstab'])

    return (args['name'], changed)


def mount(module, args):
    """Mount up a path or remount if needed."""

    mount_bin = module.get_bin_path('mount', required=True)
    name = args['name']
    cmd = [mount_bin]

    if ismount(name):
        cmd += ['-o', 'remount']

    if args['fstab'] != '/etc/fstab':
        if get_platform() == 'FreeBSD':
            cmd += ['-F', args['fstab']]
        elif get_platform() == 'Linux':
            cmd += ['-T', args['fstab']]

    cmd += [name]

    rc, out, err = module.run_command(cmd)

    if rc == 0:
        return 0, ''
    else:
        return rc, out+err


def umount(module, dest):
    """Unmount a path."""

    umount_bin = module.get_bin_path('umount', required=True)
    cmd = [umount_bin, dest]

    rc, out, err = module.run_command(cmd)

    if rc == 0:
        return 0, ''
    else:
        return rc, out+err


# Note if we wanted to put this into module_utils we'd have to get permission
# from @jupeter -- https://github.com/ansible/ansible-modules-core/pull/2923
# @jtyr -- https://github.com/ansible/ansible-modules-core/issues/4439
# and @abadger to relicense from GPLv3+
def is_bind_mounted(module, dest, src=None, fstype=None):
    """Return whether the dest is bind mounted

    :arg module: The AnsibleModule (used for helper functions)
    :arg dest: The directory to be mounted under. This is the primary means
        of identifying whether the destination is mounted.
    :kwarg src: The source directory. If specified, this is used to help
        ensure that we are detecting that the correct source is mounted there.
    :kwarg fstype: The filesystem type. If specified this is also used to
        help ensure that we are detecting the right mount.
    :returns: True if the dest is mounted with src otherwise False.
    """

    is_mounted = False
    bin_path = module.get_bin_path('mount', required=True)
    cmd = '%s -l' % bin_path

    if get_platform() == 'Linux':
        bin_path = module.get_bin_path('findmnt', required=True)
        cmd = '%s -nr %s' % (bin_path, dest)

    rc, out, err = module.run_command(cmd)
    mounts = []

    if len(out):
        mounts = to_native(out).strip().split('\n')

    mount_pattern = re.compile('\[(.*)\]')

    for mnt in mounts:
        arguments = mnt.split()

        if get_platform() == 'Linux':
            source = arguments[1]
            result = mount_pattern.search(arguments[1])

            # This is only for LVM and tmpfs mounts
            if result is not None and len(result.groups()) == 1:
                source = result.group(1)

            if src is None:
                # That's for unmounted/absent
                if arguments[0] == dest:
                    is_mounted = True
            else:
                # That's for mounted
                if arguments[0] == dest and source == src:
                    is_mounted = True
                elif arguments[0] == dest and src.endswith(source):
                    # Check if it's tmpfs mount
                    sub_path = src[:len(src)-len(source)]

                    if (
                            is_bind_mounted(module, sub_path, 'tmpfs') and
                            source == src[len(sub_path):]):
                        is_mounted = True
        elif (
                (arguments[0] == src or src is None) and
                arguments[2] == dest and
                (arguments[4] == fstype or fstype is None)):
            is_mounted = True

        if is_mounted:
            break

    return is_mounted


def main():
    module = AnsibleModule(
        argument_spec=dict(
            boot=dict(default='yes', choices=['yes', 'no']),
            dump=dict(),
            fstab=dict(default='/etc/fstab'),
            fstype=dict(),
            name=dict(required=True, type='path'),
            opts=dict(),
            passno=dict(type='str'),
            src=dict(type='path'),
            state=dict(
                required=True,
                choices=['present', 'absent', 'mounted', 'unmounted']),
        ),
        supports_check_mode=True,
        required_if=(
            ['state', 'mounted', ['src', 'fstype']],
            ['state', 'present', ['src', 'fstype']]
        )
    )

    changed = False
    # solaris args:
    #   name, src, fstype, opts, boot, passno, state, fstab=/etc/vfstab
    # linux args:
    #   name, src, fstype, opts, dump, passno, state, fstab=/etc/fstab
    if get_platform() == 'SunOS':
        args = dict(
            name=module.params['name'],
            opts='-',
            passno='-',
            fstab='/etc/vfstab',
            boot='yes'
        )
    else:
        args = dict(
            name=module.params['name'],
            opts='default',
            dump='0',
            passno='0',
            fstab='/etc/fstab'
        )

    # FreeBSD doesn't have any 'default' so set 'rw' instead
    if get_platform() == 'FreeBSD':
        args['opts'] = 'rw'

    for key in ('src', 'fstype', 'passno', 'opts', 'dump', 'fstab'):
        if module.params[key] is not None:
            args[key] = module.params[key]

    if get_platform() == 'SunOS' and args['fstab'] == '/etc/fstab':
        args['fstab'] = '/etc/vfstab'

    # If fstab file does not exist, we first need to create it. This mainly
    # happens when fstab option is passed to the module.
    if not os.path.exists(args['fstab']):
        if not os.path.exists(os.path.dirname(args['fstab'])):
            os.makedirs(os.path.dirname(args['fstab']))

        open(args['fstab'], 'a').close()

    # absent:
    #   Remove from fstab and unmounted.
    # unmounted:
    #   Do not change fstab state, but unmount.
    # present:
    #   Add to fstab, do not change mount state.
    # mounted:
    #   Add to fstab if not there and make sure it is mounted. If it has
    #   changed in fstab then remount it.

    state = module.params['state']
    name = module.params['name']

    if state == 'absent':
        name, changed = unset_mount(module, args)

        if changed and not module.check_mode:
            if ismount(name) or is_bind_mounted(module, name):
                res, msg = umount(module, name)

                if res:
                    module.fail_json(
                        msg="Error unmounting %s: %s" % (name, msg))

            if os.path.exists(name):
                try:
                    os.rmdir(name)
                except (OSError, IOError):
                    e = get_exception()
                    module.fail_json(msg="Error rmdir %s: %s" % (name, str(e)))
    elif state == 'unmounted':
        if ismount(name) or is_bind_mounted(module, name):
            if not module.check_mode:
                res, msg = umount(module, name)

                if res:
                    module.fail_json(
                        msg="Error unmounting %s: %s" % (name, msg))

            changed = True
    elif state == 'mounted':
        if not os.path.exists(name) and not module.check_mode:
            try:
                os.makedirs(name)
            except (OSError, IOError):
                e = get_exception()
                module.fail_json(
                    msg="Error making dir %s: %s" % (name, str(e)))

        name, changed = set_mount(module, args)
        res = 0

        if ismount(name):
            if changed and not module.check_mode:
                res, msg = mount(module, args)
                changed = True
        elif 'bind' in args.get('opts', []):
            changed = True

            if is_bind_mounted(module, name, args['src'], args['fstype']):
                changed = False

            if changed and not module.check_mode:
                res, msg = mount(module, args)
        else:
            changed = True

            if not module.check_mode:
                res, msg = mount(module, args)

        if res:
            module.fail_json(msg="Error mounting %s: %s" % (name, msg))
    elif state == 'present':
        name, changed = set_mount(module, args)
    else:
        module.fail_json(msg='Unexpected position reached')

    module.exit_json(changed=changed, **args)


if __name__ == '__main__':
    main()
