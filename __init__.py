from __future__ import print_function

import errno
import hashlib
import os
from functools import partial
try:
    from urllib import urlretrieve
except ImportError:
    from urllib.request import urlretrieve

from binaryninja import *
from builtins import bytes

import nampa


DEV_MODE = False
FUNCTION_TAIL_LENGTH = 0x100
LIBRARY = [
    ('Ubuntu - libc6-dev_2.15-0ubuntu10.15 [armhf]', 'https://github.com/push0ebp/sig-database/raw/master/debian/arm/libc6-dev_2.15-0ubuntu10.15_armhf.sig'),
    ('Ubuntu - libc6-dev_2.15-0ubuntu10.15 [armel]', 'https://github.com/push0ebp/sig-database/raw/master/debian/arm/libc6-dev_2.15-0ubuntu10.15_armel.sig'),
    ('Ubuntu 14.04 - libc [x64]', 'https://github.com/push0ebp/sig-database/raw/master/ubuntu/libc_14_04_x64.sig'),
    ('Ubuntu 14.04 - libc [x86]', 'https://github.com/push0ebp/sig-database/raw/master/ubuntu/libc_14_04_x86.sig'),
    ('Ubuntu 15.10 - libc [x64]', 'https://github.com/push0ebp/sig-database/raw/master/ubuntu/libc_15_10_x64.sig'),
    ('Ubuntu 15.10 - libc [x86]', 'https://github.com/push0ebp/sig-database/raw/master/ubuntu/libc_15_10_x86.sig'),
    ('Ubuntu 16.04 - libc [x64]', 'https://github.com/push0ebp/sig-database/raw/master/ubuntu/libc_16_04_x64.sig'),
    ('Ubuntu 16.04 - libc [x86]', 'https://github.com/push0ebp/sig-database/raw/master/ubuntu/libc_16_04_x86.sig'),
    ('Windows - libvcruntime 15 [arm]', 'https://github.com/Maktm/FLIRTDB/raw/master/vcruntime/windows/libvcruntime_15_msvc_arm.sig'),
    ('Windows - libvcruntime 15 [x64]', 'https://github.com/Maktm/FLIRTDB/raw/master/vcruntime/windows/libvcruntime_15_msvc_x64.sig'),
    ('Windows - libvcruntime 15 [x86]', 'https://github.com/Maktm/FLIRTDB/raw/master/vcruntime/windows/libvcruntime_15_msvc_x86.sig'),
    ('Windows - libvcruntimed 15 [arm]', 'https://github.com/Maktm/FLIRTDB/raw/master/vcruntime/windows/libvcruntimed_15_msvc_arm.sig'),
    ('Windows - libvcruntimed 15 [x64]', 'https://github.com/Maktm/FLIRTDB/raw/master/vcruntime/windows/libvcruntimed_15_msvc_x64.sig'),
    ('Windows - libvcruntimed 15 [x86]', 'https://github.com/Maktm/FLIRTDB/raw/master/vcruntime/windows/libvcruntimed_15_msvc_x86.sig'),
]


dir_path = os.path.dirname(__file__)
cache_dir = os.path.join(dir_path, 'cache')
try:
    os.makedirs(cache_dir, mode=0o755)
except OSError as e:
    if e.errno != errno.EEXIST:
        raise OSError


def ilog(msg):
    log_info('nampa> {}'.format(msg))


def make_name_from_url(url):
    m = hashlib.md5()
    m.update(url)
    return m.hexdigest() + '.sig'


def get_library_file_path(idx):
    name, url = LIBRARY[idx]
    dst_path = os.path.join(cache_dir, make_name_from_url(url))

    # Download if not cached
    if not os.path.exists(dst_path):
        ilog('downloading "{}" to "{}"...'.format(name, dst_path))
        urlretrieve(url, dst_path)

    return dst_path


def analysis_callback(bv, addr, funk, **kwargs):
    # type: (None, int, nampa.FlirtFunction) -> ()
    action = kwargs['action']
    keep_manually_renamed = kwargs['keep_manually_renamed']
    prefix = kwargs['prefix']

    # TODO: check offsets > 0
    # TODO: split/merge/reanalyze the matching functions
    bv_funk = bv.get_function_at(addr + funk.offset)
    if bv_funk is None:
        # ilog('!!! Please send the files to the nampa\'s author !!!')
        ilog('!!! no function "{}" @ {:08X}'.format(funk.name, addr + funk.offset))
        return
    # assert bv_funk is not None

    # Skip functions with names different than 'sub_.*'
    if keep_manually_renamed and not bv_funk.name.startswith('sub_'):
        return

    bv_name = prefix + funk.name
    if action == 'comment':
        bv_funk.set_comment(addr, bv_name)
    elif action == 'rename':
        bv_funk.name = bv_name
    elif action == 'log':
        ilog('{:08X}: {}'.format(addr, funk))
    else:
        assert False

    print('{:08X}: {} => {}'.format(addr, funk, action))


def get_function_end(funk, end=None):
    if end is None:
        end = funk.start

    for b in funk.basic_blocks:
        end = max(end, b.end)

    return end


def match_functions(bv, flirt_path, action, keep_manually_renamed, prefix):
    callback = partial(analysis_callback, bv, action=action, keep_manually_renamed=keep_manually_renamed, prefix=prefix)
    ilog('opening "{}"'.format(flirt_path))
    with open(flirt_path, 'rb') as f:
        flirt = nampa.parse_flirt_file(f)
        ilog('signature name: "{}"'.format(flirt.header.library_name))

        ilog('processing...')
        for funk in bv.functions:
            f_start = funk.start
            f_end = get_function_end(funk)
            buff = bytes(bv.read(f_start, f_end - f_start + FUNCTION_TAIL_LENGTH))
            nampa.match_function(flirt, buff, f_start, callback)

        # ff = [f.start for f in bv.functions] + [bv.end]
        # for f_start, f_end in zip(ff[:-1], ff[1:]):
        #     buff = bytes(bv.read(f_start, f_end - f_start))
        #     nampa.match_function(flirt, buff, f_start, callback)

    ilog('done :B')


def match_functions_gui(bv):
    actions = ('rename', 'comment', 'log')

    gui_label_options = LabelField('Options')
    gui_analysis_mode = ChoiceField('Analysis:', ('Only Functions',))
    gui_prefix = TextLineField('Function prefix:')
    gui_selector = ChoiceField('Function selector:', ('sub_.*', '.*'))
    gui_action = ChoiceField('Action:', [a.title() for a in actions])

    gui_separator = SeparatorField()

    gui_label_signature = LabelField('Signature')
    gui_from_library = ChoiceField('From Library:', [name for name, _ in LIBRARY])
    gui_from_file = OpenFileNameField('From File:', '*.sig')

    ret = get_form_input(
        (gui_label_options, gui_analysis_mode, gui_prefix, gui_selector, gui_action, gui_separator, gui_label_signature
         , gui_from_library , gui_from_file),
        'Nampa'
    )

    # Exit if the user didn't confirm
    if not ret:
        return

    # Option parsing/sanitization
    action = actions[gui_action.result]
    prefix = gui_prefix.result.strip()
    keep_manually_renamed = gui_selector.result == 0
    from_file = gui_from_file.result.strip()
    if from_file != '':
        flirt_path = from_file
    else:
        flirt_path = get_library_file_path(gui_from_library.result)

    match_functions(bv, flirt_path, action, keep_manually_renamed, prefix)

PluginCommand.register(
    name='Nampa - GUI (flirt)',
    description='Apply FLIRT signatures to the current file',
    action=match_functions_gui
)

if DEV_MODE:
    flirt_path = os.path.expanduser('~/test.sig')
    action = 'rename'
    keep_manually_renamed = False
    prefix = ''
    PluginCommand.register(
        name='Nampa - DEV (flirt)',
        description='Ninjas don\'t just FLIRT',
        action=lambda bv: match_functions(bv, flirt_path, action, keep_manually_renamed, prefix)
    )
