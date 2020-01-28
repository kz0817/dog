#!/usr/bin/env python3
import argparse
import re
import os
import sys
import subprocess
from abc import ABC, abstractmethod

class Formatter(object):

    def get_separator(self):
        return ' '


class DisplayElement(object):
    def __init__(self, master, disp_val):
        self.master = master
        self.disp_val = disp_val

    def render(self):
        return self.master.renderValue(self.disp_val)

class Display(object):

    NO_ALIGN = -1
    LEFT = 0
    RIGHT = 1

    def __init__(self, title, align=RIGHT):
        self.title = title
        self.max_length = 0
        self.align = align

    def create(self, val):
        disp_val = str(val)
        if len(disp_val) > self.max_length:
            self.max_length = len(disp_val)
        return DisplayElement(self, disp_val)

    def get_width(self):
        return max(len(self.title), self.max_length)

    def renderHeader(self):
        return self.__align(self.title)

    def renderValue(self, disp_val):
        return self.__align(disp_val)

    def __align(self, msg):
        if self.align == self.NO_ALIGN:
            return msg
        elif self.align == self.LEFT:
            return msg.ljust(self.get_width())
        else:
            return msg.rjust(self.get_width())


class NumberDisplay(Display):
    def __init__(self, title, fmt='%d', **kwargs):
        super(NumberDisplay, self).__init__(title, kwargs)
        self.fmt = fmt

    def create(self, val):
        if isinstance(val, int):
            disp_val = '%08x' % val
        else:
            disp_val = val
        return super(NumberDisplay, self).create(disp_val)


class CommandDisplay(Display):
    def __init__(self, title, show_command_line, max_width):
        super(CommandDisplay, self).__init__(title, Display.NO_ALIGN)
        self.__show_command_line = show_command_line
        self.__max_width = max_width

    def create(self, proc):
        s = self.__create_space_header(proc.depth)

        cmd_line = ''
        if self.__show_command_line:
            cmd_line = ' '.join(proc.read_command_parameters())

        if len(cmd_line) > 0:
            s += cmd_line
        else:
            s += proc.name

        trimmed = self.__trim_if_necessary(s)
        return super(CommandDisplay, self).create(trimmed)

    def __trim_if_necessary(self, s):
        if self.__max_width == 0:
            return s
        else:
            return s[:self.__max_width]


    def __create_space_header(self, depth):
        return ''.join([' ' for i in range(depth*2)])


class UidGidBaseDisplay(Display, ABC):
    name_map = None

    def __init__(self, title, use_name, data_file):
        super(UidGidBaseDisplay, self).__init__(title)
        self.__use_name = use_name
        if self.name_map is None:
            self.__create_name_map(data_file)

    def __create_name_map(self, data_file):
        self.name_map = {}
        with open(data_file) as f:
            for line in f:
                id_num, name = self.get_name_map_pair(line)
                self.name_map[id_num] = name

    @abstractmethod
    def get_name_map_pair(self, line):
        pass

    def create(self, val):
        if self.__use_name:
            disp_val = self.name_map.get(val, val)
        else:
            disp_val = val
        return super(UidGidBaseDisplay, self).create(disp_val)


class UidDisplay(UidGidBaseDisplay):
    def __init__(self, title, use_name):
        super(UidDisplay, self).__init__(title, use_name, '/etc/passwd')

    #override
    def get_name_map_pair(self, line):
        name, passwd, uid, gid, others = line.split(':', maxsplit=4)
        return uid, name


class GidDisplay(UidGidBaseDisplay):
    def __init__(self, title, use_name):
        super(GidDisplay, self).__init__(title, use_name, '/etc/group')

    #override
    def get_name_map_pair(self, line):
        group, x, gid, others = line.split(':', maxsplit=3)
        return gid, group


class MemoryDisplay(Display):
    unit_map = {
        'B': 1,
        'KiB': 1024.0,
        'MiB': 1024.0 * 1024,
        'GiB': 1024.0 * 1024 * 1024,
        'TiB': 1024.0 * 1024 * 1024 * 1024,
    }

    def __init__(self, title, unit='MiB'):
        super(MemoryDisplay, self).__init__(title)
        self.__scale = self.unit_map[unit]

    def create(self, val):
        if self.__scale == 1:
            disp_val = str(val)
        else:
            disp_val = '%.1f' % (val / self.__scale)
        return super(MemoryDisplay, self).create(disp_val)


class Process(object):

    PAGE_SIZE = 0x1000

    def __init__(self, args, generic_pid, pid):
        # The parameter 'generic_pid' is a typical process ID. It can consit
        # of multiple lightweight processes (i.e. threads).
        # 'pid' is a number which is sometimes called tid (thread ID).

        def get_last(map_obj, key):
            arr = map_obj.get(key)
            if arr is None:
                return '-'
            return arr.split()[-1]

        stat_arr = self.__read_stat(pid)

        self.excluded = False
        self.generic_pid = int(generic_pid)
        self.pid = int(stat_arr[0])
        self.status = stat_arr[2]
        self.ppid = int(stat_arr[3])
        self.pgid = int(stat_arr[4])
        self.sid = int(stat_arr[5])
        self.name = stat_arr[1]
        self.num_threads = int(stat_arr[19])
        self.vsz = int(stat_arr[22])
        self.rss = int(stat_arr[23]) * self.PAGE_SIZE

        self.parent = None
        self.children = []

        status_map = self.__read_status(pid)

        self.ruid, self.euid, self.suid, self.fuid = status_map['Uid'].split()
        self.rgid, self.egid, self.sgid, self.fgid = status_map['Gid'].split()
        self.nspid = get_last(status_map, 'NStgid')
        self.nstid = get_last(status_map, 'NSpid')
        self.nspgid = get_last(status_map, 'NSpgid')
        self.nssid = get_last(status_map, 'NSsid')

    def __read_stat(self, pid):
        with open('/proc/%s/stat' % pid) as f:
            line = f.read()
            first, remaining = line.split('(', maxsplit=1)
            second, others = remaining.rsplit(')', maxsplit=1)
            return [first, second] + others.split()

    def __read_status(self, pid):
        kv_map = {}
        with open('/proc/%s/status' % pid) as f:
            for line in f:
                key, remaining = line.split(':', maxsplit=1)
                kv_map[key] = remaining.strip()
        return kv_map

    def read_command_parameters(self):
        with open('/proc/%s/cmdline' % self.pid) as f:
            return f.read().split('\0')

    def __str__(self):
        s = ''
        s += 'pid: %s, ' % str(self.pid).rjust(6)
        s += 'ppid: %s, ' % str(self.ppid).rjust(6)
        vsz_m = self.vsz / 1024.0 / 1024
        rss_m = self.rss / 1024.0 / 1024
        s += 'vsz-m: %s, ' % ('%.1f' % vsz_m).rjust(8)
        s += 'rss-k: %s, ' % ('%.1f' % rss_m).rjust(8)
        s += 'name: %s, ' % self.name
        return s

    def get_ns(self, ns_type):
        try:
            ns = os.readlink('/proc/%s/ns/%s' % (self.pid, ns_type))
            start = len(ns_type) + 2
            return int(ns[start:-1])
        except PermissionError:
            return '-'

    def ancestors(self):
        arr = []
        parent = self.parent
        while parent is not None:
            arr.append(parent)
            parent = parent.parent
        return arr

    def descendants(self):

        def collect_descendants(arr, proc):
            for child in proc.children:
                arr.append(child)
                collect_descendants(arr, child)

        arr = []
        collect_descendants(arr, self)
        return arr


class DisplayManager(object):
    column_def = {
        'pid': (
            lambda args: Display('PID'),
            lambda proc: proc.generic_pid,
        ),
        'tid': (
            lambda args: Display('TID'),
            lambda proc: proc.pid,
        ),
        'ppid': (
            lambda args: Display('PPID'),
            lambda proc: proc.ppid,
        ),
        'pgid': (
            lambda args: Display('PGID'),
            lambda proc: proc.pgid,
        ),
        'sid': (
            lambda args: Display('SID'),
            lambda proc: proc.sid,
        ),
        'name': (
            lambda args: Display('NAME', Display.LEFT),
            lambda proc: proc.name,
        ),
        'cmd': (
            lambda args: CommandDisplay('COMMAND', args.command_line, args.max_cmd_width),
            lambda proc: proc,
        ),
        'stat': (
            lambda args: Display('S'),
            lambda proc: proc.status,
        ),
        'vsz': (
            lambda args: MemoryDisplay('VSZ', args.vsz_unit),
            lambda proc: proc.vsz,
        ),
        'rss': (
            lambda args: MemoryDisplay('RSS', args.rss_unit),
            lambda proc: proc.rss,
        ),
        'nthr': (
            lambda args: Display('Nth'),
            lambda proc: proc.num_threads,
        ),
        'netns': (
            lambda args: NumberDisplay('NETNS', fmt='%08x'),
            lambda proc: proc.get_ns('net'),
        ),
        'pidns': (
            lambda args: NumberDisplay('PIDNS', fmt='%08x'),
            lambda proc: proc.get_ns('pid'),
        ),
        'nspid': (
            lambda args: NumberDisplay('NSPID'),
            lambda proc: proc.nspid,
        ),
        'nstid': (
            lambda args: NumberDisplay('NSTID'),
            lambda proc: proc.nstid,
        ),
        'nspgid': (
            lambda args: NumberDisplay('NSPGID'),
            lambda proc: proc.nspgid,
        ),
        'nssid': (
            lambda args: NumberDisplay('NSSID'),
            lambda proc: proc.nssid,
        ),
    }
    uid_defs = [
        ('ruid', 'RUID'), ('euid', 'EUID'),
        ('suid', 'SUID'), ('fuid', 'FUID'),
    ]
    gid_defs = [
        ('rgid', 'RGID'), ('egid', 'EGID'),
        ('sgid', 'SGID'), ('fgid', 'FGID'),
    ]
    for defs, klass in ((uid_defs, 'UidDisplay'), (gid_defs, 'GidDisplay')):
        for name, label in defs:
            column_def[name] = (
                eval('lambda args: %s("%s", args.show_name_instead_of_id)' \
                     % (klass, label)),
                eval('lambda proc: getattr(proc, "%s")' % name),
            )


    def __init__(self, args):
        self.display_list = []
        for column_name in args.output:
            generator, value_getter = self.column_def[column_name]
            disp = generator(args)
            self.display_list.append((disp, value_getter))

    def render(self, proc):
        for disp, value_getter in self.display_list:
            yield disp.create(value_getter(proc))

class ProcessFinder(object):
    def __init__(self, args, proc_list):
        self.pids = set()
        self.names = set()
        self.depth_limit = args.depth_limit
        self.__append_list(proc_list)

    def __append_list(self, target_list):
        if target_list is None:
            return

        for target in target_list:
            if isinstance(target, list):
                self.__append_list(target)
            else:
                self.__append(target)

    def __append(self, target):
        if target.isdecimal():
            self.pids.add(int(target))
        else:
            self.names.add(target)

    def match(self, proc):
        return (proc.pid in self.pids) or (proc.name in self.names)


class SearchedProcFinder(ProcessFinder):
    def __init__(self, args):
        super(SearchedProcFinder, self).__init__(args, args.searched_processes)


class ExclusionFinder(ProcessFinder):
    def __init__(self, args):
        super(ExclusionFinder, self).__init__(args, args.exclusion_processes)

    def match(self, proc):
        matched = super(ExclusionFinder, self).match(proc)
        if matched:
            return True
        if self.depth_limit is not None and proc.depth > self.depth_limit:
            return True
        return False


class ProcessTree(object):

    def __init__(self, args):
        self.args = args
        self.display_manager = DisplayManager(args)
        self.searched_proc_finder = SearchedProcFinder(args)
        self.exclusion_finder = ExclusionFinder(args)

        self.proc_map = {}
        for proc in self.__list_processes(args):
            self.proc_map[proc.pid] = proc

        self.root_proc_list = []
        self.__associate_parent_with_children()
        self.__set_depth_of_process()

        if len(args.searched_processes) > 0:
            self.__pickup_seached_processes()
        self.__mark_excluded_processes()

        # The following method shall be called before show_tree() is called
        # to get the maximum width of each column.
        self.__render_display_elements_for_all_process()

    def __list_processes(self, args):
        re_proc_name = re.compile(r'^\d+$')
        entries = os.listdir('/proc')
        for dirname in filter(lambda x: re_proc_name.match(x), entries):
            pid = dirname
            if args.show_thread:
                for tid in os.listdir('/proc/%s/task' % pid):
                    yield Process(self.args, pid, tid)
            else:
                yield Process(self.args, pid, pid)

    def __associate_parent_with_children(self):
        for pid, proc in self.proc_map.items():
            parent = self.proc_map.get(proc.ppid)
            proc.parent = parent
            if parent is None:
                self.root_proc_list.append(proc)
            else:
                parent.children.append(proc)

    def __iterate_process_tree(self, force_all=False):
        proc_list = []

        def iterate(proc):
            if proc.excluded and (not force_all):
                return
            proc_list.append(proc)
            for child in proc.children:
                iterate(child)

        for root_proc in self.root_proc_list:
            iterate(root_proc)
        return proc_list

    def __pickup_seached_processes(self):

        def exclude_all_processes():
            for proc in self.__iterate_process_tree(force_all=True):
                proc.excluded = True

        def pickup_branch(proc_list):
            for proc in proc_list:
                if not proc.excluded:
                    # ancestors or descendant are already picked up
                    # we can skip
                    break
                proc.excluded = False

        exclude_all_processes()
        for proc in self.__iterate_process_tree(force_all=True):
            if not self.searched_proc_finder.match(proc):
                continue
            if not proc.excluded:
                # already pickedup
                continue
            proc.excluded = False
            pickup_branch(proc.ancestors())
            pickup_branch(proc.descendants())


    def __mark_excluded_processes(self):
        for proc in self.__iterate_process_tree():
             proc.excluded = self.exclusion_finder.match(proc)

    def __set_depth_of_process(self):
        for proc in self.__iterate_process_tree():
            if proc.parent is None:
                proc.depth = 0
            else:
                proc.depth = proc.parent.depth + 1

    def __render_display_elements_for_all_process(self):
        for proc in self.__iterate_process_tree():
            proc.disp_elem_list = []
            for display, value_getter in self.display_manager.display_list:
                v = value_getter(proc)
                proc.disp_elem_list.append(display.create(v))

    def __create_one_proc_line(self, proc, formatter):
        sep = formatter.get_separator()
        s = sep.join([disp_elem.render() for disp_elem in proc.disp_elem_list])
        print(s)

    def show_header(self, formatter):
        sep = formatter.get_separator()
        disp_mgr_list = self.display_manager.display_list
        s = sep.join([disp.renderHeader() for disp, x in disp_mgr_list])
        print(s)

    def show_tree(self):
        formatter = Formatter()
        self.show_header(formatter)
        for proc in self.__iterate_process_tree():
            self.__create_one_proc_line(proc, formatter)

    def show_list(self):
        for proc in self.proc_map.values():
            print(proc)


def append_display_list_if_needed(args):
    if args.append:
        args.output[0:0] = args.append

def run(args):
    append_display_list_if_needed(args)

    proc_tree = ProcessTree(args)
    if args.list_processes:
        proc_tree.show_list()
    proc_tree.show_tree()


HELP_MSG_SUDO='''
run as a root user. This option is required to show namespaces such as netns
and pidns
'''

HELP_MSG_OUTPUT='''
add output ITEMs: %s
''' % ', '.join(DisplayManager.column_def.keys())

HELP_MSG_APPEND='''
add ITEMs before the default items: 'pid' and 'cmd'
'''

HELP_MSG_VSZ_UNIT='set the unit of VSZ (Virtual Memory Size) (Default: MiB)'
HELP_MSG_RSS_UNIT='set the unit of RSS (Resident Size Set) (Default: MiB)'

HELP_MSG_SHOW_NAME='''
show a number instead of user or group name. This is effective for
ruid, euid, suid, fuid, rgid, egid, sgid, and fgid
'''

HELP_MSG_SEARCHED_PROCESS='''
only show the specified proesses and their ancestors and descendants
'''

HELP_MSG_EXCLUSION_PROCESS='''
exclude a proecess and its descendant from the output.
PROC is either a process ID or the process name
'''

HELP_MSG_DEPTH_LIMIT='''
show processes whose depth are smaller than or equals to DEPTH
(DEPTH starts from 0)
'''

def main():

    size_unit_choices = MemoryDisplay.unit_map.keys()

    parser = argparse.ArgumentParser(description='A tool to list processes.')
    parser.add_argument('-l', '--list-processes', action='store_true',
                        help=argparse.SUPPRESS)
    parser.add_argument('-c', '--command-line', action='store_true',
                        help='show a command line instead of the process name')
    parser.add_argument('-t', '--show-thread', action='store_true',
                        help='show threds')
    parser.add_argument('-s', '--sudo', action='store_true',
                        help=HELP_MSG_SUDO)
    parser.add_argument('-o', '--output', nargs='+', default=['pid', 'cmd'],
                        choices=DisplayManager.column_def.keys(),
                        metavar='ITEM', help=HELP_MSG_OUTPUT)
    parser.add_argument('-a', '--append', nargs='+', default=[],
                        choices=DisplayManager.column_def.keys(),
                        metavar='ITEM', help=HELP_MSG_APPEND)
    parser.add_argument('--vsz-unit', choices=size_unit_choices, default='MiB',
                        help=HELP_MSG_VSZ_UNIT)
    parser.add_argument('--rss-unit', choices=size_unit_choices, default='MiB',
                        help=HELP_MSG_RSS_UNIT)
    parser.add_argument('-w', '--max-cmd-width', type=int, default=0,
                        metavar='WIDTH',
                        help='limit the line width for each process')
    parser.add_argument('-n', '--show-name-instead-of-id', action='store_true',
                        help=HELP_MSG_SHOW_NAME)
    parser.add_argument('-S', '--searched-processes', nargs='+',
                        action='append', metavar='PROC', default=[],
                        help=HELP_MSG_SEARCHED_PROCESS)
    parser.add_argument('-E', '--exclusion-processes', nargs='+',
                        action='append', metavar='PROC',
                        help=HELP_MSG_EXCLUSION_PROCESS)
    parser.add_argument('-D', '--depth-limit', type=int, metavar='DEPTH',
                        help=HELP_MSG_DEPTH_LIMIT)

    # This is for internal use
    parser.add_argument('--subprocess', action='store_true',
                        help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.sudo and not args.subprocess:
        cmd = ['sudo']
        cmd.extend(sys.argv)
        cmd.append('--subprocess')
        subprocess.call(cmd)
    else:
        run(args)


if __name__ == '__main__':
    main()
