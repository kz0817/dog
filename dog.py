#!/usr/bin/env python3
import argparse
import re
import os

class Formatter(object):

    def get_pid_width(self):
        return 6

    def get_status_width(self):
        return 1

    def get_separator(self):
        return ' '

    def get_header(self):
        return s

class MemoryDisplay(object):
    unit_map = {
        'B': 1,
        'KiB': 1024.0,
        'MiB': 1024.0 * 1024,
        'GiB': 1024.0 * 1024 * 1024,
        'TiB': 1024.0 * 1024 * 1024 * 1024,
    }

    TITLE = 'VSZ'

    def __init__(self, unit='MiB'):
        self.__scale = self.unit_map[unit]
        self.max_length = 0

    def create(self, val):
        disp_val = '%.1f' % (val / self.__scale)
        if len(disp_val) > self.max_length:
            self.max_length = len(disp_val)
        return disp_val

    def get_width(self):
        return max(len(self.TITLE), self.max_length)

    def renderHeader(self):
        return self.TITLE.rjust(self.get_width())

    def renderValue(self, disp_val):
        return disp_val.rjust(self.get_width())


class Context(object):
    def __init__(self, args):
        self.args = args
        self.vsz_mem_disp = MemoryDisplay()


class Process(object):

    PAGE_SIZE = 0x1000

    def __init__(self, ctx, pid):
        self.__ctx = ctx
        args = ctx.args
        stat_arr = self.__read_stat(pid)

        self.pid = int(stat_arr[0])
        self.status = stat_arr[2]
        self.ppid = int(stat_arr[3])
        self.name = self.__get_name(stat_arr)
        self.vsz = int(stat_arr[22])
        self.rss = int(stat_arr[23]) * self.PAGE_SIZE

        self.parent = None
        self.children = []

        if args.command_line:
            self.cmd_arr = self.__read_commandline(pid)

        if args.virtual_memory_size:
            self.vsz_disp = ctx.vsz_mem_disp.create(self.vsz)


    def __read_stat(self, pid):
        with open(f'/proc/{pid}/stat') as f:
            return f.read().split()

    def __read_commandline(self, pid):
        with open(f'/proc/{pid}/cmdline') as f:
            return f.read().split('\0')

    def __get_name(self, stat_arr):
        return stat_arr[1][1:-1]

    def __str__(self):
        s = ''
        s += f'pid: {self.pid: >6}, '
        s += f'ppid: {self.ppid: >6}, '
        vsz_m = self.vsz / 1024.0 / 1024
        rss_m = self.rss / 1024.0 / 1024
        s += f'vsz-m: {vsz_m: >6.1f}, '
        s += f'rss-k: {rss_m: >6.1f}, '
        s += f'name: {self.name}, '
        return s

    def get_info_line(self, formatter):
        ctx = self.__ctx
        s = f'{self.pid}'.rjust(formatter.get_pid_width())
        s += formatter.get_separator()
        s += f'{self.status}'.rjust(formatter.get_status_width())
        s += formatter.get_separator()
        if ctx.args.virtual_memory_size:
            s += ctx.vsz_mem_disp.renderValue(self.vsz_disp)
        return s


class ProcessTree(object):

    def __init__(self, args):
        self.__ctx = Context(args)
        self.proc_map = {}
        self.root_proc_list = []
        for proc in self.__list_processes():
            self.proc_map[proc.pid] = proc

        self.__associate_parent_with_children()

    def __list_processes(self):
        re_proc_name = re.compile(r'^\d+$')
        entries = os.listdir('/proc')
        for dirname in filter(lambda x: re_proc_name.match(x), entries):
            yield Process(self.__ctx, pid=dirname)

    def __associate_parent_with_children(self):
        for pid, proc in self.proc_map.items():
            parent = self.proc_map.get(proc.ppid)
            proc.parent = parent
            if parent is None:
                self.root_proc_list.append(proc)
            else:
                parent.children.append(proc)

    def __create_space_header(self, depth):
        return ''.join([' ' for i in range(depth*2)])

    def __create_one_proc_line(self, proc, formatter, depth):
        s = proc.get_info_line(formatter)
        s += formatter.get_separator()
        s += self.__create_space_header(depth)
        if self.__ctx.args.command_line:
            s += " ".join(proc.cmd_arr)
        else:
            s += f'{proc.name}'
        print(s)
        for child in proc.children:
            self.__create_one_proc_line(child, formatter, depth+1)

    def show_header(self, formatter):
        ctx = self.__ctx

        s = 'PID'.ljust(formatter.get_pid_width())
        s += formatter.get_separator()
        s += 'S'.ljust(formatter.get_status_width())
        s += formatter.get_separator()
        if ctx.args.virtual_memory_size:
            s += ctx.vsz_mem_disp.renderHeader()
        s += formatter.get_separator()
        s += 'Command'
        print(s)

    def show_tree(self):
        formatter = Formatter()
        self.show_header(formatter)
        for root_proc in self.root_proc_list:
            self.__create_one_proc_line(root_proc, formatter, 0)

    def show_list(self):
        for proc in self.proc_map.values():
            print(proc)


def run(args):
    proc_tree = ProcessTree(args)
    if args.list_processes:
        proc_tree.show_list()
    proc_tree.show_tree()


def main():
    parser = argparse.ArgumentParser(description='A tool to list processes.')
    parser.add_argument('-l', '--list-processes', action='store_true')
    parser.add_argument('-c', '--command-line', action='store_true')
    parser.add_argument('-vsz', '--virtual-memory-size', action='store_true')
    args = parser.parse_args()
    run(args)


if __name__ == '__main__':
    main()
