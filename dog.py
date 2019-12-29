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
        s = 'PID'.ljust(self.get_pid_width())
        s += self.get_separator()
        s += 'S'.ljust(self.get_status_width())
        s += self.get_separator()
        s += 'Command'
        return s


class Process(object):

    def __init__(self, pid, args):
        stat_arr = self.__read_stat(pid)

        self.pid = int(stat_arr[0])
        self.status = stat_arr[2]
        self.ppid = int(stat_arr[3])
        self.name = self.__get_name(stat_arr)
        self.vsz = int(stat_arr[22])
        self.rss = int(stat_arr[23]) * 4096

        self.parent = None
        self.children = []

        if args.command_line:
            self.cmd_arr = self.__read_commandline(pid)


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
        s = f'{self.pid}'.rjust(formatter.get_pid_width())
        s += formatter.get_separator()
        s += f'{self.status}'.rjust(formatter.get_status_width())
        return s


class ProcessTree(object):

    def __init__(self, args):
        self.__args = args
        self.proc_map = {}
        self.root_proc_list = []
        for proc in self.__list_processes():
            self.proc_map[proc.pid] = proc

        self.__associate_parent_with_children()

    def __list_processes(self):
        re_proc_name = re.compile(r'^\d+$')
        entries = os.listdir('/proc')
        for dirname in filter(lambda x: re_proc_name.match(x), entries):
            yield Process(pid=dirname, args=self.__args)

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
        if self.__args.command_line:
            s += " ".join(proc.cmd_arr)
        else:
            s += f'{proc.name}'
        print(s)
        for child in proc.children:
            self.__create_one_proc_line(child, formatter, depth+1)

    def show_tree(self):
        formatter = Formatter()
        print(formatter.get_header())
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
    args = parser.parse_args()
    run(args)


if __name__ == '__main__':
    main()
