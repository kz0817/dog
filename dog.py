#!/usr/bin/env python3
import argparse
import re
import os

class process(object):

    def __init__(self, pid):
        stat_arr = self.__read_stat(pid)

        self.pid = int(stat_arr[0])
        self.ppid = int(stat_arr[3])
        self.name = self.__get_name(stat_arr)
        self.vsz = int(stat_arr[22])
        self.rss = int(stat_arr[23]) * 4096

        self.parent = None
        self.children = []

    def __read_stat(self, pid):
        with open(f'/proc/{pid}/stat') as f:
            return f.read().split()

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


class process_tree(object):

    def __init__(self):
        self.proc_map = {}
        self.root_proc_list = []
        for proc in self.__list_processes():
            self.proc_map[proc.pid] = proc

        self.__associate_parent_with_children()

    def __list_processes(self):
        re_proc_name = re.compile(r'^\d+$')
        entries = os.listdir('/proc')
        for dirname in filter(lambda x: re_proc_name.match(x), entries):
            yield process(pid=dirname)

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

    def __create_one_proc_line(self, proc, depth):
        s = self.__create_space_header(depth)
        s += f'{proc.name}'
        print(s)
        for child in proc.children:
            self.__create_one_proc_line(child, depth+1)

    def show_tree(self):
        for root_proc in self.root_proc_list:
            self.__create_one_proc_line(root_proc, 0)

    def show_list(self):
        for proc in self.proc_map.values():
            print(proc)


def run(args):
    proc_tree = process_tree()
    if args.list_processes:
        proc_tree.show_list()
    proc_tree.show_tree()


def main():
    parser = argparse.ArgumentParser(description='A tool to list processes.')
    parser.add_argument('-l', '--list-processes', action='store_true')
    args = parser.parse_args()
    run(args)


if __name__ == '__main__':
    main()
