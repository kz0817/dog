#!/usr/bin/env python3
import argparse
import re
import os

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
        if self.align == self.LEFT:
            return msg.ljust(self.get_width())
        else:
            return msg.rjust(self.get_width())


class CommandDisplay(Display):
    def __init__(self, title, show_command_line):
        super(CommandDisplay, self).__init__(title, Display.LEFT)
        self.__show_command_line = show_command_line

    def create(self, proc):
        s = ''
        s += self.__create_space_header(proc.depth)
        if self.__show_command_line:
            s += ' '.join(proc.cmd_arr)
        else:
            s += f'{proc.name}'
        return super(CommandDisplay, self).create(s)

    def __create_space_header(self, depth):
        return ''.join([' ' for i in range(depth*2)])


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
        disp_val = '%.1f' % (val / self.__scale)
        return super(MemoryDisplay, self).create(disp_val)


class Process(object):

    PAGE_SIZE = 0x1000

    def __init__(self, args, pid):

        stat_arr = self.__read_stat(pid)

        self.pid = int(stat_arr[0])
        self.status = stat_arr[2]
        self.ppid = int(stat_arr[3])
        self.name = self.__get_name(stat_arr)
        self.num_threads = int(stat_arr[19])
        self.vsz = int(stat_arr[22])
        self.rss = int(stat_arr[23]) * self.PAGE_SIZE

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

class DisplayManager(object):
    def __init__(self, args):
        column_def = {
            'pid': (
                lambda: Display('PID'),
                lambda proc: proc.pid,
            ),
            'cmd': (
                lambda: CommandDisplay('COMMAND', args.command_line),
                lambda proc: proc,
            ),
            'stat': (
                lambda: Display('S'),
                lambda proc: proc.status,
            ),
            'vsz': (
                lambda: MemoryDisplay('VSZ'),
                lambda proc: proc.vsz,
            ),
            'rss': (
                lambda: MemoryDisplay('RSS'),
                lambda proc: proc.rss,
            ),
            'nthr': (
                lambda: Display('Nth'),
                lambda proc: proc.num_threads,
            ),
        }

        self.display_list = []
        for column_name in args.output:
            generator, value_getter = column_def[column_name]
            disp = generator()
            self.display_list.append((disp, value_getter))

    def render(self, proc):
        for disp, value_getter in self.display_list:
            yield disp.create(value_getter(proc))


class ProcessTree(object):

    def __init__(self, args):
        self.args = args
        self.display_manager = DisplayManager(args)

        self.proc_map = {}
        for proc in self.__list_processes(args):
            self.proc_map[proc.pid] = proc

        self.root_proc_list = []
        self.__associate_parent_with_children()
        self.__set_depth_of_process()

        # The following method shall be called before show_tree() is called
        # to get the maximum width of each column.
        self.__render_display_elements_for_all_process()

    def __list_processes(self, args):
        re_proc_name = re.compile(r'^\d+$')
        entries = os.listdir('/proc')
        for dirname in filter(lambda x: re_proc_name.match(x), entries):
            yield Process(self.args, pid=dirname)

    def __associate_parent_with_children(self):
        for pid, proc in self.proc_map.items():
            parent = self.proc_map.get(proc.ppid)
            proc.parent = parent
            if parent is None:
                self.root_proc_list.append(proc)
            else:
                parent.children.append(proc)

    def __set_depth_of_process(self):

        def set_children_depth(proc):
            for child in proc.children:
                child.depth = proc.depth + 1
                set_children_depth(child)

        for root_proc in self.root_proc_list:
            root_proc.depth = 0
            set_children_depth(root_proc)

    def __render_display_elements_for_all_process(self):
        for pid, proc in self.proc_map.items():
            proc.disp_elem_list = []
            for display, value_getter in self.display_manager.display_list:
                v = value_getter(proc)
                proc.disp_elem_list.append(display.create(v))

    def __create_one_proc_line(self, proc, formatter):
        sep = formatter.get_separator()
        s = sep.join([disp_elem.render() for disp_elem in proc.disp_elem_list])
        print(s)
        for child in proc.children:
            self.__create_one_proc_line(child, formatter)

    def show_header(self, formatter):
        sep = formatter.get_separator()
        disp_mgr_list = self.display_manager.display_list
        s = sep.join([disp.renderHeader() for disp, x in disp_mgr_list])
        print(s)

    def show_tree(self):
        formatter = Formatter()
        self.show_header(formatter)
        for root_proc in self.root_proc_list:
            self.__create_one_proc_line(root_proc, formatter)

    def show_list(self):
        for proc in self.proc_map.values():
            print(proc)


def run(args):
    proc_tree = ProcessTree(args)
    if args.list_processes:
        proc_tree.show_list()
    proc_tree.show_tree()


def main():

    output_choices = [
        'pid', 'cmd', 'stat', 'vsz', 'rss', 'nthr',
    ]

    parser = argparse.ArgumentParser(description='A tool to list processes.')
    parser.add_argument('-l', '--list-processes', action='store_true')
    parser.add_argument('-c', '--command-line', action='store_true')
    parser.add_argument('-o', '--output', nargs='*', default=['pid', 'cmd'],
                        choices=output_choices)
    args = parser.parse_args()
    run(args)


if __name__ == '__main__':
    main()
