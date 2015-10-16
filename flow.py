import argparse
import logging
import os
import sys
import time
from capstone import *
from copy import copy
from collections import Counter
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.relocation import RelocationSection
from Queue import Queue
from threading import Thread

from pin_wrapper import pin_cmd

trace_opts = ['function', 'plt', 'loop']

class Function:
    def __init__(self, start_address, name, is_plt = False):
        self.start_address = int(start_address)
        self.name = name
        self.is_plt = is_plt
        self.instructions = []
        # Maps address -> list of operations corresponding to that address
        #    Need a list here if (for instance) the instruction pointed to by a backwards jmp is a call
        self.operations = {} 

    
    def __repr__(self):
        return '<Function {} @ {}>'.format(self.name, hex(self.start_address))
    
    def add_instruction(self, instruction):
        self.instructions.append(instruction)

    def add_operation(self, operation, addr):
        if addr in self.operations:
            self.operations[addr].append(operation)
        else:
            self.operations[addr] = [operation]

class FunctionCall:
    def __init__(self, dest_function):
        self.dest_function = dest_function
    
    def printable(self):
        return 'Call to function {}'.format(self.dest_function.name)

class Loop:
    def __init__(self, addr_of_jump, jump_address):
        self.source_addresses = [addr_of_jump]
        self.start_address = jump_address
        self.hits = 1
    
    def add_hit(self, source_addr):
        self.source_addresses.append(source_addr)
        self.hits += 1
    
    def printable(self):
        return 'Loop hit {} time(s)'.format(self.hits)

# Creates a dict that maps address to operation (CsInsn)
def get_address_operation_map(cmd):
    elf = ELFFile(open(cmd, 'rb'))
    
    text_section = elf.get_section_by_name('.text')
    
    text_mem_start = text_section.header['sh_addr']
    
    logging.debug('Got .text start @ {}'.format(hex(text_mem_start)))
    
    op_map = {}
    
    cs = Cs(CS_ARCH_X86, CS_MODE_32 if elf.elfclass == 32 else CS_MODE_64)
    cs.detail = True
    for ins in cs.disasm(text_section.data(), text_mem_start):
        op_map[ins.address] = ins
    
    return op_map

# Creates a dict of all function addresses mapped to their Function objects (generating 'sub_' names as needed)
def get_functions(cmd, op_map):
    functions = {}
    
    elf = ELFFile(open(cmd, 'rb'))
    libc_start_main_addr = None
    
    # Add in (or overwrite) function names with anything provided in symtab
    symbol_table = elf.get_section_by_name('.symtab')
    if symbol_table is not None:
        for symbol in symbol_table.iter_symbols():
            if symbol['st_info']['type'] == 'STT_FUNC':
                functions[symbol['st_value']] = Function(symbol['st_value'], symbol.name)
    
    # Add in PLT
    # .rela.plt contains indexes to reference both .dynsym (symbol names) and .plt (jumps to GOT)
    reloc_section = elf.get_section_by_name('.rela.plt')
    if reloc_section is not None:
        dynsym = elf.get_section(reloc_section['sh_link']) # .dynsym
        plt = elf.get_section_by_name('.plt') # .plt
        for reloc in reloc_section.iter_relocations():
            # Get the symbol's name from dynsym and the symbol's address from .plt's address + offset
            symbol_name = dynsym.get_symbol(reloc['r_info_sym']).name
            plt_addr = plt['sh_addr'] + (reloc['r_info_sym'] * plt['sh_entsize'])
            functions[plt_addr] = Function(plt_addr, symbol_name + '@PLT', is_plt = True)
            if symbol_name == '__libc_start_main':
                libc_start_main_addr = plt_addr
    
    # Finally, add in all functions that are called
    for ins in op_map.values():
        if ins.bytes[0] == 0xE8:
            called_addr = ins.operands[0].imm
            if functions.get(called_addr) is None:
                logging.debug('Instruction at {} calls function at {}'.format(hex(int(ins.address)), hex(called_addr)))
                functions[called_addr] = Function(ins.address, "sub_" + hex(called_addr)[2:])
    
    
    if libc_start_main_addr is None:
        logging.debug('Cannot locate call to libc_start_main in executable! This is not good!')
        sys.exit(1)
    
    addrs = sorted(op_map)
    for i in range(len(addrs)):
        ins = op_map[addrs[i]]
        # Find  'call __libc_start_main'
        if ins.bytes[0] == 0xE8 and ins.operands[0].imm == libc_start_main_addr:
            # Instruction before this is  mov edi, {address of main}
            load_main_ins = op_map[addrs[i-1]]
            main_addr = load_main_ins.operands[1].imm
            functions[main_addr] = Function(main_addr, "main")
    
    return functions

# Recursively called with the trace Queue, so the first instruction's address should be the function's address
def analyze_function(trace, op_map, functions, opts=trace_opts):
    function = None
    
    address = trace.get()
    if address in functions:
        function = copy(functions[address])
        logging.debug('Beginning analysis of function at {}'.format(hex(address)))
        while not trace.empty():
            address = trace.get()
            if address in op_map:
               ins = op_map[address]
               function.add_instruction(ins)
               
               if ins.bytes[0] == 0xE8: # call
                   called_func = functions.get(ins.operands[0].imm)
                   logging.debug('In function {}, found call to function {}'.format(function, called_func))
                   if called_func.is_plt:
                       # We don't want to analyze calls to external functions (e.g. printf),
                       #  so we just toss the trace up until the next expected instruction in this function
                       sub_func = called_func
                       sorted_instructions = sorted(op_map)
                       next_ins_addr = int(sorted_instructions[sorted_instructions.index(address) + 1])
                       while trace.queue[0] != next_ins_addr:
                           trace.get()
                       logging.debug('Skipping analysis of PLT function {}. Resuming at address {}'.format(called_func, hex(next_ins_addr)))
                   else:
                       # Recurse into the called function and analyze it
                       logging.debug('Analyzing function {}'.format(called_func))
                       sub_func = analyze_function(trace, op_map, functions, opts=trace_opts)
                       logging.debug('Returned from call to {}'.format(hex(ins.operands[0].imm)))
                   
                   function.add_operation(FunctionCall(sub_func), ins.address)
               
               if ins.mnemonic == 'ret': # ret
                   return function
               
               # TODO: Better parsing/filtering of jumps
               if ins.mnemonic[0] == 'j': # jump of some kind
                   dest_addr = int(ins.op_str, 16)
                   if dest_addr < ins.address: # Presumably a loop
                       if dest_addr in function.operations and len([x for x in function.operations[dest_addr] if isinstance(x, Loop)]) == 1:
                           existing_loop = [x for x in function.operations[dest_addr] if isinstance(x, Loop)][0]
                           existing_loop.add_hit(ins.addr)
                       else:
                           function.add_operation(Loop(ins.address, dest_addr), dest_addr)
    
    return function

def gen_call_graph(trace, op_map, functions, opts=trace_opts):
    # For now, skip until we hit main
    main_addr = [x.start_address for x in functions.values() if x.name == 'main'][0]
    while trace.queue[0] != main_addr:
        trace.get()
    logging.info('Beginning trace analysis')
    analysis = analyze_function(trace, op_map, functions, opts)
    logging.info('Trace analysis finished')
    
    return analysis

def display_call_graph(start_function, opts, layer=0):
    for addr in sorted(start_function.operations):
        for op in start_function.operations[addr]:
            if 'function' in opts and isinstance(op, FunctionCall):
                if op.dest_function.is_plt and 'plt' in opts:
                    print '{}{}: {}'.format(' '*4*layer, hex(int(addr)), op.printable())
                elif not op.dest_function.is_plt:
                    print '{}{}: {}'.format(' '*4*layer, hex(int(addr)), op.printable())
                    display_call_graph(op.dest_function, opts, layer+1)
            elif 'loop' in opts and isinstance(op, Loop):
                print '{}{}: {}'.format(' '*4*layer, hex(int(addr)), op.printable())

def main():
    # Needed for PIN to work
    if open('/proc/sys/kernel/yama/ptrace_scope').read()[0] != '0':
        print 'You must run \'echo 0 > /proc/sys/kernel/yama/ptrace_scope\' as root before using this!'
        sys.exit(1)
    
    
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', action='store_true', help='Run in debug mode')
    parser.add_argument('-s', '--save-trace', action='store_true', help='Save the trace for future re-analysis')
    
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument('-i', '--input', help='Text to send to program\'s stdin')
    g.add_argument('-t', '--trace', help='Existing trace to use (instead of creating a new one)')
    
    parser.add_argument('-b', '--binary', help='Executable to trace', required=True)
    
    parser.add_argument('options', nargs='+', help='Types of instructions you want to trace. Use \'all\' for all options.')
    
    
    args = parser.parse_args()
    
    logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.INFO)
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if args.input is not None:
        stdin = args.input
    else:
        stdin = ''
    
    
    cmd = args.binary
    
    # Use a queue to hold the trace because we never need to go backwards in the trace and it allows us to nicely recurse down the call chain
    trace = Queue()
    
    # Use existing trace if present
    if args.trace:
        logging.debug('Using existing trace "{}"'.format(args.trace))
        [trace.put(int(x, 16)) for x in open(args.trace).read().split()[:-1]]
    else:
        if not os.path.exists(cmd): # TODO: split executable name off of cmd (if cmdline args are needed for target program)
            raise ValueError('Executable doesn\'t exist!')
        if args.save_trace:
            trace_filename = '{}-{}.trace'.format(cmd, int(time.time()))
            instructs = pin_cmd('itrace.so', cmd, stdin, temp_filename=trace_filename)
            logging.info('Trace saved to {}'.format(trace_filename))
        else:
            instructs = pin_cmd('itrace.so', cmd, stdin)
        [trace.put(int(x, 16)) for x in instructs[:-1]]
    
    
    if 'all' in args.options:
        args.options = trace_opts
    else:
        for o in args.options:
            if o not in trace_opts:
                print 'Option {} is not recognized'.format(o)
                sys.exit(1)
    
    
    op_map = get_address_operation_map(cmd)
    logging.info('Mapped {} operations'.format(len(op_map)))
    functions = get_functions(cmd, op_map)
    logging.debug('Function addr->name map:\n' + '\n'.join(['    {}: {}'.format(hex(f), functions[f].name) for f in functions]))
    
    call_graph = gen_call_graph(trace, op_map, functions)
    
    display_call_graph(call_graph, args.options)

if __name__=='__main__':
    main()

