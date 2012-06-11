#!/usr/bin/python
# -*- coding: utf-8 -*-

# Python Y86 Assembler
# By Linus Yang <laokongzi@gmail.com>
# Licensed under Creative Commons BY-NC-SA 3.0
# Some Rights Reserved (c) 2012

from optparse import OptionParser
import re
import binascii
import os

regs = {
    "%eax": "0",
    "%ecx": "1",
    "%edx": "2",
    "%ebx": "3",
    "%esp": "4",
    "%ebp": "5",
    "%esi": "6",
    "%edi": "7",
    "rnone": "8"
}

instr = {
    "nop": "00",
    "halt": "10",
    "rrmovl": "20",
    "cmovle": "21",
    "cmovl": "22",
    "cmove": "23",
    "cmovne": "24",
    "cmovge": "25",
    "cmovg": "26",
    "irmovl": "30",
    "rmmovl": "40",
    "mrmovl": "50",
    "addl": "60",
    "subl": "61",
    "andl": "62",
    "xorl": "63",
    "jmp": "70",
    "jle": "71",
    "jl": "72",
    "je": "73",
    "jne": "74",
    "jge": "75",
    "jg": "76",
    "call": "80",
    "ret": "90",
    "pushl": "a0",
    "popl": "b0",
    "iaddl": "c0",
    "leave": "d0"
}

instbyte = {
    "nop": 1,
    "halt": 1,
    "rrmovl": 2,
    "cmovle": 2,
    "cmovl": 2,
    "cmove": 2,
    "cmovne": 2,
    "cmovge": 2,
    "cmovg": 2,
    "irmovl": 6,
    "rmmovl": 6,
    "mrmovl": 6,
    "addl": 2,
    "subl": 2,
    "andl": 2,
    "xorl": 2,
    "jmp": 5,
    "jle": 5,
    "jl": 5,
    "je": 5,
    "jne": 5,
    "jge": 5,
    "jg": 5,
    "call": 5,
    "ret": 1,
    "pushl": 2,
    "popl": 2,
    "iaddl": 6,
    "leave": 1
}

bytelen = {
    '.long': 4,
    '.word': 2,
    '.byte': 1
}

def stripComment(line):
    sharp = re.compile('#.*$')
    splash = re.compile('/\*.*\*/')
    comma = re.compile('\s*,\s*')
    linestr = line
    linestr = sharp.sub('', linestr)
    linestr = splash.sub('', linestr)
    linestr = comma.sub(',', linestr)
    return linestr

def stripLabel(line):
    lab = re.compile('([^\s]+):')
    linestr = line
    labmatch = lab.search(linestr)
    linestr = lab.sub('', linestr)
    if labmatch != None:
        return (labmatch.group(1), linestr)
    return None
        
def endianStr(x, length, bigendian=False):
    s = ''
    nowlen = 0
    while x != 0 and nowlen < length:
        if bigendian:
            s = "%.2x" % (x & 0xff) + s
        else:
            s += "%.2x" % (x & 0xff)
        x = x >> 8
        nowlen += 1
    while nowlen < length:
        if bigendian:
            s = '00' + s
        else:
            s += '00'
        nowlen += 1    
    return s    

def printError(error):
    print "[Assembly Error]"
    for err in error:
        print "Line %d: %s" % (err[0], err[1])
    
def main():
    print '[Y86 Assembler - 0.1.1 - Linus Yang]'
    parser = OptionParser('Usage: %prog [options] [assembly file]')
    parser.add_option("-l", "--largemem", action="store_true", dest="largemem", default=True, \
                      help="support code generation for more than 4096 bytes. (default is enabled)")
    parser.add_option("-b", "--bigendian", action="store_true", dest="bigendian", default=False, \
                      help="code generation using big-endian. (default is little-endian)")
    parser.add_option("-s", "--second", action="store_true", dest="second", default=False, \
                      help="using generation rules in csapp 2nd edition. (default using 1st editon rules)")
    parser.add_option("-a", "--asciibin", action="store_true", dest="asciibin", default=False, \
                      help="enable conversion binary object to ASCII digits. (default is disabled)")
    (options, args) = parser.parse_args()
    bigendian = options.bigendian
    asciibin = options.asciibin
    inputName = 'prog.ys'
    if args != []:
        inputName = args[0]
    try:
        fin = open(inputName)
    except:
        print '[Error] Cannot open input file: %s.' % (inputName)
        return
    if bigendian:
        print '[Warning] Generation using big-endian.'
    if options.second:
        regs['rnone'] = 'f'
        instr['nop'] = '10'
        instr['halt'] = '00'
        print '[Warning] Using csapp 2nd edition rules.'
    print 'Input File   : %s' % (inputName)
    
    binpos = 0
    linepos = 0
    alignment = 0
    labels = {}
    error = []
    strippedline = []
    origline = []
    yaslineno = {}
    
    #First pass to get labels and detect errors
    
    for line in fin:
        linepos += 1
        origline.append((linepos, line))
        nowline = stripComment(line)
        if nowline.find(':') != -1:
            try:
                (labelname, nowline) = stripLabel(nowline)
            except:
                error.append((linepos, 'Label error.'))
                continue
            if labelname in labels:
                error.append((linepos, 'Label repeated error.'))
                continue
            else:
                labels[labelname] = binpos
                yaslineno[linepos] = binpos
        linelist = []
        for element in nowline.split(' '):
            linelist.append(element.replace('\t', '').replace('\n', '').replace('\r', ''))
        while '' in linelist:
            linelist.remove('')
        if linelist == []:
            continue
        strippedline.append((linepos, linelist))
        try:
            if linelist[0] in instbyte:
                alignment = 0
                yaslineno[linepos] = binpos
                binpos += instbyte[linelist[0]]
            elif linelist[0] == '.pos':
                binpos = int(linelist[1], 0)
                yaslineno[linepos] = binpos
            elif linelist[0] == '.align':
                alignment = int(linelist[1], 0)
                if binpos % alignment != 0:
                    binpos += alignment - binpos % alignment
                yaslineno[linepos] = binpos
            elif linelist[0] in ('.long', '.word', '.byte'):
                yaslineno[linepos] = binpos
                if alignment != 0:
                    binpos += alignment
                else:
                    binpos += bytelen[linelist[0]]
            else:
                error.append((linepos,'Instruction "%s" not defined.' % (linelist[0])))
                continue
        except:
            error.append((linepos, 'Instruction error.'))
            continue
    fin.close()
    if error != []:
        printError(error)
        return
    
    #Second pass to convert binary
    
    yasbin = {}
    for line in strippedline:
        linepos = line[0]
        linelist = line[1]
        if linelist == []:
            continue
        resbin = ''
        if linelist[0] in instr:
            alignment = 0
            try:
                if linelist[0] in ('nop', 'halt', 'ret', 'leave'):
                    resbin = instr[linelist[0]]
                elif linelist[0] in ('pushl', 'popl'):
                    resbin = instr[linelist[0]] + regs[linelist[1]] + regs["rnone"]
                elif linelist[0] in ('addl', 'subl', 'andl', 'xorl', 'rrmovl') \
                     or linelist[0].startswith('cmov'):
                    reglist = linelist[1].split(',')
                    resbin = instr[linelist[0]] + regs[reglist[0]] + regs[reglist[1]]
                elif linelist[0].startswith('j') or linelist[0] == 'call':
                    resbin = instr[linelist[0]]
                    if linelist[1] in labels:
                        resbin += endianStr(labels[linelist[1]], 4, bigendian)
                    else: 
                        resbin += endianStr(int(linelist[1], 0), 4, bigendian)
                elif linelist[0] in ('irmovl', 'iaddl'):
                    reglist = linelist[1].split(',')  
                    if reglist[0] in labels:
                        instnum = endianStr(labels[reglist[0]], 4, bigendian)
                    else:
                        instnum = endianStr(int(reglist[0].replace('$', ''), 0), 4, bigendian)
                    resbin = instr[linelist[0]] + regs["rnone"] + \
                             regs[reglist[1]] + instnum
                elif linelist[0].endswith('movl'):
                    reglist = linelist[1].split(',')
                    if linelist[0] == 'rmmovl':
                        memstr = reglist[1]
                        regstr = reglist[0]
                    elif linelist[0] == 'mrmovl':
                        memstr = reglist[0]
                        regstr = reglist[1]
                    regre = re.compile('\((.+)\)')
                    regmatch = regre.search(memstr)
                    memint = regre.sub('', memstr)
                    if memint == '' or memint == None:
                        memint = '0'
                    resbin = instr[linelist[0]] + regs[regstr] + \
                             regs[regmatch.group(1)] + \
                             endianStr(int(memint, 0), 4, bigendian)
                else:
                    error.append((linepos, 'Instruction "%s" not defined.' % (linelist[0])))
                    continue  
            except:
                error.append((linepos, 'Instruction error.'))
                continue
        else:
            try:
                if linelist[0] == '.pos':
                    pass
                elif linelist[0] == '.align':
                    alignment = int(linelist[1], 0)
                elif linelist[0] in ('.long', '.word', '.byte'):
                    if alignment != 0:
                        length = alignment
                    else:
                        length = bytelen[linelist[0]]
                    if linelist[1] in labels:
                        resbin = endianStr(labels[linelist[1]], length, bigendian)
                    else:
                        resbin = endianStr(int(linelist[1], 0), length, bigendian)
                else:
                    error.append((linepos, 'Alignment error.'))
                    continue
            except:
                error.append((linepos, 'Alignment error.'))
                continue
        if resbin != '':
            yasbin[linepos] = resbin
            
    #Write to files
    
    binpos = 0
    maxaddrlen = 3
    if options.largemem:
        maxaddrlen = len("%x" % (max(yaslineno.values())))
        if maxaddrlen < 3:
            maxaddrlen = 3
    if error != []:
        printError(error)
    else:
        prefixName = os.path.splitext(inputName)[0]
        outputName = prefixName + '.yo'
        outbinName = prefixName + '.ybo'
        outascName = prefixName + '.yao'
        try:
            fout = open(outputName, 'w')
            fbout = open(outbinName, 'wb')
            if asciibin:
                faout = open(outascName, 'w')
        except:
            print '[Error] Cannot create output files.'
            return
        for line in origline:
            if (line[0] in yasbin) and (line[0] in yaslineno):
                ystr = yasbin[line[0]]
                nowaddr = yaslineno[line[0]]
                if binpos != nowaddr:
                    blank = '{0:0{width}d}'.format(0, width = 2 * (nowaddr - binpos))
                    if asciibin:
                        faout.write(blank)
                    fbout.write(binascii.a2b_hex(blank))
                    binpos = nowaddr
                binpos += len(ystr) // 2
                fout.write('  0x%.*x: %-12s | %s' % (maxaddrlen, nowaddr, ystr, line[1]))
                if asciibin:
                    faout.write(ystr)
                fbout.write(binascii.a2b_hex(ystr))
            elif line[0] in yaslineno:
                nowaddr = yaslineno[line[0]]
                fout.write('  0x%.*x:              | %s' % (maxaddrlen, nowaddr, line[1]))
            else:
                fout.write('    %*c               | %s' % (maxaddrlen, ' ', line[1]))
        print 'ASCII Object : %s' % (outputName)
        print 'Binary Object: %s' % (outbinName)
        if asciibin:
            print 'AscBin Object: %s' % (outascName)
            faout.close()
        fout.close()
        fbout.close()
    
if __name__ == '__main__':
    main()