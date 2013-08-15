#!/usr/bin/python

__doc__ = '''\
distill_menagerie.py

Increases the quality of a capture file collection.
'''

from optparse import OptionParser
import commands
import operator
import os
import os.path
import platform
import re
import shelve
import subprocess
import sys
import tempfile

debug_mem = False
if debug_mem:
	try:
		from pympler.asizeof import asizeof
	except:
		debug_mem = False

# command line arguments
tshark = ""
pin = ""
pintool = ""
menagerie = ""

cnt = 0

devnull = open(os.devnull, 'w')

def exit_msg(msg=None, status=1):
	if msg is not None:
		sys.stderr.write(msg + '\n\n')
	sys.stderr.write(__doc__ + '\n')
	sys.exit(status)

# http://www.codinghorror.com/blog/2007/12/sorting-for-humans-natural-sort-order.html
def sort_nicely(l):
	''' Sort the given list in the way that humans expect.
	'''
	convert = lambda text: int(text) if text.isdigit() else text
	alphanum_key = lambda key: [ convert(c) for c in re.split('([0-9]+)', key) ]
	l.sort( key=alphanum_key )
	return l


# branch_pcap_dic sample:
#
# 0x08050440 {'7686-rfcomm_channel_btsnoop.log': 53, 'ais': 2}
# 0x0805044b {'7686-rfcomm_channel_btsnoop.log': 52, 'ais': 1}
# 0x08050660 {'7686-rfcomm_channel_btsnoop.log': 51}
# 0x0805066b {'7686-rfcomm_channel_btsnoop.log': 50}
# 0x080506d0 {'7686-rfcomm_channel_btsnoop.log': 49, 'ais': 79}
# 0x080506db {'7686-rfcomm_channel_btsnoop.log': 48, 'ais': 78}
#
# branch_pcap_dic is a dictionary of dictionaries which keys are addresses of branches.
# The value associated with each branch address is a dictionary which keys are names of capture files
# which execution path contains the corresponding branch address, and values are counters.
# A counter indicates the number of successive branches in the execution path of the associated 
# capture file starting from the corresponding branch.

# XXX - We need to catch any exceptions below and clean up accordingly.
bcd_name = os.path.join(
	tempfile.gettempdir(),
	('distill_menagerie_branch_%d' % os.getpid())
	)
branch_pcap_dic = shelve.open(bcd_name)

## Create the directory "to_remove" in the menagerie directory and move the capture files to remove to that directory.
#  @param[in]	captures_to_rm	set containing the names of the capture files to remove
def mv_captures_to_rm(captures_to_rm):
	commands.getoutput("mkdir %s/to_remove" % menagerie)
	for pcap in captures_to_rm:
		commands.getoutput("mv %s/%s %s/to_remove/" % (menagerie, pcap, menagerie))

## Iterate over the global branch_pcap_dic dictionary and retrieve the capture files to remove.
#  @param[in]	files	list containing the filenames in the menagerie
#  @return		set containing the names of the capture files to remove
def get_captures_to_rm(files):
	branches_ascending_order = sorted(branch_pcap_dic.keys())
	captures_to_keep = set()
	
	cnt = 0
	branch = branches_ascending_order[0]
	while True:
		pcap = max(branch_pcap_dic[branch].iteritems(), key=operator.itemgetter(1))[0]	
		captures_to_keep.add(pcap)	
		
		cnt = cnt+branch_pcap_dic[branch][pcap]
		if cnt == len(branch_pcap_dic):
			break
		
		branch = branches_ascending_order[cnt]
		
	captures_to_rm = set(files).difference(captures_to_keep)
	return captures_to_rm
	
## Fill the counters of the global branch_pcap_dic dictionary.
def fill_branch_pcap_dic_counters():
	global branch_pcap_dic

	branches_descending_order = sorted(branch_pcap_dic.keys(), reverse=True)
	
	prev_branch = branches_descending_order[0]
	for branch in branches_descending_order:
		for pcap in branch_pcap_dic[branch]:
			if pcap in branch_pcap_dic[prev_branch]:
				branch_pcap_dic[branch][pcap] = branch_pcap_dic[prev_branch][pcap]+1
			else:
				branch_pcap_dic[branch][pcap] = 1
		prev_branch = branch

## Read the execution path of a capture file and store it into the global branch_pcap_dic dictionary.
#  @param[in]	pcap	capture file to process
def read_pcap_path(pcap):
	global branch_pcap_dic, src_branches

	branches = [line.strip() for line in open("MyPinTool.out")]		
	for branch in branches:
		if not branch_pcap_dic.has_key(branch):
			branch_pcap_dic[branch] = {}		
		branch_pcap_dic[branch][pcap] = 0
		
## Run TShark on a capture file under Pin and store the execution path of TShark into "MyPinTool.out" file.
#  @param[in]	pcap	capture file to process with TShark
def write_pcap_path(pcap):
	pcap_path = os.path.join(menagerie, pcap)
	res = subprocess.call([
		'setarch', platform.machine(), '-R',
		pin,
		'-injection', 'child',
		'-t', pintool,
		'--',
		tshark, '-nVxr', pcap_path,
		],
		stdout=devnull, stderr=devnull)
	#print('Results for %s: %s' % (pcap_path, res))
		#"%s -injection child -t %s -- %s -nVxr %s/%s > /dev/null" % (pin, pintool, tshark, menagerie, pcap))

## Check if a file is a capture file.
#  @param[in]	filename	name of the file to process
#  @return		true if file is a capture file, false otherwise	
def file_is_pcap(filename):
	file_path = os.path.join(menagerie, filename)
	capinfos = os.path.join(os.path.dirname(tshark), 'capinfos')
	try:
		subprocess.check_call([capinfos, file_path], stdout=devnull, stderr=devnull)
	except subprocess.CalledProcessError:
		return False
	return True
	
## Distill the menagerie.
def distill_menagerie():
	global cnt

	files = sort_nicely(os.listdir(menagerie))
	print('Total file count: %d' % len(files))
	for filename in files:
		if debug_mem:
			print('Size of branch_pcap_dic: %.2f M' % (asizeof(branch_pcap_dic) / 1024.0 / 1024.0))
		if file_is_pcap(filename):
			print filename
			write_pcap_path(filename)
			read_pcap_path(filename)
			cnt = cnt+1
	print('Pcap count: %d' % cnt)
	if (cnt < 1):
		exit_msg('No valid capture files found.')
			
	fill_branch_pcap_dic_counters()	
	captures_to_rm = get_captures_to_rm(files)
	mv_captures_to_rm(captures_to_rm)
	
## Parse command line options.
def parse_cmd():
	global pin, pintool, menagerie, tshark

	parser = OptionParser()
	parser.add_option("-p", "--pin", dest="pin", help="location of pin")
	parser.add_option("-t", "--pintool", dest="pintool", help="location of the pintool")
	parser.add_option("-m", "--menagerie", dest="menagerie", help="location of the menagerie")
	parser.add_option("-b", "--tshark", dest="tshark", help="location of TShark")
	
	(options, args) = parser.parse_args()
	
	if (options.pin == None or options.pintool == None or options.menagerie == None or options.tshark == None):
		print "for help use --help"
		sys.exit(2)
		
	pin = options.pin
	pintool = options.pintool
	menagerie = options.menagerie
	tshark = options.tshark
	
def main():
	parse_cmd()	
	distill_menagerie()

if __name__ == "__main__":
	main()

#
# Editor modelines  -  http://www.wireshark.org/tools/modelines.html
#
# Local variables:
# c-basic-offset: 8
# tab-width: 8
# indent-tabs-mode: t
# End:
#
# vi: set shiftwidth=8 tabstop=8 noexpandtab:
# :indentSize=8:tabSize=8:noTabs=false:
#

