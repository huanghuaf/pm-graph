#!/usr/bin/python
#
# Tool for analyzing boot timing
# Copyright (c) 2013, Intel Corporation.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms and conditions of the GNU General Public License,
# version 2, as published by the Free Software Foundation.
#
# This program is distributed in the hope it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# Authors:
#	 Todd Brandt <todd.e.brandt@linux.intel.com>
#
# Description:
#	 This tool is designed to assist kernel and OS developers in optimizing
#	 their linux stack's boot time. It creates an html representation of
#	 the kernel boot timeline up to the start of the init process.
#

# ----------------- LIBRARIES --------------------

import sys
import time
import os
import string
import re
import platform
import shutil
from datetime import datetime, timedelta
from subprocess import call, Popen, PIPE
import analyze_suspend as aslib

# ----------------- CLASSES --------------------

# Class: SystemValues
# Description:
#	 A global, single-instance container used to
#	 store system values and test parameters
class SystemValues(aslib.SystemValues):
	title = 'BootGraph'
	version = '2.1a'
	hostname = 'localhost'
	testtime = ''
	kernel = ''
	ftracefile = ''
	testdir = ''
	testdirprefix = 'boot'
	embedded = False
	testlog = False
	ftracelog = False
	usedevsrc = True
	suspendmode = 'boot'
	trace_wakeup_source = False
	trace_wakelock = False
	trace_cpuidle = False
	trace_cpufreq = False
	def __init__(self):
		if('LOG_FILE' in os.environ and 'TEST_RESULTS_IDENTIFIER' in os.environ):
			self.embedded = True
		self.hostname = platform.node()
		self.testtime = datetime.now().strftime('%Y-%m-%d_%H:%M:%S')
		if os.path.exists('/proc/version'):
			fp = open('/proc/version', 'r')
			val = fp.read().strip()
			fp.close()
			self.kernel = self.kernelVersion(val)
		else:
			self.kernel = 'unknown'
		self.testdir = datetime.now().strftime('boot-%y%m%d-%H%M%S')
	def kernelVersion(self, msg):
		return msg.split()[2]


sysvals = SystemValues()

# Class: Data
# Description:
#	 The primary container for test data.
class Data(aslib.Data):
	dmesg = {}  # root data structure
	start = 0.0 # test start
	end = 0.0   # test end
	dmesgtext = []   # dmesg text file in memory
	testnumber = 0
	idstr = ''
	html_device_id = 0
	valid = False
	initstart = 0.0
	boottime = ''
	phases = ['boot']
	do_one_initcall = False
	def __init__(self, num):
		self.testnumber = num
		self.idstr = 'a'
		self.dmesgtext = []
		self.dmesg = {
			'wakesource': {'list': dict(), 'start': -1.0, 'end': -1.0, 'row': 0, 'color': '#dddddd'},
			'wakelock': {'list': dict(), 'start': -1.0, 'end': -1.0, 'row': 0, 'color': '#dddddd'},
			'cpuidle': {'list': dict(), 'start': -1.0, 'end': -1.0, 'row': 0, 'color': '#dddddd'},
			'cpufreq': {'list': dict(), 'start': -1.0, 'end': -1.0, 'row': 0, 'color': '#dddddd'}
		}
	def deviceTopology(self):
		return ''
	def newAction(self, phase, name, start, end, ret, ulen):
		# new device callback for a specific phase
		self.html_device_id += 1
		devid = '%s%d' % (self.idstr, self.html_device_id)
		list = self.dmesg[phase]['list']
		length = -1.0
		if(start >= 0 and end >= 0):
			length = end - start
		i = 2
		origname = name
		while(name in list):
			name = '%s[%d]' % (origname, i)
			i += 1
		list[name] = {'name': name, 'start': start, 'end': end,
			'pid': 0, 'length': length, 'row': 0, 'id': devid,
			'ret': ret, 'ulen': ulen }
		return name

# ----------------- FUNCTIONS --------------------

def dumpFtraceData():
	for phase in data.dmesg:
		for item in data.dmesg[phase]['list']:
			print (phase, data.dmesg[phase]['list'][item], data.dmesg[phase]['list'][item]['name'], data.dmesg[phase]['list'][item]['start'], data.dmesg[phase]['list'][item]['end'])
	print
	print data.dmesg
	print 
	print data.dmesg['cpufreq']
	print 
	print data.dmesg['cpufreq']['list']
	print 
	print data.dmesg['cpufreq']['start']
	print 
	print data.dmesg['cpufreq']['end']

# Function: parseFtraceLog
# Description:
#	 parse a kernel log for boot data
def parseFtraceLog():
	data = Data(0)
	data.dmesg['wakesource']['start'] = data.start = ktime = 0.0
	data.dmesg['wakelock']['start'] = data.start = ktime = 0.0
	data.dmesg['cpuidle']['start'] = data.start = ktime = 0.0
	data.dmesg['cpufreq']['start'] = data.start = ktime = 0.0

	sysvals.stamp = {
		'time': datetime.now().strftime('%B %d %Y, %I:%M:%S %p'),
		'host': sysvals.hostname,
		'mode': 'boot', 'kernel': ''}

	devtemp = dict()
	if(sysvals.ftracefile):
		lf = open(sysvals.ftracefile, 'r')
	else:
		lf = Popen('dmesg', stdout=PIPE).stdout


	for line in lf:
		line = line.replace('\r\n', '')
		line = line.replace('\n', '')

		ftrace_line_fmt_nop = \
		' *(?P<proc>.*)-(?P<pid>[0-9]*) *\[(?P<cpu>[0-9]*)\] *'+\
		'(?P<flags>.{4}) *(?P<time>[0-9\.]*): *'+\
		'(?P<msg>.*)'
		m = re.match(ftrace_line_fmt_nop, line)
		if(not m):
			continue

		proc = m.group('proc')
		ktime = float(m.group('time'))
		#if(ktime > 120):
		#	break
		msg = m.group('msg')

		data.end = data.initstart = ktime
		data.dmesgtext.append(line)

	#Wakeup source processing
		if (sysvals.trace_wakeup_source):
			m = re.match('^wakeup_source_activate: *(?P<f>.*) .*', msg)
			if(m):
				if (data.dmesg['wakesource']['start']==0.0):
					data.dmesg['wakesource']['start'] = data.start = ktime
				devtemp[m.group('f')] = ktime
				continue

			m = re.match('^wakeup_source_deactivate: *(?P<f>.*) .*', msg)
			if(m):
				data.valid = True
				f = m.group('f')
				r = 0
				if(f in devtemp):
					t = ktime - devtemp[m.group('f')]
					data.newAction('wakesource', f, devtemp[f], ktime, int(r), int(t))
					data.end = ktime
					#print ('wakesource', f, str(devtemp[f])+'-'+str(ktime), str(t*1000000)+' us')
					del devtemp[f]
				continue
	#Wakelock processing
		if (sysvals.trace_wakelock):
			m = re.match('^pm_wake_lock: *(?P<f>.*)', msg)
			if(m):
				if (data.dmesg['wakelock']['start']==0.0):
					data.dmesg['wakelock']['start'] = data.start = ktime
				devtemp[m.group('f')] = ktime
				continue
			m = re.match('^pm_wake_unlock: *(?P<f>.*)', msg)
			if(m):
				data.valid = True
				f = m.group('f')
				r = 0
				if(f in devtemp):
					t = ktime - devtemp[m.group('f')]
					data.newAction('wakelock', f, devtemp[f], ktime, int(r), int(t))
					data.end = ktime
					#print ('wakelock', f, str(devtemp[f])+'-'+str(ktime), str(t*1000000)+' us')
					del devtemp[f]
				continue
	#Cpuidle start/end processing
		if (sysvals.trace_cpuidle):
			m = re.match('^cpu_idle: state=(?P<state>[0-9]*) *cpu_id=(?P<f>.*)', msg)
			if(m):
				if (data.dmesg['cpuidle']['start']==0.0):
					data.dmesg['cpuidle']['start'] = data.start = ktime
				state = int(m.group('state'))
				if state < 2:
					if state == 0:
						idle_state = 'WFI'
					elif state == 1:
						idle_state = 'POWEROFF'
					devtemp[m.group('f')] = ktime
					#print (m.group('f'), idle_state, 'start')
					continue
				else:
					data.valid = True
					f = m.group('f')
					r = 0
					if(f in devtemp):
						t = ktime - devtemp[m.group('f')]
						#print ('cpuidle', f,idle_state, str(devtemp[f])+'-'+str(ktime), str(t*1000000)+' us')
						data.newAction('cpuidle', f+'-'+idle_state, devtemp[f], ktime, int(r), int(t))
						data.end = ktime
						del devtemp[f]
					continue
	#cpufreq processing
		if (sysvals.trace_cpufreq):
			m = re.match('^cpu_frequency: state=(?P<freq>[0-9]*) *cpu_id=(?P<f>.*)', msg)
			if(m):
				if (data.dmesg['cpufreq']['start']==0.0):
					data.dmesg['cpufreq']['start'] = data.start = ktime
				r = 0
				t = 0.01
				f = m.group('f')
				freq = m.group('freq')
				data.valid = True
				data.newAction('cpufreq', f+'-'+freq, ktime, ktime + t, int(r), int(t))
				#print ('cpufreq', f, freq, ktime)
				data.end = ktime + t

	data.dmesg['wakesource']['end'] = data.end
	data.dmesg['wakelock']['end'] = data.end
	data.dmesg['cpuidle']['end'] = data.end
	data.dmesg['cpufreq']['end'] = data.end

	lf.close()
	return data

# Function: doError Description:
#	 generic error function for catastrphic failures
# Arguments:
#	 msg: the error message to print
#	 help: True if printHelp should be called after, False otherwise
def doError(msg, help=False):
	if help == True:
		printHelp()
	print 'ERROR: %s\n' % msg
	sys.exit()

# Function: printHelp
# Description:
#	 print out the help text
def printHelp():
	print('')
	print('%s v%s' % (sysvals.title, sysvals.version))
	print('Usage: bootgraph <options> <command>')
	print('')
	print('Description:')
	print('  This tool reads in a dmesg log of linux kernel boot and')
	print('  creates an html representation of the boot timeline up to')
	print('  the start of the init process.')
	print('Options:')
	print('  -h            Print this help text')
	print('  -v            Print the current tool version')
	print('  -ftrace file  Load a stored ftrace file (used with -dmesg)')
	print('')
	return True

# ----------------- MAIN --------------------
# exec start (skipped if script is loaded as library)
if __name__ == '__main__':
	# loop through the command line arguments
	cmd = ''
	testrun = True
	args = iter(sys.argv[1:])
	for arg in args:
		if(arg == '-h'):
			printHelp()
			sys.exit()
		elif(arg == '-v'):
			print("Version %s" % sysvals.version)
			sys.exit()
		elif(arg == '-wakesource'):
			sysvals.trace_wakeup_source = True
		elif(arg == '-wakelock'):
			sysvals.trace_wakelock = True
		elif(arg == '-cpuidle'):
			sysvals.trace_cpuidle = True
		elif(arg == '-cpufreq'):
			sysvals.trace_cpufreq = True
		elif(arg == '-ftrace'):
			try:
				val = args.next()
			except:
				doError('No ftrace file supplied', True)
			if(os.path.exists(val) == False):
				doError('%s does not exist' % val)
			testrun = False
			sysvals.ftracefile = val
		else:
			doError('Invalid argument: '+arg, True)

	# process the log data
	if sysvals.ftracefile:
		data = parseFtraceLog()
	else:
		doError('ftrace file required')

	dumpFtraceData()

	print('          Host: %s' % sysvals.hostname)
	print('     Test time: %s' % sysvals.testtime)
	print('     Boot time: %s' % data.boottime)
	print('Kernel Version: %s' % sysvals.kernel)
	print(' Measure start: %.3f' % (data.start * 1000))
	print('   Measure end: %.3f' % (data.initstart * 1000))
