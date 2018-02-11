#     __  __|                        |          #
#        |  _ \   __| __ \   _ \  _` |  _ \     #
#        | (   | |    |   |  __/ (   | (   |    #
#       _|\___/ _|    .__/ \___|\__,_|\___/     #
#         Intrusion  _|  Detection System       #

_ __|__ _ http://paypal.me/russianotter _ __|__ _

# QuadTorp Intrusion Dection System is designed #
#  to effectively map and log all LAN activity  #
#    while also verbosing and documenting       #
#   vulnerabilities within certain devices      #

_ __|__ _        **Version Info**       _ __|__ _
    |                                       |

 - 6/13/17 = v1.0   - Established Detection   -
 - 6/15/17 = v1.2   - Enhanced Preformance    -
 - 7/03/17 = v1.2.3 - New Scan Types          -
 - 1/31/18 = v1.3.3 - Enhanced User Interface -
 - 2/05/18 = v1.5.5 - Code Improvements       -
 - 2/08/18 = v1.5.6 - Scan Improvements       -
 - 2/08/18 = v1.5.7 - Major Bug Fixes         -
 - 2/10/18 = v1.6.0 - Dynamic Scanning        -
 - ?/??/?? = v?.?.? - Honeypot Added          -
 - ?/??/?? = v?.?.? - Speed Tests Added       -
 - ?/??/?? = v?.?.? - More Security Scans     -

_ __|__ _       **Licensing Info**      _ __|__ _
    |                                       |

   *THE SOFTWARE IS PROVIDED "AS IS", WITHOUT*
    *WARRANTY OFANY KIND, EXPRESS OR IMPLIED*
 *INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF*
   *MERCHANTABILITY, FITNESS FOR A PARTICULAR*
 *PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL*
 *THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR* 
 *ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER* 
  *IN AN ACTION OF CONTRACT, TORT OR OTHERWISE*
 *ARISING FROM, OUT OF OR IN CONNECTION WITH THE* 
 *SOFTWARE OR THE USE OR OTHER DEALINGS IN THE*
                   *SOFTWARE*

# Copyright (c) Savage Security Technology 2018 #
#Copyright (c) Quadtorp Intrusion Detection 2018#

_ __|__ _          _         _          _ __|__ _
_ __|__      _ __ // TORPEDO \\ __ _      __|__ _
_ __|__ _         \\ARGUMENTS//         _ __|__ _

:: **--ttl** :: *Connection timeout.*

:: **--hd** :: *Hides donation information.*

:: **-r** :: --rate :: *Minutes between scans.*

:: **-s** :: --smooth :: *Smoothly print scans.*

:: *-m* :: --maxthread :: Limits how many active
threads can be made. More threads means more CPU
usage and battery consumption! Min: 20 Max: 400

:: *-a* :: --auto-clear :: Clear terminal after x
amount of scans have been made. This will reduce
lag and memory buildup (especially for long-term
scans).

:: *-l* :: --level :: Select scanning intensity
	level while searching for devices.
- --- ----  -  ---- +[ OPT ]+ ----  -  ---- --- -
..::SECURITY: Find vulnerable devices and report
              any new devices on the network.
..::PASSIVE : Scan basic devices and log info.
..::DEFCON  : Report vulnerable devices and
              actively check for network ports.

:: *-n* :: --network-level :: Scanning Range.
- --- ----  -  ---- +[ OPT ]+ ----  -  ---- --- -
..::DYNAMIC : Scans all subnet ranges and reports
              all active subnets for future scans
..::LOCAL   : Scans all addresses on the same
              level as the host scanning.
..::MAX     : Scans all addresses.

- --- ----  -  ---- +[ TIP ]+ ----  -  ---- --- -

# 1. Try to avoid stopping the program while a
# scan is actively running. This may lead to
# large scale crashes, so instead stop the
# program when it is either printing statistics
# or when it is waiting to initialize the next scan.

# 2. To set up custom subnet scan ranges, go to
# ./networks/<net>/stat.dyn (or make stat.dyn)
# and make a Python list containing the first 3
# positions of the address followed by %s. When
# set in dynamic mode, QuadTorp will use this
# to know where to scan! If you don't know your
# active address range, run QuadTorp in max mode.
# Example of stat.dyn:
	["192.168.1.%s","192.168.2.%s","192.168.3.%s"]
 
Copyright © QuadTorp Intrusion Detection System
