Similar implementation of .gdbinit from fG! for lldb in python

How to install it:
cp lldbinit.py /Library/Python/2.7/site-packages
in $HOME/.lldbinit add:
command script import lldbinit

Later versions of MacOS come with lldb and Python3 which is bundled with Xcode. 
Thus to install python3 version on later versions:
cp lldbinitpy3.py ~/
in $HOME/.lldbinit add:
command script import ~/lldbinitpy3.py

If you want latest lldb, to compile it from svn we need to do:
svn co http://llvm.org/svn/llvm-project/lldb/trunk lldb
xcodebuild -configuration Release

Commands which are implemented:
	stepo       - step over some instructions (call/movs/stos/cmps/loop)
	dd          - dump hex data at certain address (keep compatibility with .gdbinit)
		      this shoud be db command
	db          - same as dd for SoftICE enthusiasts	
	ctx/context - dump registers and assembly
	lb	    - load breakpoints from file and apply them (currently only func names are applied)	 
	lb_rva	    - load breakpoints from file and apply to main executable, only RVA in this case
		      and command will determine main program base and apply breaks	
	u	    - dump instructions at certain address (SoftICE like u command style)
	ddword	    - dump data as dword 
	dq	    - dump data as qword
	dw	    - dump data as word
	iphone	    - connect to debugserver running on iPhone 
	findmem	    - command to search memory 
		      [options]
		      -s searches for specified string
		      -u searches for specified unicode string
                      -b searches binary (eg. -b 4142434445 will find ABCDE anywhere in mem)
		      -d searches dword  (eg. -d 0x41414141)
                      -q searches qword  (eg. -d 0x4141414141414141)
		      -f loads patern from file if it's tooooo big to fit into any of specified
                         options
		      -c specify if you want to find N occurances (default is all)
	bt	    - broken... and removed, now thread/frame information is by default shown on every
                      hook-stop by lldb itself...

hook-stop can be added only when target exists, before it's not possible (maybe in later versions
of lldb it is or will be possible but...). Trick to get arround this is to create thread which will
try to add hook-stop, and will continue doing so until it's done. This could cause some raise conditions
as I don't know if this is thread safe, however in my testing (and using it) it worked quite well so
I keep using it instead of adding extra command "init" or such when target is created...

Currently registers dump are done for i386/x86_64/arm 

For supported ARM types for iPhone check here:
	source/Plugins/Platform/MacOSX/PlatformDarwin.cpp
	PlatformDarwin::ARMGetSupportedArchitectureAtIndex  <-- maybe wrong, but you have
								idea what they support
