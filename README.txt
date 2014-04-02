Similar implementation of .gdbinit from fG! for lldb in python

How to install it:
cp lldbinit.py /Library/Python/2.7/site-packages
in $HOME/.lldbinit add:
command script import lldbinit

Apple's default lldb comes with annoying disassembly eg:
-> 0x1d70:  push   EBP
   0x1d71:  mov    EBP, ESP
   0x1d73:  push   EDI
   0x1d74:  push   ESI
   0x1d75:  sub    ESP, 80

with lldb from lldb svn:

-> 0x1d70:  push   ebp
   0x1d71:  mov    ebp, esp
   0x1d73:  push   edi
   0x1d74:  push   esi
   0x1d75:  sub    esp, 0x50

Somewhere nicer, to compile lldb from svn we need to do:
svn co http://llvm.org/svn/llvm-project/lldb/trunk lldb
xcodebuild -configuration Release

From latest update of lldb there is change in handling IO, so to use
this script and be compatible with Apple's lldb you need to checkout
revision r200253 and you can do that by typing:
svn co -r r200253 http://llvm.org/svn/llvm-project/lldb/trunk

Commands which are implemented:
   stepo       - step over some instructions (call/movs/stos/cmps/loop)
   dd          - dump hex data at certain address (keep compatibility with .gdbinit)
   	      this shoud be db command
   ctx/context - dump registers and assembly
   lb	    - load breakpoints from file and apply them (currently only func names are applied)	 	
   u	    - dump instructions at certain address (SoftICE like u command style)
   ddword	    - dump data as dword 
   dq	    - dump data as qword
   dw	    - dump data as word
   iphone	    - connect to debugserver running on iPhone 
   
   hook-stop can be added only when target exists, before it's not possible (maybe in later versions
   of lldb it is or will be possible but...). Trick to get arround this is to create thread which will
   try to add hook-stop, and will continue doing so until it's done. This could cause some raise conditions
   as I don't know if this is thread safe, however in my testing (and using it) it worked quite well so
   I keep using it instead of adding extra command "init" or such when target is created...
   
   Currently registers dump are done for i386/x86_64/arm 

   TODO:
	Add code to highlight only changed flags (both x86/x86_64 and ARM)
