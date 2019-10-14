'''
        Similar implementation of .gdbinit from fG! for lldb in python

        How to install it:
        cp lldbinit.py /Library/Python/2.7/site-packages
        in $HOME/.lldbinit add:
        command script import lldbinit

        If you want latest lldb, to compile it from svn we need to do:
        svn co http://llvm.org/svn/llvm-project/lldb/trunk lldb
        xcodebuild -configuration Release

Commands which are implemented:
        stepo       - step over some instructions (call/movs/stos/cmps/loop)
        dd          - dump hex data at certain address (keep compatibility with .gdbinit)
                      this shoud be db command
        ctx/context - dump registers and assembly
        lb          - load breakpoints from file and apply them (currently only func names are applied)  
        lb_rva      - load breakpoints from file and apply to main executable, only RVA in this case
                      and command will determine main program base and apply breaks     
        u           - dump instructions at certain address (SoftICE like u command style)
        ddword      - dump data as dword 
        dq          - dump data as qword
        dw          - dump data as word
        iphone      - connect to debugserver running on iPhone 
        findmem     - command to search memory 
                      [options]
                      -s searches for specified string
                      -u searches for specified unicode string
                      -b searches binary (eg. -b 4142434445 will find ABCDE anywhere in mem)
                      -d searches dword  (eg. -d 0x41414141)
                      -q searches qword  (eg. -d 0x4141414141414141)
                      -f loads patern from file if it's tooooo big to fit into any of specified
                         options
                      -c specify if you want to find N occurances (default is all)
        bt          - broken... and removed, now thread/frame information is by default shown on every
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

'''

if __name__ == "__main__":
        print("Run only as script from lldb... Not as standalone program");

try:
        import  lldb
except:
        pass;   
import  sys
import  re
import  os
import  _thread
import  time
import  struct
import  argparse
import  subprocess

old_eax = 0;
old_ecx = 0;
old_edx = 0;
old_ebx = 0;
old_esp = 0;
old_ebp = 0;
old_esi = 0;
old_edi = 0;
old_eip = 0;
old_eflags = 0;
old_cs  = 0;
old_ds  = 0;
old_fs  = 0;
old_gs  = 0;
old_ss  = 0;
old_es  = 0;

old_rax = 0;
old_rcx = 0;
old_rdx = 0;
old_rbx = 0;
old_rsp = 0;
old_rbp = 0;
old_rsi = 0;
old_rdi = 0;
old_r8  = 0;
old_r9  = 0;
old_r10 = 0;
old_r11 = 0;
old_r12 = 0;
old_r13 = 0;
old_r14 = 0;
old_r15 = 0;
old_rflags = 0;
old_rip = 0;

old_arm_r0      = 0;
old_arm_r1      = 0;
old_arm_r2      = 0;
old_arm_r3      = 0;
old_arm_r4      = 0;
old_arm_r5      = 0;
old_arm_r6      = 0;
old_arm_r7      = 0;
old_arm_r8      = 0;
old_arm_r9      = 0;
old_arm_r10     = 0;
old_arm_r11     = 0;
old_arm_r12     = 0;
old_arm_sp      = 0;
old_arm_lr      = 0;
old_arm_pc      = 0;
old_arm_cpsr    = 0;

BLACK = 0
RED = 1
GREEN = 2
YELLOW = 3
BLUE = 4
MAGENTA = 5
CYAN = 6
WHITE = 7

COLOR_REGNAME = GREEN
COLOR_REGVAL = WHITE
COLOR_REGVAL_MODIFIED  = RED
COLOR_SEPARATOR = BLUE
COLOR_CPUFLAGS = RED
COLOR_HIGHLIGHT_LINE = CYAN

arm_type = "thumbv7-apple-ios";

GlobalListOutput = [];

hook_stop_added = 0;

def     wait_for_hook_stop():
        while True:
                #print("Waiting...");
                res = lldb.SBCommandReturnObject();
                lldb.debugger.GetCommandInterpreter().HandleCommand("target stop-hook add -o \"HandleHookStopOnTarget\"", res);
                if res.Succeeded() == True:
                        return;
                time.sleep(0.05);

def     __lldb_init_module(debugger, internal_dict):
        ''' we can execute commands using debugger.HandleCommand which makes all outptu to default
            lldb console. With GetCommandinterpreter().HandleCommand() we can consume all output
            with SBCommandReturnObject and parse data before we send it to output (eg. modify it);
        '''
        global hook_stop_added;

        '''
                If I'm running from $HOME where .lldbinit is located, seems like lldb will load 
                .lldbinit 2 times, thus this dirty hack is here to prevent doulbe loading...
                if somebody knows better way, would be great to know :)
        '''     
        var = lldb.debugger.GetInternalVariableValue("stop-disassembly-count", lldb.debugger.GetInstanceName());
        if var.IsValid():
                var = var.GetStringAtIndex(0);
                if var == "0":
                        return; 
        res = lldb.SBCommandReturnObject();
        
        lldb.debugger.GetCommandInterpreter().HandleCommand("settings set target.x86-disassembly-flavor intel", res);
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.stepo stepo", res);                               
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.HandleHookStopOnTarget HandleHookStopOnTarget", res);   
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.dd dd", res);                                           
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.si si", res);
        #lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.r  r", res);
        #lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.r  run", res);
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.HandleHookStopOnTarget ctx", res);
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.HandleHookStopOnTarget context", res);
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.DumpInstructions u", res);
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.LoadBreakPoints lb", res);
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.LoadBreakPointsRva lbrva", res);
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.dq dq", res);
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.dd db", res);
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.ddword ddword", res);
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.dw dw", res);
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.IphoneConnect iphone", res);
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.findmem findmem", res);                       
        

        '''
                target stop-hook can be added only when target is loaded, thus I create thread
                to execute this command until it returns success... dunno if this is ok, or thread
                safe, but I hate to add extra command "init" or such to install this hook...
        '''
        _thread.start_new_thread(wait_for_hook_stop, ());
        
        #lldb.debugger.GetCommandInterpreter().HandleCommand("settings set prompt \"\033[01;31m(lldb) \033[0m\"", res);                                                                    
        lldb.debugger.GetCommandInterpreter().HandleCommand("settings set stop-disassembly-count 0", res);                                      
        return;


def     get_arch():
        return lldb.debugger.GetSelectedTarget().triple.split('-')[0];
def     get_frame():
        #return lldb.debugger.GetSelectedTarget().process.selected_thread.GetSelectedFrame(); 
        #return lldb.debugger.GetSelectedTarget().GetProcess().GetSelectedThread().GetSelectedFrame()
        #return lldb.debugger.GetTargetAtIndex(0).process.selected_thread.GetFrameAtIndex(0);
                
        #return frame for stopped thread... there should be one at least...
        ret = None;
        for t in get_process():
                if t.GetStopReason() != lldb.eStopReasonNone and t.GetStopReason() != lldb.eStopReasonInvalid:
                        ret = t.GetFrameAtIndex(0);
                        
        return ret;

def     get_process():
        return lldb.debugger.GetSelectedTarget().process; #GetTargetAtIndex(0).process;

def     evaluate(command):
        value = get_frame().EvaluateExpression(command);
        if value.IsValid() == False:
                return None;
        try:
                value = int(value.GetValue(), 10); #long(value.GetValue(), 10);
                return value;
        except:
                try:
                        value = int(value.GetValue(), 16);
                        return value;
                except:
                        
                        return None;

def     is_i386():
        arch = get_arch();
        if arch[0:1] == "i":
                return True;
        return False;

def     is_x64():
        arch = get_arch();
        if arch == "x86_64":
                return True;
        return False;

def     is_arm():
        arch = get_arch();
        if "arm" in arch:
                return True;
        return False;

def     get_pointer_size():
        poisz = evaluate("sizeof(long)");
        return poisz;

def     color_reset():
        output("\033[0m");
def     color_bold():
        output("\033[1m");
def     color_underline():
        output("\033[4m");

def     color(x):
        out_col = "";
        if x == BLACK:
                out_col = "\033[30m";
        elif x == RED:
                out_col = "\033[31m";
        elif x == GREEN:
                out_col = "\033[32m";
        elif x == YELLOW:
                out_col = "\033[33m";
        elif x == BLUE:
                out_col = "\033[34m";
        elif x == MAGENTA:
                out_col = "\033[35m";
        elif x == CYAN:
                out_col = "\033[36m";
        elif x == WHITE:
                out_col = "\033[37m";
        output(out_col);

def     output(x):
        global GlobalListOutput;
        GlobalListOutput.append(x);
        
def get_register(reg_name):
        regs = get_GPRs();
        if regs == None:
                return "0";
        for reg in regs:
                if reg_name == reg.GetName():
                        return reg.GetValue();
        return "0"; #0; 

def get_registers(kind):
    """Returns the registers given the frame and the kind of registers desired.

    Returns None if there's no such kind.
    """
    registerSet = get_frame().GetRegisters() # Return type of SBValueList.
    for value in registerSet:
        if kind.lower() in value.GetName().lower():
            return value

    return None

def     dump_eflags(eflags):
        if (eflags >> 0xB) & 1:
                output("O ");
        else:
                output("o ");
        
        if (eflags >> 0xA) & 1:
                output("D ");
        else:
                output("d ");
        
        if (eflags >> 9) & 1:
                output("I ");
        else:
                output("i ");
        
        if (eflags >> 8) & 1:
                output("T ");
        else:
                output("t ");
        
        if (eflags >> 7) & 1:
                output("S ");
        else:
                output("s ");
        
        if (eflags >> 6) & 1:
                output("Z ");
        else:
                output("z ");
        
        if (eflags >> 4) & 1:
                output("A ");
        else:
                output("a ");
        
        if (eflags >> 2) & 1:
                output("P ");
        else:
                output("p ");        

        if eflags & 1:
                output("C");
        else:
                output("c");

def     reg64():
        global old_cs;
        global old_ds;
        global old_fs;
        global old_gs;
        global old_ss;
        global old_es;
        global old_rax;
        global old_rcx;
        global old_rdx;
        global old_rbx;
        global old_rsp;
        global old_rbp;
        global old_rsi;
        global old_rdi;
        global old_r8; 
        global old_r9; 
        global old_r10;
        global old_r11;
        global old_r12;
        global old_r13;
        global old_r14;
        global old_r15;
        global old_rflags;
        global old_rip;

        rax = int(str(get_register("rax")).strip().split()[0], 16);
        rcx = int(str(get_register("rcx")).strip().split()[0], 16);
        rdx = int(str(get_register("rdx")).strip().split()[0], 16);
        rbx = int(str(get_register("rbx")).strip().split()[0], 16);
        rsp = int(str(get_register("rsp")).strip().split()[0], 16);
        rbp = int(str(get_register("rbp")).strip().split()[0], 16);
        rsi = int(str(get_register("rsi")).strip().split()[0], 16);
        rdi = int(str(get_register("rdi")).strip().split()[0], 16);
        r8  = int(str(get_register("r8")).strip().split()[0], 16);
        r9  = int(str(get_register("r9")).strip().split()[0], 16);
        r10 = int(str(get_register("r10")).strip().split()[0], 16);
        r11 = int(str(get_register("r11")).strip().split()[0], 16);
        r12 = int(str(get_register("r12")).strip().split()[0], 16);
        r13 = int(str(get_register("r13")).strip().split()[0], 16);
        r14 = int(str(get_register("r14")).strip().split()[0], 16);
        r15 = int(str(get_register("r15")).strip().split()[0], 16);
        rip = int(str(get_register("rip")).strip().split()[0], 16);
        rflags = int(str(get_register("rflags")).strip().split()[0], 16);
        cs = int(str(get_register("cs")).strip().split()[0], 16);
        gs = int(str(get_register("gs")).strip().split()[0], 16);
        fs = int(str(get_register("fs")).strip().split()[0], 16);
        
        # not needed as x64 doesn't use them...
        # ds = int(str(get_register("ds")).strip().split()[0], 16);
        # ss = int(str(get_register("ss")).strip().split()[0], 16);
        
        color(COLOR_REGNAME);
        output("  RAX: ");
        if rax == old_rax:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("0x%.016lX" % (rax));
        old_rax = rax;
        
        color(COLOR_REGNAME);
        output("  RBX: ")
        if rbx == old_rbx:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("0x%.016lX" % (rbx));
        old_rbx = rbx;
        
        color(COLOR_REGNAME);
        output("  RBP: ");
        if rbp == old_rbp:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("0x%.016lX" % (rbp));
        old_rbp = rbp;
        
        color(COLOR_REGNAME);
        output("  RSP: ");
        if rsp == old_rsp:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("0x%.016lX" % (rsp));
        old_rsp = rsp;
        
        output("  ");
        color_bold();
        color_underline();
        color(COLOR_CPUFLAGS);
        dump_eflags(rflags);
        color_reset();
        
        output("\n");
        
        
        color(COLOR_REGNAME);
        output("  RDI: ");
        if rdi == old_rdi:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("0x%.016lX" % (rdi));
        old_rdi = rdi;
        
        color(COLOR_REGNAME);
        output("  RSI: ");
        if rsi == old_rsi:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("0x%.016lX" % (rsi));
        old_rsi = rsi;
        
        color(COLOR_REGNAME);
        output("  RDX: ");
        if rdx == old_rdx:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("0x%.016lX" % (rdx));
        old_rdx = rdx;
        
        color(COLOR_REGNAME);
        output("  RCX: ");
        if rcx == old_rcx:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("0x%.016lX" % (rcx));
        old_rcx = rcx;
        
        color(COLOR_REGNAME);
        output("  RIP: ");
        if rip == old_rip:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("0x%.016lX" % (rip));
        old_rip = rip;
        output("\n");
        
        color(COLOR_REGNAME);
        output("  R8:  ");
        if r8 == old_r8:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("0x%.016lX" % (r8));
        old_r8 = r8;
        
        color(COLOR_REGNAME);
        output("  R9:  ");
        if r9 == old_r9:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("0x%.016lX" % (r9));
        old_r9 = r9;
        
        color(COLOR_REGNAME);
        output("  R10: ");
        if r10 == old_r10:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("0x%.016lX" % (r10));
        old_r10 = r10;
        
        color(COLOR_REGNAME);
        output("  R11: ");
        if r11 == old_r11:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("0x%.016lX" % (r11));
        old_r11 = r11;
        
        color(COLOR_REGNAME);
        output("  R12: ");
        if r12 == old_r12:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("0x%.016lX" % (r12));
        old_r12 = r12;
        
        output("\n");
        
        color(COLOR_REGNAME);
        output("  R13: ");
        if r13 == old_r13:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("0x%.016lX" % (r13));
        old_r13 = r13;
        
        color(COLOR_REGNAME);
        output("  R14: ");
        if r14 == old_r14:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("0x%.016lX" % (r14));
        old_r14 = r14;
        
        color(COLOR_REGNAME);
        output("  R15: ");
        if r15 == old_r15:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("0x%.016lX" % (r15));
        old_r15 = r15;
        output("\n");
        
        color(COLOR_REGNAME);
        output("  CS:  ");
        if cs == old_cs:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("%.04X" % (cs));
        old_cs = cs;
        
        color(COLOR_REGNAME);
        output("  FS: ");
        if fs == old_fs:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("%.04X" % (fs));
        old_fs = fs;
        
        color(COLOR_REGNAME);
        output("  GS: ");
        if gs == old_gs:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("%.04X" % (gs));
        old_gs = gs;
        output("\n");
        
def     reg32():
        global old_eax;
        global old_ecx;
        global old_edx;
        global old_ebx;
        global old_esp;
        global old_ebp;
        global old_esi;
        global old_edi;
        global old_eflags;
        global old_cs;
        global old_ds;
        global old_fs;
        global old_gs;
        global old_ss;
        global old_es;
        global old_eip;
        
        color(COLOR_REGNAME);
        output("  EAX: ");
        eax = int(get_register("eax"), 16);
        if eax == old_eax:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("0x%.08X" % (eax));
        old_eax = eax;
        
        color(COLOR_REGNAME);
        output("  EBX: ");
        ebx = int(get_register("ebx"), 16);
        if ebx == old_ebx:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("0x%.08X" % (ebx));
        old_ebx = ebx;
        
        color(COLOR_REGNAME);
        output("  ECX: ");
        ecx = int(get_register("ecx"), 16);
        if ecx == old_ecx:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("0x%.08X" % (ecx));
        old_ecx = ecx;

        color(COLOR_REGNAME);
        output("  EDX: ");
        edx = int(get_register("edx"), 16);
        if edx == old_edx:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("0x%.08X" % (edx));
        old_edx = edx;
        
        output("  ");
        eflags = int(get_register("eflags"), 16);
        color_bold();
        color_underline();
        color(COLOR_CPUFLAGS);
        dump_eflags(eflags);
        color_reset();
        
        output("\n");
        
        color(COLOR_REGNAME);
        output("  ESI: ");
        esi = int(get_register("esi"), 16);
        if esi == old_esi:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("0x%.08X" % (esi));
        old_esi = esi;
        
        color(COLOR_REGNAME);
        output("  EDI: ");
        edi = int(get_register("edi"), 16);
        if edi == old_edi:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("0x%.08X" % (edi));
        old_edi = edi;
        
        color(COLOR_REGNAME);
        output("  EBP: ");
        ebp = int(get_register("ebp"), 16);
        if ebp == old_ebp:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("0x%.08X" % (ebp));
        old_ebp = ebp;
        
        color(COLOR_REGNAME);
        output("  ESP: ");
        esp = int(get_register("esp"), 16);
        if esp == old_esp:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("0x%.08X" % (esp));
        old_esp = esp;
        
        color(COLOR_REGNAME);
        output("  EIP: ");
        eip = int(get_register("eip"), 16);
        if eip == old_eip:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("0x%.08X" % (eip));
        old_eip = eip;
        output("\n");
        
        color(COLOR_REGNAME);
        output("  CS:  ");
        cs = int(get_register("cs"), 16);
        if cs == old_cs:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("%.04X" % (cs));
        old_cs = cs;
        
        color(COLOR_REGNAME);
        output("  DS: ");
        ds = int(get_register("ds"), 16);
        if ds == old_ds:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("%.04X" % (ds));
        old_ds = ds;
        
        color(COLOR_REGNAME);
        output("  ES: ");
        es = int(get_register("es"), 16);
        if es == old_es:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("%.04X" % (es));
        old_es = es;
        
        color(COLOR_REGNAME);
        output("  FS: ");
        fs = int(get_register("fs"), 16);
        if fs == old_fs:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("%.04X" % (fs));
        old_fs = fs;
        
        color(COLOR_REGNAME);
        output("  GS: ");
        gs = int(get_register("gs"), 16);
        if gs == old_gs:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("%.04X" % (gs));
        old_gs = gs;
        
        color(COLOR_REGNAME);
        output("  SS: ");
        ss = int(get_register("ss"), 16);
        if ss == old_ss:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("%.04X" % (ss));
        old_ss = ss;
        output("\n");
        
def dump_cpsr(cpsr):
        if (cpsr >> 31) & 1:
                output("N ");
        else:
                output("n ");

        if (cpsr >> 30) & 1:
                output("Z ");
        else:
                output("z ");

        if (cpsr >> 29) & 1:
                output("C ");
        else:
                output("c ");
        
        if (cpsr >> 28) & 1:
                output("V ");
        else:
                output("v ");
        
        if (cpsr >> 27) & 1:
                output("Q ");
        else:
                output("q ");
        
        if (cpsr >> 24) & 1:
                output("J ");
        else:
                output("j ");
        
        if (cpsr >> 9) & 1:
                output("E ");
        else:
                output("e ");
        if (cpsr >> 8) & 1:
                output("A ");
        else:
                output("a ");
        if (cpsr >> 7) & 1:
                output("I ");
        else:
                output("i ");
        if (cpsr >> 6) & 1:
                output("F ");
        else:
                output("f ");
        if (cpsr >> 5) & 1:
                output("T");
        else:
                output("t");
                
def regarm():
        global  old_arm_r0;      
        global  old_arm_r1;      
        global  old_arm_r2;      
        global  old_arm_r3;      
        global  old_arm_r4;      
        global  old_arm_r5;      
        global  old_arm_r6;      
        global  old_arm_r7;      
        global  old_arm_r8;      
        global  old_arm_r9;      
        global  old_arm_r10;     
        global  old_arm_r11;     
        global  old_arm_r12;     
        global  old_arm_sp;      
        global  old_arm_lr;      
        global  old_arm_pc;      
        global  old_arm_cpsr;    

        color(COLOR_REGNAME);
        output("  R0:  ");
        r0 = int(get_register("r0"), 16);
        if r0 == old_arm_r0:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("0x%.08X" % (r0));
        old_arm_r0 = r0;

        color(COLOR_REGNAME);
        output("  R1:  ");
        r1 = int(get_register("r1"), 16);
        if r1 == old_arm_r1:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("0x%.08X" % (r1));
        old_arm_r1 = r1;

        color(COLOR_REGNAME);
        output("  R2:  ");
        r2 = int(get_register("r2"), 16);
        if r2 == old_arm_r2:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("0x%.08X" % (r2));
        old_arm_r2 = r2;

        color(COLOR_REGNAME);
        output("  R3:  ");
        r3 = int(get_register("r3"), 16);
        if r3 == old_arm_r3:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("0x%.08X" % (r3));
        old_arm_r3 = r3;
        
        output(" ");
        color_bold();
        color_underline();
        color(COLOR_CPUFLAGS);
        cpsr = int(get_register("cpsr"), 16);
        dump_cpsr(cpsr);
        color_reset();

        output("\n");
        

        color(COLOR_REGNAME);
        output("  R4:  ");
        r4 = int(get_register("r4"), 16);
        if r4 == old_arm_r4:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("0x%.08X" % (r4));
        old_arm_r4 = r4;

        color(COLOR_REGNAME);
        output("  R5:  ");
        r5 = int(get_register("r5"), 16);
        if r5 == old_arm_r5:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("0x%.08X" % (r5));
        old_arm_r5 = r5;

        color(COLOR_REGNAME);
        output("  R6:  ");
        r6 = int(get_register("r6"), 16);
        if r6 == old_arm_r6:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("0x%.08X" % (r6));
        old_arm_r6 = r6;

        color(COLOR_REGNAME);
        output("  R7:  ");
        r7 = int(get_register("r7"), 16);
        if r7 == old_arm_r7:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("0x%.08X" % (r7));
        old_arm_r7 = r7;

        output("\n");

        color(COLOR_REGNAME);
        output("  R8:  ");
        r8 = int(get_register("r8"), 16);
        if r8 == old_arm_r8:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("0x%.08X" % (r8));
        old_arm_r8 = r8;

        color(COLOR_REGNAME);
        output("  R9:  ");
        r9 = int(get_register("r9"), 16);
        if r9 == old_arm_r9:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("0x%.08X" % (r9));
        old_arm_r9 = r9;

        color(COLOR_REGNAME);
        output("  R10: ");
        r10 = int(get_register("r10"), 16);
        if r10 == old_arm_r10:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("0x%.08X" % (r10));
        old_arm_r10 = r10;

        color(COLOR_REGNAME);
        output("  R11: ");
        r11 = int(get_register("r11"), 16);
        if r11 == old_arm_r11:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("0x%.08X" % (r11));
        old_arm_r11 = r11;
        
        output("\n");

        color(COLOR_REGNAME);
        output("  R12: ");
        r12 = int(get_register("r12"), 16);
        if r12 == old_arm_r12:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("0x%.08X" % (r12));
        old_arm_r12 = r12;

        color(COLOR_REGNAME);
        output("  SP:  ");
        sp = int(get_register("sp"), 16);
        if sp == old_arm_sp:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("0x%.08X" % (sp));
        old_arm_sp = sp;

        color(COLOR_REGNAME);
        output("  LR:  ");
        lr = int(get_register("lr"), 16);
        if lr == old_arm_lr:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("0x%.08X" % (lr));
        old_arm_lr = lr;

        color(COLOR_REGNAME);
        output("  PC:  ");
        pc = int(get_register("pc"), 16);
        if pc == old_arm_pc:
                color(COLOR_REGVAL);
        else:
                color(COLOR_REGVAL_MODIFIED);
        output("0x%.08X" % (pc));
        old_arm_pc = pc;
        output("\n");

def print_registers():
        arch = get_arch();
        if is_i386(): 
                reg32();
        elif is_x64():
                reg64();
        elif is_arm():
                regarm();
def get_GPRs():
    """Returns the general purpose registers of the frame as an SBValue.

    The returned SBValue object is iterable.  An example:
        ...
        from lldbutil import get_GPRs
        regs = get_GPRs(frame)
        for reg in regs:
            print "%s => %s" % (reg.GetName(), reg.GetValue())
        ...
    """
    return get_registers("general purpose")

def     HandleHookStopOnTarget(debugger, command, result, dict):
        # Don't display anything if we're inside Xcode
        if os.getenv('PATH').startswith('/Applications/Xcode.app'):
                return
        
        global GlobalListOutput;
        global arm_type;
        
        debugger.SetAsync(True);        
        frame = get_frame();
        if not frame: return;
                
        thread= frame.GetThread();
        while True:     
                frame = get_frame();
                thread = frame.GetThread();
                #print("----------------------------------");
                #for t in get_process():
                #       print("Thread stop reason : %d" % (t.GetStopReason()));
        
                if thread.GetStopReason() == lldb.eStopReasonNone or thread.GetStopReason() == lldb.eStopReasonInvalid: 
                        time.sleep(0.001);
                else:
                        break;
        
        GlobalListOutput = [];
        
        arch = get_arch();
        if not is_i386() and not is_x64() and not is_arm():
                #this is for ARM probably in the future... when I will need it...
                print("Unknown architecture : " + arch);
                return;
        
        output("\n");
        color(COLOR_SEPARATOR);
        if is_i386() or is_arm():
                output("---------------------------------------------------------------------------------");
        elif is_x64():
                output("-----------------------------------------------------------------------------------------------------------------------");
                
        color_bold();
        output("[regs]\n");
        color_reset();
        print_registers();
        
        color(COLOR_SEPARATOR);
        if is_i386() or is_arm():
                output("---------------------------------------------------------------------------------");
        elif is_x64():
                output("-----------------------------------------------------------------------------------------------------------------------");
        color_bold();
        output("[code]\n");
        color_reset();
        
        if is_i386():
                pc = get_register("eip");
        elif is_x64():
                pc = get_register("rip");
        elif is_arm():
                pc = get_register("pc");        
        
        res = lldb.SBCommandReturnObject();
        if is_arm():
                cpsr = int(get_register("cpsr"), 16); 
                t = (cpsr >> 5) & 1;
                if t:
                        #it's thumb
                        arm_type = "thumbv7-apple-ios"; 
                else:
                        arm_type = "armv7-apple-ios";
                lldb.debugger.GetCommandInterpreter().HandleCommand("disassemble -A " + arm_type + " --start-address=" + pc + " --count=8", res)
        else:
                lldb.debugger.GetCommandInterpreter().HandleCommand("disassemble --start-address=" + pc + " --count=8", res);
        data = res.GetOutput(); 
        #split lines... and mark currently executed code...
        data = data.split("\n");
        #detemine what to hl, as sometimes lldb won't put => into stoped thread... well...
        #need to check if first sym is => or '  ' which means this is name without symol
        #symbols are stored 1st so here we go...
        line_to_hl = 0;
        #if data[0][0:2] == "->":
        #       line_to_hl = 0;
        #if data[0][0:2] != '  ':
        #       line_to_hl = 1;
        
        #now we look when pc is held in disassembly and we color only that line 
        pc_text = int(str(pc).strip().split()[0], 16);
        pc_text = hex(pc_text);
        #print(pc_text);
        for idx,x in enumerate(data):
                if pc_text in x:
                        line_to_hl = idx;
                        break;
        for idx,x in enumerate(data):
                if line_to_hl == idx: #x[0:2] == "->" and idx < 3:
                        color(COLOR_HIGHLIGHT_LINE);
                        color_bold();
                        output(x);
                        color_reset();
                else:
                        output(x);
                output("\n");
        #output(res.GetOutput());
        color(COLOR_SEPARATOR);
        if get_pointer_size() == 4: #is_i386() or is_arm():
                output("---------------------------------------------------------------------------------------");
        elif get_pointer_size() == 8: #is_x64():
                output("-----------------------------------------------------------------------------------------------------------------------------");
        color_reset();
        output("\n");
        
        output("Stop reason : " + str(thread.GetStopDescription(100))); #str(lldb.debugger.GetSelectedTarget().process.selected_thread.GetStopDescription(100)));
        output("\r");   
        data = "".join(GlobalListOutput);
        
        result.PutCString(data);
        result.SetStatus(lldb.eReturnStatusSuccessFinishResult);  
        return 0;
        
def     LoadBreakPointsRva(debugger, command, result, dict):
        global  GlobalOutputList;
        GlobalOutputList = [];
        '''
        frame = get_frame();
        target = lldb.debugger.GetSelectedTarget();

        nummods = target.GetNumModules();
        #for x in range (0, nummods):
        #       mod = target.GetModuleAtIndex(x);
        #       #print(dir(mod));
        #       print(target.GetModuleAtIndex(x));              
        #       for sec in mod.section_iter():
        #               addr = sec.GetLoadAddress(target);
        #               name = sec.GetName();
        #               print(hex(addr));

        #1st module is executable
        mod = target.GetModuleAtIndex(0);
        sec = mod.GetSectionAtIndex(0);
        loadaddr = sec.GetLoadAddress(target);
        if loadaddr == lldb.LLDB_INVALID_ADDRESS:
                sec = mod.GetSectionAtIndex(1);
                loadaddr = sec.GetLoadAddress(target);
        print(hex(loadaddr));
        '''

        target = lldb.debugger.GetSelectedTarget();
        mod = target.GetModuleAtIndex(0);
        sec = mod.GetSectionAtIndex(0);
        loadaddr = sec.GetLoadAddress(target);
        if loadaddr == lldb.LLDB_INVALID_ADDRESS:
                sec = mod.GetSectionAtIndex(1);
                loadaddr = sec.GetLoadAddress(target);
        try:
                f = open(command, "r");
        except:
                output("Failed to load file : " + command);
                result.PutCString("".join(GlobalListOutput));
                return;
        while True:
                line = f.readline();
                if not line: break;
                line = line.rstrip();
                if not line: break;
                debugger.HandleCommand("breakpoint set -a " + hex(loadaddr + long(line, 16)));
        f.close();      


def     LoadBreakPoints(debugger, command, result, dict):
        global GlobalOutputList;
        GlobalOutputList = [];

        try:
                f = open(command, "r");
        except:
                output("Failed to load file : " + command);
                result.PutCString("".join(GlobalListOutput));
                return;
        while True:
                line = f.readline();
                if not line:
                        break;
                line = line.rstrip();
                if not line:
                        break;
                debugger.HandleCommand("breakpoint set --name " + line);
        f.close();              

'''
        si, c, r instruction override deault ones to consume their output.
        For example:
                si is thread step-in which by default dumps thread and frame info
                after every step. Consuming output of this instruction allows us
                to nicely display informations in our hook-stop
        Same goes for c and r (continue and run)
'''
def     si(debugger, command, result, dict):
        debugger.SetAsync(True);
        res = lldb.SBCommandReturnObject();
        lldb.debugger.GetSelectedTarget().process.selected_thread.StepInstruction(False);
        result.SetStatus(lldb.eReturnStatusSuccessFinishNoResult);

def     c(debugger, command, result, dict):
        debugger.SetAsync(True);
        res = lldb.SBCommandReturnObject();
        lldb.debugger.GetSelectedTarget().GetProcess().Continue();
        result.SetStatus(lldb.eReturnStatusSuccessFinishNoResult );

def     r(debugger, command, result, dict):
        debugger.SetAsync(True);
        res = lldb.SBCommandReturnObject();
        if command[0:3] == "-c/":
                index = command.find("--");
                command = command[index+2:];
        #strip -c/bin/sh or -c/bin/bash -- when arguments are passed to cmd line...
        lldb.debugger.GetCommandInterpreter().HandleCommand("process launch -- " + command, res);
        result.SetStatus(lldb.eReturnStatusSuccessFinishNoResult );

'''
        Handles 'u' command which displays instructions. Also handles output of
        'disassemble' command ...
'''
def     DumpInstructions(debugger, command, result, dict):
        global GlobalListOutput;
        global arm_type;
        GlobalListOutput = [];
        
        if is_arm():
                cpsr = int(get_register("cpsr"), 16);
                t = (cpsr >> 5) & 1;
                if t:
                        #it's thumb
                        arm_type = "thumbv7-apple-ios";
                else:
                        arm_type = "armv7-apple-ios";
        res = lldb.SBCommandReturnObject();
        cmd = command.split();
        if len(cmd) == 0 or len(cmd) > 2:
                if is_arm():
                        lldb.debugger.GetCommandInterpreter().HandleCommand("disassemble -A " +arm_type + " --start-address=$pc --count=8", res);
                else:
                        lldb.debugger.GetCommandInterpreter().HandleCommand("disassemble --start-address=$pc --count=8", res);
        elif len(cmd) == 1:
                if is_arm():
                        lldb.debugger.GetCommandInterpreter().HandleCommand("disassemble -A "+arm_type+" --start-address=" + cmd[0] + " --count=8", res);
                else:
                        lldb.debugger.GetCommandInterpreter().HandleCommand("disassemble --start-address=" + cmd[0] + " --count=8", res);
        else:
                if is_arm():
                        lldb.debugger.GetCommandInterpreter().HandleCommand("disassemble -A "+arm_type+" --start-address=" + cmd[0] + " --count="+cmd[1], res);
                        lldb.debugger.GetCommandInterpreter().HandleCommand("disassemble --start-address=" + cmd[0] + " --count="+cmd[1], res);
        
        if res.Succeeded() == True:
                output(res.GetOutput());
        else:
                output("Error getting instructions for : " + command);
        
        result.PutCString("".join(GlobalListOutput));
        result.SetStatus(lldb.eReturnStatusSuccessFinishResult);

'''
        Implements stepover instruction. Unfortunatelly here is no internal breakpoint exposed to Python
        thus all breaks have to be visible. Internal breakpoints are breakpoints which are < 0 (eg. -1 etc...)
        and their existance is visible from :
        lldb/sources/Target/Target.cpp

        BreakpointSP
        Target::CreateBreakpoint (const FileSpecList *containingModules,
                                  const FileSpec &file,
                                  uint32_t line_no,
                                  LazyBool check_inlines,
                                  LazyBool skip_prologue,
                                  bool internal,
                                  bool hardware)
        
'''

bplist = [];

def     stepo(debugger, command, result, dict):
        global GlobalListOutput; 
        global arm_type;
        GlobalListOutput = [];
        debugger.SetAsync(True);
        arch = get_arch();
        
        result.SetStatus(lldb.eReturnStatusSuccessFinishNoResult);
        
        err = lldb.SBError();
        target = lldb.debugger.GetSelectedTarget();
        
        if is_arm():
                cpsr = int(get_register("cpsr"), 16);
                t = (cpsr >> 5) & 1;
                if t:
                        #it's thumb
                        arm_type = "thumbv7-apple-ios";
                else:
                        arm_type = "armv7-apple-ios";

        res = lldb.SBCommandReturnObject();
        #if is_arm():
        #       lldb.debugger.GetCommandInterpreter().HandleCommand("disassemble -A " +arm_type + " --raw --start-address=$pc --count=2", res);
        #else:
        #       lldb.debugger.GetCommandInterpreter().HandleCommand("disassemble --raw --start-address=$pc --count=2", res);    
        
        lldb.debugger.GetCommandInterpreter().HandleCommand("x/2i $pc", res);
        if res.Succeeded() != True:
                output("[X] Error in stepo... can't disassemble at pc");
                return;

        #use regex to locate hex addrress which is between 8-16
        #as lldb changes disassembly very often... sometimes is has ->
        #sometimes doesn't, and instead of always looking for different
        #pattern, just use regex... Matching hex is dropped to 4 digits
        #because of x32 where it prints 4 digits...     
        stuff = res.GetOutput();
        stuff = stuff.splitlines(True);
        newlst = [];
        for x in stuff:
                if x == "\n": continue;
                newlst.append(x);
        stuff = newlst;

        p = re.compile("0x[\da-fA-F]{1,16}");
        current_pc = p.search(stuff[0]).group(0);
        next_pc    = p.search(stuff[1]).group(0);
        current_pc = long(current_pc, 16);
        next_pc    = long(next_pc, 16);

        pc_inst = stuff[0].split(";")[0];
        if is_arm():
                if "blx" in pc_inst or "bl " in pc_inst:
                        breakpoint = target.BreakpointCreateByAddress(next_pc);
                        breakpoint.SetThreadID(get_frame().GetThread().GetThreadID());
                        breakpoint.SetOneShot(True);
                        breakpoint.SetThreadID(get_frame().GetThread().GetThreadID());
                        target.GetProcess().Continue();
                        #debugger.HandleCommand("c");
                        #debugger.HandleCommand("thread step-inst-over");
                        return;
                else:
                        lldb.debugger.GetSelectedTarget().process.selected_thread.StepInstruction(False);
                        #debugger.HandleCommand("si");
                        return;
        if "call" in pc_inst or "movs" in pc_inst or "stos" in pc_inst or "loop" in pc_inst or "cmps" in pc_inst:
                breakpoint = target.BreakpointCreateByAddress(next_pc);
                breakpoint.SetOneShot(True);
                breakpoint.SetThreadID(get_frame().GetThread().GetThreadID());
                target.GetProcess().Continue();
        else:
                lldb.debugger.GetSelectedTarget().process.selected_thread.StepInstruction(False);

def hexdump(addr, chars, sep, width ):
        l = [];
        while chars:
                line = chars[:width]
                chars = chars[width:]
                line = line.ljust( width, '\000' )
                arch = get_arch();
                if get_pointer_size() == 4: #is_i386() or is_arm():
                        szaddr = "0x%.08X" % addr;
                else: # is_x64():
                        szaddr = "0x%.016lX" % addr;
                l.append("\033[1m%s :\033[0m %s%s \033[1m%s\033[0m" % (szaddr, sep.join( "%02X" % ord(c) for c in line ), sep, quotechars( line )));
                addr += 0x10;
        return "\n".join(l);

def quotechars( chars ):
        #return ''.join( ['.', c][c.isalnum()] for c in chars )
        data = "";
        for x in chars:
                if isinstance(chars, bytes):
                        x = chr(x);
                if ord(x) >= 0x20 and ord(x) <= 126:
                        data += x;
                else:           
                        data += ".";
        return data;

'''
        Output nice hexdump... Should be db (in the future) so we can give dw/dd/dq
        outputs as it's done with any normal debugger...
'''                    
def     dd(debugger, command, result, dict):
        global GlobalListOutput;
        
        GlobalListOutput = [];
        
        arch = get_arch();
        value = get_frame().EvaluateExpression(command);
        if value.IsValid() == False:
                output("Error evaluating expression : " + command);
                result.PutCString("".join(GlobalListOutput));
                return;
        try:        
                value = int(value.GetValue(), 10);
        except:
                output("Error evaluating expression : " + command);
                result.PutCString("".join(GlobalListOutput));
                return;
        
        err = lldb.SBError();
        target = lldb.debugger.GetSelectedTarget();
        size = 0x100; 
        while size != 0:
                membuff = target.GetProcess().ReadMemory(value, size, err);
                if err.Success() == False and size == 0:
                        output(str(err));
                        result.PutCString("".join(GlobalListOutput));
                        return;
                if err.Success() == True:
                        break;
                size = size - 1;
        membuff = membuff + b"\x00" * (0x100-size); 
        color(BLUE);
        if get_pointer_size() == 4: #is_i386() or is_arm():
                output("[0x0000:0x%.08X]" % value);
                output("------------------------------------------------------");
        else: #is_x64():
                output("[0x0000:0x%.016lX]" % value);
                output("------------------------------------------------------");
        color_bold();
        output("[data]")
        color_reset();
        output("\n");        
        #output(hexdump(value, membuff, " ", 16));
        index = 0;
        while index < 0x100:
                data = struct.unpack("B"*16, membuff[index:index+0x10]);
                if get_pointer_size() == 4: #is_i386() or is_arm():
                        szaddr = "0x%.08X" % value;
                else: #is_x64():
                        szaddr = "0x%.016lX" % value;
                fmtnice = "%.02X %.02X %.02X %.02X %.02X %.02X %.02X %.02X"
                fmtnice = fmtnice + " - " + fmtnice;
                output("\033[1m%s :\033[0m %.02X %.02X %.02X %.02X %.02X %.02X %.02X %.02X - %.02X %.02X %.02X %.02X %.02X %.02X %.02X %.02X \033[1m%s\033[0m" % 
                        (szaddr, 
                        data[0], 
                        data[1], 
                        data[2], 
                        data[3], 
                        data[4], 
                        data[5], 
                        data[6], 
                        data[7], 
                        data[8], 
                        data[9], 
                        data[10], 
                        data[11], 
                        data[12], 
                        data[13], 
                        data[14], 
                        data[15], 
                        quotechars(membuff[index:index+0x10])));
                if index + 0x10 != 0x100:
                        output("\n");
                index += 0x10;
                value += 0x10;
        color_reset();
        #last element of the list has all data output...
        #so we remove last \n
        result.PutCString("".join(GlobalListOutput));
        result.SetStatus(lldb.eReturnStatusSuccessFinishResult);

def     dq(debugger, command, result, dict):
        global GlobalListOutput;

        GlobalListOutput = [];

        arch = get_arch();
        value = get_frame().EvaluateExpression(command);
        if value.IsValid() == False:
                output("Error evaluating expression : " + command);
                result.PutCString("".join(GlobalListOutput));
                return;
        try:
                value = int(value.GetValue(), 10);
        except:
                output("Error evaluating expression : " + command);
                result.PutCString("".join(GlobalListOutput));
                return;

        err = lldb.SBError();
        target = lldb.debugger.GetSelectedTarget();
        size = 0x100;
        while size != 0:
                membuff = target.GetProcess().ReadMemory(value, size, err);
                if err.Success() == False and size == 0:
                        output(str(err));
                        result.PutCString("".join(GlobalListOutput));
                        return;
                if err.Success() == True:
                        break;
                size = size - 8;
        membuff = membuff + b"\x00" * (0x100-size);
        if err.Success() == False:
                output(str(err));
                result.PutCString("".join(GlobalListOutput));
                return;

        color(BLUE);
        if get_pointer_size() == 4: #is_i386() or is_arm():
                output("[0x0000:0x%.08X]" % value);
                output("-------------------------------------------------------");
        else: #is_x64():
                output("[0x0000:0x%.016lX]" % value);
                output("-------------------------------------------------------");
        color_bold();
        output("[data]")
        color_reset();
        output("\n");   
        index = 0;
        while index < 0x100:
                (mem0, mem1, mem2, mem3) = struct.unpack("QQQQ", membuff[index:index+0x20]);
                if get_pointer_size() == 4: #is_i386() or is_arm():
                        szaddr = "0x%.08X" % value;
                else: #is_x64():
                        szaddr = "0x%.016lX" % value;
                output("\033[1m%s :\033[0m %.016lX %.016lX %.016lX %.016lX" % (szaddr, mem0, mem1, mem2, mem3));
                if index + 0x20 != 0x100:
                        output("\n");
                index += 0x20;
                value += 0x20;
        color_reset();
        result.PutCString("".join(GlobalListOutput));
        result.SetStatus(lldb.eReturnStatusSuccessFinishResult);

def     ddword(debugger, command, result, dict):
        global GlobalListOutput;

        GlobalListOutput = [];

        arch = get_arch();
        value = get_frame().EvaluateExpression(command);
        if value.IsValid() == False:
                output("Error evaluating expression : " + command);
                result.PutCString("".join(GlobalListOutput));
                return;
        try:
                value = int(value.GetValue(), 10);
        except:
                output("Error evaluating expression : " + command);
                result.PutCString("".join(GlobalListOutput));
                return;

        err = lldb.SBError();
        target = lldb.debugger.GetSelectedTarget();
        size = 0x100;
        while size != 0:        
                membuff = target.GetProcess().ReadMemory(value, size, err);
                if err.Success() == False and size == 0:
                        output(str(err));
                        result.PutCString("".join(GlobalListOutput));
                        return;
                if err.Success() == True:
                        break;
                size = size - 4;
        membuff = membuff + b"\x00" * (0x100-size);
        color(BLUE);
        if get_pointer_size() == 4: #is_i386() or is_arm():
                output("[0x0000:0x%.08X]" % value);
                output("----------------------------------------");
        else: #is_x64():
                output("[0x0000:0x%.016lX]" % value);
                output("----------------------------------------");
        color_bold();
        output("[data]")
        color_reset();
        output("\n");
        index = 0;
        while index < 0x100:
                (mem0, mem1, mem2, mem3) = struct.unpack("IIII", membuff[index:index+0x10]);
                if get_pointer_size() == 4: #is_i386() or is_arm():
                        szaddr = "0x%.08X" % value;
                else:  #is_x64():
                        szaddr = "0x%.016lX" % value;
                output("\033[1m%s :\033[0m %.08X %.08X %.08X %.08X \033[1m%s\033[0m" % (szaddr, 
                                                                                        mem0, 
                                                                                        mem1, 
                                                                                        mem2, 
                                                                                        mem3, 
                                                                                        quotechars(membuff[index:index+0x10])));
                if index + 0x10 != 0x100:
                        output("\n");
                index += 0x10;
                value += 0x10;
        color_reset();
        result.PutCString("".join(GlobalListOutput));   
        result.SetStatus(lldb.eReturnStatusSuccessFinishResult);

def     dw(debugger, command, result, dict):
        global GlobalListOutput;

        GlobalListOutput = [];

        arch = get_arch();
        value = get_frame().EvaluateExpression(command);
        if value.IsValid() == False:
                output("Error evaluating expression : " + command);
                result.PutCString("".join(GlobalListOutput));
                return;
        try:
                value = int(value.GetValue(), 10);
        except:
                output("Error evaluating expression : " + command);
                result.PutCString("".join(GlobalListOutput));
                return;

        err = lldb.SBError();
        target = lldb.debugger.GetSelectedTarget();
        size = 0x100;
        while size != 0:
                membuff = target.GetProcess().ReadMemory(value, size, err);
                if err.Success() == False and size == 0:
                        output(str(err));
                        result.PutCString("".join(GlobalListOutput));
                        return;
                if err.Success() == True:
                        break;
                size = size - 2;
        membuff = membuff + b"\x00" * (0x100-size);

        color(BLUE);
        if get_pointer_size() == 4: #is_i386() or is_arm():
                output("[0x0000:0x%.08X]" % value);
                output("--------------------------------------------");
        else: #is_x64():
                output("[0x0000:0x%.016lX]" % value);
                output("--------------------------------------------");
        color_bold();
        output("[data]")
        color_reset();
        output("\n");
        index = 0;
        while index < 0x100:
                data = struct.unpack("HHHHHHHH", membuff[index:index+0x10]);
                if get_pointer_size() == 4: #is_i386() or is_arm():
                        szaddr = "0x%.08X" % value;
                else: #is_x64():
                        szaddr = "0x%.016lX" % value;
                output("\033[1m%s :\033[0m %.04X %.04X %.04X %.04X %.04X %.04X %.04X %.04X \033[1m%s\033[0m" % (szaddr, 
                        data[0],
                        data[1],
                        data[2],
                        data[3],
                        data[4],
                        data[5],
                        data[6],
                        data[7],
                        quotechars(membuff[index:index+0x10])));
                if index + 0x10 != 0x100:
                        output("\n");
                index += 0x10;
                value += 0x10;
        color_reset();
        result.PutCString("".join(GlobalListOutput));
        result.SetStatus(lldb.eReturnStatusSuccessFinishResult);

def IphoneConnect(debugger, command, result, dict):     
        global GlobalListOutput;
        GlobalListOutput = [];
                
        if len(command) == 0 or ":" not in command:
                output("Connect to remote iPhone debug server");
                output("\n");
                output("iphone <ipaddress:port>");
                output("\n");
                output("iphone 192.168.0.2:5555");
                result.PutCString("".join(GlobalListOutput));
                result.SetStatus(lldb.eReturnStatusSuccessFinishResult);
                return;

        res = lldb.SBCommandReturnObject();
        lldb.debugger.GetCommandInterpreter().HandleCommand("platform select remote-ios", res);
        if res.Succeeded() == True:
                output(res.GetOutput());
        else:
                output("Error running platform select remote-ios");
                result.PutCString("".join(GlobalListOutput));
                result.SetStatus(lldb.eReturnStatusSuccessFinishResult);
                return;
        lldb.debugger.GetCommandInterpreter().HandleCommand("process connect connect://" + command, res);
        if res.Succeeded() == True:
                output("Connected to iphone at : " + command);
        else:
                output(res.GetOutput());
        result.PutCString("".join(GlobalListOutput));
        result.SetStatus(lldb.eReturnStatusSuccessFinishResult);

def findmem(debugger, command, result, dict):
        global GlobalListOutput;
        GlobalListOutput = [];

        arg = str(command);     
        parser = argparse.ArgumentParser(prog="lldb");
        parser.add_argument("-s", "--string",  help="Search string");
        parser.add_argument("-u", "--unicode", help="Search unicode string");
        parser.add_argument("-b", "--binary",  help="Serach binary string");
        parser.add_argument("-d", "--dword",   help="Find dword (native packing)");
        parser.add_argument("-q", "--qword",   help="Find qword (native packing)");
        parser.add_argument("-f", "--file" ,   help="Load find pattern from file");
        parser.add_argument("-c", "--count",   help="How many occurances to find, default is all");

        parser = parser.parse_args(arg.split());
        
        if parser.string != None:
                search_string = parser.string.encode(); #parser.string;
        elif parser.unicode != None:
                search_string  = parser.unicode.encode("utf-16-le"); #unicode(parser.unicode);
        elif parser.binary != None:
                search_string = bytes.fromhex(parser.binary); #parser.binary.decode("hex");
        elif parser.dword != None:
                dword = evaluate(parser.dword);
                if dword == None:
                        print("Error evaluating : " + parser.dword);
                        return;
                search_string = struct.pack("I", dword & 0xffffffff);
        elif parser.qword != None:
                qword = evaluate(parser.qword);
                if qword == None:
                        print("Error evaluating : " + parser.qword);
                        return;
                search_string = struct.pack("Q", qword & 0xffffffffffffffff);
        elif parser.file != None:
                f = 0;
                try:
                        f = open(parser.file, "rb");
                except:
                        print("Failed to open file : " + parser.file);
                        return;
                search_string = f.read();
                f.close();
        else:
                print("Wrong option... use findmem --help");
                return;
        
        count = -1;
        if parser.count != None:
                count = evaluate(parser.count);
                if count == None:
                        print("Error evaluating count : " + parser.count);
                        return;
        
        process = lldb.debugger.GetSelectedTarget().GetProcess();
        pid = process.GetProcessID();
        output_data = subprocess.check_output(["/usr/bin/vmmap", "%d" % pid])
        if isinstance(output_data, bytes):
                output_data = output_data.decode();
        lines = output_data.split("\n");
        #print(lines);
        #this relies on output from /usr/bin/vmmap so code is dependant on that 
        #only reason why it's used is for better description of regions, which is
        #nice to have. If they change vmmap in the future, I'll use my version 
        #and that output is much easier to parse...
        newlines = [];
        for x in lines:
                p = re.compile("([\S\s]+)\s([\da-fA-F]{16}-[\da-fA-F]{16}|[\da-fA-F]{8}-[\da-fA-F]{8})");
                m = p.search(x);
                if not m: continue;
                tmp = [];
                mem_name  = m.group(1);
                mem_range = m.group(2);
                mem_start = int(mem_range.split("-")[0], 16);#    long(mem_range.split("-")[0], 16);  #0x000000-0x000000
                mem_end   = int(mem_range.split("-")[1], 16);#    long(mem_range.split("-")[1], 16);
                tmp.append(mem_name);
                tmp.append(mem_start);          
                tmp.append(mem_end);
                newlines.append(tmp);
        
        lines = sorted(newlines, key=lambda sortnewlines: sortnewlines[1]);
        #move line extraction a bit up, thus we can latter sort it, as vmmap gives
        #readable pages only, and then writable pages, so it looks ugly a bit :)
        newlines = [];
        for x in lines:
                mem_name = x[0];
                mem_start= x[1];
                mem_end  = x[2];
                mem_size = mem_end - mem_start;
        
                err = lldb.SBError();
                    
                membuff = process.ReadMemory(mem_start, mem_size, err);
                if err.Success() == False:
                        #output(str(err));
                        #result.PutCString("".join(GlobalListOutput));
                        continue;
                off = 0;
                base_displayed = 0;

                while True:
                        if count == 0: return;
                        idx = membuff.find(search_string);
                        if idx == -1: break;
                        if count != -1:
                                count = count - 1;              
                        off += idx;
        
                        GlobalListOutput = [];  
                        
                        if get_pointer_size() == 4:
                                ptrformat = "%.08X";
                        else:
                                ptrformat = "%.016lX";

                        color_reset();  
                        output("Found at : ");
                        color(GREEN);
                        output(ptrformat % (mem_start + off));
                        color_reset();
                        if base_displayed == 0:
                                output(" base : ");
                                color(YELLOW);
                                output(ptrformat % mem_start);
                                color_reset();
                                base_displayed = 1;
                        else:
                                output("        ");
                                if get_pointer_size() == 4:
                                        output(" " * 8);
                                else:
                                        output(" " * 16);
                        #well if somebody allocated 4GB of course offset will be to small to fit here
                        #but who cares...
                        output(" off : %.08X %s" % (off, mem_name));
                        print("".join(GlobalListOutput));
                        membuff = membuff[idx+len(search_string):];
                        off += len(search_string);
        return;
