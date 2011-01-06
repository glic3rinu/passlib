"""bps.develop - useful functions for debugging and developing code
"""
#=========================================================
#imports
#=========================================================
#core
import inspect
import time
import os, sys
import re
import code as code_mod
#pkg
from bps.fs import filepath
#local
__all__ = [
    #console
    "dbgcon",

    #utils
    "trap",
    "timer",

    #ide
    "global_replace",
    "purge_bytecode",

    #tracing
    "log_imports",
]

#=========================================================
#debugging console
#=========================================================
def _default_shell(local_ns, global_ns):
    "helper for dbgcon which uses default python interactive shell"
    #prepare vars
    if global_ns is None:
        global_ns = {}
    if local_ns is None:
        local_ns = {}
    filename = "<console>"
    banner = "Dropping into Python"

    #try to load readline
    try:
        import readline
    except ImportError:
        pass

    #create console object
    console = code_mod.InteractiveConsole(local_ns, filename)

    #patch runcode
    def runcode(code):
        try:
            eval(code, global_ns, local_ns)
        except SystemExit:
            raise
        except:
            console.showtraceback()
        else:
            if code_mod.softspace(sys.stdout, 0):
                print
    console.runcode = runcode

    #run the console
    console.interact(banner)

#disabled this for now... integration has some glitches
def _ipython_shell(local_ns, global_ns):
    "helper for dbgcon which runs IPython shell, or returns False if IPython not present"
    #check for IPython
    try:
        from IPython.Shell import IPShellEmbed
    except ImportError:
        global _ipython_shell
        _ipython_shell = None #disable in future
        return False

    #check for nested instance
    try:
        __IPYTHON__
    except NameError:
        nested = 0
        args = ['']
    else:
        print "Running nested copies of IPython."
        print "The prompts for the nested copy have been modified"
        nested = 1
        # what the embedded instance will see as sys.argv:
        args = ['-pi1','In <\\#>: ','-pi2','   .\\D.: ',
                '-po','Out<\\#>: ','-nosep']

    # Now create an instance of the embeddable shell. The first argument is a
    # string with options exactly as you would type them if you were starting
    # IPython at the system command line. Any parameters you want to define for
    # configuration can thus be specified here.
    ipshell = IPShellEmbed(args,
                           banner = 'Dropping into IPython',
                           exit_msg = 'Leaving Interpreter, back to program.')
    ipshell(local_ns=local_ns, global_ns=global_ns)
    return True

def dbgcon(local_ns=None, global_ns=None, stacklevel=1):
    """opens up an embedded debugging console on stdin/stdout.
    by default, the accesses the local namespace of the calling function,
    but this can be altered via the various options.

    This function uses an embedded IPython shell if installed,
    else it falls back to the builtin python interpreter.

    .. todo::

        A env flag to disable IPython selection would be nice.
        A env flag to disable readline would be nice.

    :Parameters:
        stacklevel
            Choose what stacklevel the default namespaces should be pulled from.
            ``1`` (the default) uses the namespace of the immediate caller.
        local_ns
            Optionally overrides the local namespace that would be chosen via stacklevel.
        global_ns
            Optionally overrides the global namespace that would be chosen via stacklevel.
    """
    "run interact using caller's frame for locals"
    #TODO: make this load globals correctly!
    print "\n", "-=" * 40
    extra_keys = set() #set of extra keys we added to local_ns
    orig_ns = {} #set of values we clobbered in local_ns
    def shadow_local(key, value):
        if key in local_ns:
            orig_ns[key] = local_ns[key]
        else:
            extra_keys.add(key)
        local_ns[key] = value
    frame = inspect.currentframe(stacklevel)
    try:
        if local_ns is None:
            local_ns = frame.f_locals
        if global_ns is None:
            global_ns = frame.f_globals
        shadow_local("exit", sys.exit)
        if _ipython_shell and _ipython_shell(local_ns, global_ns):
            return
        _default_shell(local_ns, global_ns)
    finally:
        del frame
        if local_ns:
            for key in orig_ns:
                local_ns[key] = orig_ns[key]
            for key in extra_keys:
                del local_ns[key]
        print "\n", "^=" * 40

#=========================================================
#other utility funcs
#=========================================================
def trap(func, *args, **kwds):
    """development helper which traps and return errors.

    :param func:
        function to call
    :param *args:
        positional arguments for function
    :param **kwds:
        keyword arguments for function

    :returns:
        * ``(True,result)`` if function returns without error
        * ``(False,error)`` if function raises error
    """
    try:
        return True, func(*args, **kwds)
    except Exception, err:
        return False, err


def dbgstack(depth=0,  limit=None):
    "helper for pretty-printing the callstack"
    out = ''
    idx = depth
    frame = inspect.currentframe(1+depth)
    while frame:
        out += "(%r, %r, %r, %r),\n" % (
            depth,
            frame.f_code.co_filename,
            frame.f_code.co_name,
            frame.f_lineno)
        frame = frame.f_back
        depth += 1
        if limit and depth >= limit:
            break
    return out

def timer(count, func, *args, **kwds):
    "helper func for timing a function call"
    itr = xrange(count)
    s = time.time()
    result = func(*args, **kwds)
    if count > 1:
        for c in itr:
            func(*args, **kwds)
    delta = time.time() - s
    return delta / float(count), result

#=========================================================
#global search and replace
#=========================================================

def global_replace(root_path, match_re, replace_func, guard_func=None, file_filter=None):
    """This function implements a helpful global search-and-replace for an entire project tree.

    For simple uses, an IDE's global search and replace tool is usually better,
    the changes that need to be made are too extensive or complicated.
    This function allows quick scripts to be written which take care of
    complicated search-and-replace operations across an entire project.

    :arg root_path:
            root of path to perform search & replace within

    :param match_re:
            regular expression (if not compiled, will be compiled with re.M flag)
            any parts of any file in tree which match this regular expression
            will be passed to the replace_func for (potential) replacement.

    :param replace_func:
            function to handle analysis and replacement of any matching parts of a file.
            is called with one argument, the regexp match object.
            this function should then return the desired replacement string,
            or it should return None, in which case no replacement is performed.

    :param guard_func:
            optional function for checking file one last time before saving it...
            passed (path, input, output)... if it returns True, file is saved, else it isn't.

    .. todo::
        Give an example for this function
    """
    if isinstance(match_re, (tuple, list)):
        #assume it's a (re_str, re_flags) pair
        match_re = re.compile(*match_re)
    elif isinstance(match_re, str):
        match_re = re.compile(match_re, re.M)
    if file_filter is None:
        def file_filter(name):
            return name.endswith(".py")
    ctx = [None] #helper for logging
    for root, dirs, files in os.walk(root_path):
        if '.svn' in root: continue #skip subversion dirs
        for name in files:
            if not file_filter(name):
                continue
            path = filepath(root, name)
            input = path.get()
            #replace any matches
            def replace_wrapper(match):
                output = replace_func(match)
                input = match.group()
                if output is None:
                    return input
                if input != output:
                    if not ctx[0]:
                        if ctx[0] is False: print "\n"
                        print "FILE: %r" % (path,)
                        ctx[0] = True
                    print "   MATCH: %r" % (input,)
                    print "     -->: %r" % (output,)
                return output
            output = match_re.sub(replace_wrapper, input)
            if ctx[0]: ctx[0] = False
            #save result only if it changes
            if output and output != input:
                if guard_func and not guard_func(path, output, input):
                    print "   REJECTED"
                    continue
                path.set(output)

def purge_bytecode(root_path):
    """purge all pyc & pyo files from specified path"""
    for root, dirs, files in os.walk(root_path):
        if '.svn' in root: continue #skip subversion dirs
        if '.hg' in root: continue
        for name in files:
            if name[-4:] not in (".pyc", ".pyo"): continue
            path = filepath(root, name)
            print "PURGING ", path
            path.remove()

#=========================================================
#import tracker
#=========================================================
def log_imports(logger="sys.imports"):
    """
    this code wraps the builtin __import__ function
    with some code to log a message about every import that occurs.

    :param logger:
        Name of the logger to send output to.
        If ``False``, output is written straight to stderr.
    """
    depth = [0] #state for tracking import depth
    orig_import = __builtins__['__import__'] #old import hook
    import inspect,sys,os

    if logger:
        from logging import getLogger
        log = getLogger(logger)
        log._bps3_flag = False
        def write(msg, *args):
            if log._bps3_flag:
                #why do this? because we get a recursive import otherwise :(
                return
            msg = (".   " * depth[0]) + msg
            log._bps3_flag = True
            log.info(msg, *args)
            log._bps3_flag = False
    else:
        def write(msg, *args):
            if args: msg %= args
            sys.stderr.write("   " * depth[0])
            sys.stderr.write(">>> %s\n" % (msg,))
            sys.stderr.flush()

    def __import__(name, globals=None, locals=None, fromlist=None, level=-1):
        fname = inspect.currentframe(1).f_code.co_filename
        for elem in sys.path:
            if fname[0:len(elem)] == elem:
                mname = fname[len(elem):]
                if mname[0] == "/":
                    mname = mname[1:]
                break
        else:
            mname = fname #inspect.getmodulename(fname)
        if fromlist is not None:
            fstr = repr(fromlist)
            if len(fromlist) == 1:
                fstr = fstr[1:-2]
            else:
                fstr = fstr[1:-1]
            write("[FOR %r IMPORT %r FROM %r]", mname, fstr, name)
        else:
            write("[FOR %r IMPORT %r]", mname, name)
        depth[0] += 1
        try:
            mod = orig_import(name, globals, locals, fromlist, level)
        finally:
            depth[0] -= 1
        return mod

    #make sure all modules from now on use this
    __builtins__['__import__'] = __import__
    return __import__

#=========================================================
#EOF
#=========================================================
