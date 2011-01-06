"""
Email Client Interface - (c) 2005-2008 Assurance Technologies, LLC
"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
import os
import re
import subprocess
#site
from bps import *
from bps.stream import get_input_type
#lib
#pkg
find_exe = None #filled in by bps.host.__init__ to prevent cyclic loop
#local
__all__ = [
    #frontends
    'compose_email',

    #choosing
    'list_drivers', 'set_default_driver',

    #lookup
    'get_driver', 'has_driver', 'unload_drivers',

]

#=========================================================
#frontends
#=========================================================
def compose_email(*args, **kwds):
    "open mail client 'compose' window, raises EnvironmentError if something goes wrong talking to client"
    name = kwds.pop("client", "any")
    #XXX: rename "client" kwd to "driver_name" ? do same for get_driver()?
    return get_driver(name, missing="error").compose_email(*args, **kwds)

#=========================================================
#registry
#=========================================================
_default = "any" #name of explicitly chosen default driver, or None
_last_default = None #if default is "any", this caches last detected driver
_names = [] #list of driver names, in order they were registered
_classes = {} #map of driver name -> class
_instances = {} #map of driver name -> instance | None

def get_driver(name="any", missing="ignore"):
    """return named/default client or None if not found.

    *name* specifies the name of the client to load.
    If the named client is known, and can be located & contacted,
    the driver object for that client will be returned.
    If the client name is not known, or the specified client cannot be detected
    on the current system, ``None`` is returned.

    If no name is specified, the default client is chosen.
    If no suitable default can be found, ``None`` is returned.

    If *missing* is set to ``error`` instead of ``ignore``,
    a :exc:`KeyError` will be raised if the specified instead
    of returning ``None`` in any of the above cases.
    """
    assert missing in ("ignore", "error")
    global _default, _last_default
    if name is None:
        warn("name=None passed in, please use name='any' instead", stacklevel=2)
        name = "any"

    #check if driver was explicitly named
    if name != "any":
        driver = _load_driver(name)
        if driver:
           return driver
        if missing == "ignore":
            return None
        elif driver is False:
            raise KeyError, "email client %r not supported" % name
        else:
            raise KeyError, "email client %r not present" % name
    #else use default driver

    #check if default was disabled
    if _default is None:
        if missing == "ignore":
            return None
        else:
            raise KeyError, "default email client disabled"

    #try explicitly named default before picking first available
    if _default != "any":
        driver = _load_driver(_default)
        if driver:
            return driver
        log.warning("default email client not present: %r", _default)

    #check for cached value
    if _last_default:
        driver = _load_driver(_last_default)
        if driver:
            return driver

    #pick the first one we find
    for name in _names:
        driver = _load_driver(name)
        if driver:
            #remember for next time
            _last_default = driver.name
            return driver

    #give up
    if missing == "ignore":
        return None
    else:
        raise KeyError, "no known email clients are present"

def has_driver(name="any"):
    "check if driver for client is available & loadable"
    return bool(get_driver(name))

##def list_clients(known=False):
##    "lists names of known clients (may not all be present on system)"
##    if known:
##        return list(_names)
##    else:
##        return [ driver.name for driver in list_drivers() ]

def list_drivers():
    """return list of drivers for all known clients which can be detected on host"""
    global _names
    out = []
    for name in _names:
        driver = _load_driver(name)
        if driver:
            out.append(driver)
    return out

#TODO: update interface to allow app to set list of preferred clients,
# or get by list of preferred clients, instead of just a single one.

def set_default_driver(name):
    """explicitly choose which driver to use as the default.
    You may pass in the name of a driver, the driver object itself,
    ``"any"`` to allow the default to be automatically chosen,
    or ``None`` to explictly choose that there should be no default.
    """
    "set the default client to use"
    global _default
    if name == "any" or name is None:
        _default = name
        return
    if hasattr(name, "name"): #it's a driver class/instance
        name = name.name
    else:
        assert isinstance(name, str)
##    driver = _load_driver(name)
##    if driver:
        _default = name
##    elif driver is None:
##        raise ValueError, "%r mail client not present" % (name,)
##    else:
##        raise ValueError, "unknown mail client: %r" % (name,)

def register_driver(cls):
    "register a new driver class"
    name = cls.name
    if not name:
        raise RuntimeError, "no name specified"
    if not getattr(cls, "title", None):
        cls.title = name
    global _names, _classes
    _names.append(name)
    _classes[name] = cls

def _load_driver(name):
    """internal helper to load driver given name.
    returns driver if successful,
    None if driver known but not present,
    and False if driver is not known.
    """
    global _instances, _classes
    if name in _instances: #driver is loaded / was disabled (None)
        return _instances[name]
    elif name in _classes: #try to load driver
        cls = _classes[name]
        try:
            driver = cls()
        except EnvironmentError, err:
            log.info("%r driver not present: %r", name, err)
            driver = None
        else:
            log.debug("loaded %r driver", name)
            assert driver, "loaded drivers must be boolean True" #just to be nice
        _instances[name] = driver
        return driver
    else:
        #unknown driver name
        return False

def unload_drivers():
    "flushes any loaded drivers, causing them to be redetected next time they are needed"
    global _instances, _last_default
    drivers = _instances.values()
    _last_default = None
    _instances.clear()
    for driver in drivers:
        if hasattr(driver, "close"):
            driver.close()

#=========================================================
#
#=========================================================
class BaseDriver(BaseClass):
    "base interface to mail clients"
    name = None #name to refer to driver by
    title = None #display name of driver

    #NOTE: driver's init method should do host-env detection,
    #and raise EnvironmentError if driver can't run.

    def compose_email(self, to=None, cc=None, bcc=None, subject=None, body=None, attachments=None, invalid="error"):
        """tell client to open a new compose-email window.

        :Parameters:
            to
                list of email addrs, or string containing semicolon separated email addrs.
            cc
                same format as 'to', but for 'cc' field
            bcc
                same format as 'to', but for 'bcc' field
            subject
                optional subject text
            body
                optional body text (for now, should be text/plain)
            attachments
                not implemented: would like to support list of filepaths,
                as well as dict mapping names => buffers (or filepaths)
            invalid
                policy for invalid email addrs: "error", "ignore", "keep", callable
        """
        raise NotImplementedError

#=========================================================
#thunderbird interface
#=========================================================
class ThunderbirdDriver(BaseDriver):
    name = "thunderbird"
    title = "Mozilla Thunderbird"

    path = None #path to thunderbird exe

    def __init__(self):
        self.__super.__init__()
        self.path = find_exe("thunderbird")
        if self.path is None:
            log.info("thunderbird exe can't be found")
            raise EnvironmentError, "thunderbird exe not found"
        log.info("thunderbird exe detected in path: %r", self.path)

    def compose_email(self, to=None, cc=None, bcc=None, subject=None, body=None, attachments=None, invalid="error"):
        to = norm_addrs(to, invalid=invalid)
        cc = norm_addrs(cc, invalid=invalid)
        bcc = norm_addrs(bcc, invalid=invalid)
        attachments = norm_attachments(attachments)

        #NOTE: thunderbird 1.5 has a bug where it can't parse these fields,
        #have to use the mailto:// url argument format instead.

        #TODO: check if "'" or other values are present, and deal with them.
        out = []
        if to:
            out.append("to='%s'" % ",".join(to))
        if cc:
            out.append("cc='%s'" % ",".join(cc))
        if bcc:
            out.append("bcc='%s'" % ",".join(bcc))
        if subject:
            out.append("subject='%s'" % subject)
        if body:
            out.append("body='%s'" % body)
        if attachments:
            #NOTE: 'name' attribute isn't supported.
            #we _could_ copy everything to properly named temp files, but ICH.
            #TODO: should urlencode path
            parts = ",".join(
                "file://%s" % path
                for name, path in attachments
                )
            out.append("attachment='%s'" % parts)
        opts = ",".join(out)

        log.debug("calling thunderbird to compose email: %r", opts)
        proc = subprocess.Popen([self.path, "-compose", opts])
        #NOTE: if thunderbird is already running, proc will exit w/ rc=0 immediately
        #else, will wait till user closes compose window, then exit w/ rc=0.
        #since the semantics of this call are NOWAIT, we just ignore 'proc'
        return True
register_driver(ThunderbirdDriver)


#=========================================================
#Google Apps "desktop client" interface
#   e.g.
#   %PROGFILES%\Google\Google Apps\googleapps.exe --domain=caapdocs.com --mail.google.com
#=========================================================
class GoogleAppsDriver(BaseDriver):
    name = "googleapps"
    title = "Google Apps Email"

    path = None #path to googleapps.exe

    def __init__(self):
        self.__super.__init__()
        #additional windows paths to search for exe
        extra_paths = ['%PROGRAMFILES%\\Google\\Google Apps\\',] if os.name == 'nt' else []
        self.path = find_exe("googleapps", extra_paths=extra_paths)
        if self.path is None:
            log.info("GoogleApps exe can't be found")
            raise EnvironmentError, "GoogleApps exe not found"
        log.info("GoogleApps exe detected in path: %r", self.path)

    def compose_email(self, to=None, cc=None, bcc=None, subject=None, body=None, attachments=None, invalid="error"):
        to = norm_addrs(to, invalid=invalid)
        cc = norm_addrs(cc, invalid=invalid)
        bcc = norm_addrs(bcc, invalid=invalid)
        attachments = norm_attachments(attachments)

        #NOTE: thunderbird 1.5 has a bug where it can't parse these fields,
        #have to use the mailto:// url argument format instead.

        #TODO: check if "'" or other values are present, and deal with them.
        out = []
        if to:
            out.append("to='%s'" % ",".join(to))
        if cc:
            out.append("cc='%s'" % ",".join(cc))
        if bcc:
            out.append("bcc='%s'" % ",".join(bcc))
        if subject:
            out.append("subject='%s'" % subject)
        if body:
            out.append("body='%s'" % body)
        if attachments:
            #NOTE: 'name' attribute isn't supported.
            #we _could_ copy everything to properly named temp files, but ICH.
            #TODO: should urlencode path
            parts = ",".join(
                "file://%s" % path
                for name, path in attachments
                )
            out.append("attachment='%s'" % parts)
        opts = ",".join(out)

        log.debug("calling GoogleApps to compose email: %r", opts)
        proc = subprocess.Popen([self.path, "-compose", opts])
        #NOTE: if thunderbird is already running, proc will exit w/ rc=0 immediately
        #else, will wait till user closes compose window, then exit w/ rc=0.
        #since the semantics of this call are NOWAIT, we just ignore 'proc'
        return True
register_driver(GoogleAppsDriver)

#=========================================================
#outlook interface
#=========================================================
if os.name == "nt":
    #-----------------------------------------------
    #outlook imports
    #-----------------------------------------------
    from bps.host.windows import detect_outlook ##, detect_outlook_express
    try:
        import win32com
        from pywintypes import com_error
    except ImportError:
        win32com = None

    #-----------------------------------------------
    #OUTLOOK CONSTANTS
    #-----------------------------------------------
    #OlItemTypes
    OL_MAILITEM = 0

    #OlMailRecipientType
    ##OL_TO = 1
    ##OL_CC = 2
    ##OL_BCC = 3

    #OlAttachmentTypes
    OL_BYVALUE = 1

    #-----------------------------------------------
    #outlook driver
    #-----------------------------------------------
    class OutlookDriver(BaseDriver):
        name = "outlook"
        title = "Microsoft Outlook"

        com = None #outlook com reference

        def __init__(self):
            self.__super.__init__()
            if not win32com:
                raise EnvironmentError, "win32com module required for Outlook integration"
            self.outlook = detect_outlook()
            if not self.outlook:
                #FIXME: should raise env error, but want to make sure we're detecting right first
                log.critical("MS Outlook not installed!")
            else:
                log.debug("MS Outlook detected in registry: %r", self.outlook)
##                self.title += " (%s)" % self.outlook['vstr']

        def compose_email(self, to=None, cc=None, bcc=None, subject=None, body=None, attachments=None, invalid="error"):
            to = norm_addrs(to, invalid=invalid)
            cc = norm_addrs(cc, invalid=invalid)
            bcc = norm_addrs(bcc, invalid=invalid)
            attachments = norm_attachments(attachments)
            app = email = None
            try:
                app = win32com.client.DispatchEx("Outlook.Application")
                email = app.CreateItem(OL_MAILITEM)
                if to:
                    email.To = "; ".join(to)
                if cc: #NOTE: haven't tested this com attr
                    email.Cc = "; ".join(cc)
                if bcc: #NOTE: haven't tested this com attr
                    email.Bcc = "; ".join(bcc)
                email.Subject = subject or ''
                if body:
                    raise NotImplementedError, "body not implemented"
                for name, path in attachments:
                    email.Attachments.Add(path, OL_BYVALUE, 1, name)
                email.Display()
            except com_error, err:
                #XXX: close the email? go ahead and display it?
                log.critical("unexpected com error from outlook: %r", err, exc_info=True)
                raise EnvironmentError, "an error occurred while opening Outlook"
            return True

    register_driver(OutlookDriver)

#=========================================================
#util functions
#=========================================================
_re_email_title = re.compile("""
    ^
    \s* (.+?) \s*
    <
        \s* (.+?) \s*
    > \s*
    $
    """, re.X)

_re_email_addr = re.compile("""
    ^
    \s* (.+?) @ (.+?) \s*
    $
    """, re.X)

def norm_addrs(value, invalid="error"):
    """
    parses input argument for compose's to/cc/bcc

    input value can be a string of addrs separated by "," or ";"
    or a list of addrs.

    addrs can be "a@b.c" or "Name <a@b.c>"
    """
    if not value:
        return []
    if isinstance(value, str):
        value = value.split(",")
        if len(value) == 1:
            value = value[0].split(";")
    tmp = ( norm_addr(elem, invalid=invalid) for elem in value ) #normalize
    return [ elem for elem in tmp if elem ] #strip empty addrs

def norm_addr(value, invalid="error"):
    """
    norm a single email addr
    addrs can be "a@b.c" or "Name <a@b.c>"
    """
    if not callable(invalid):
        if invalid == "error":
            def invalid(value):
                raise ValueError, "not an email address: %r" % value
        elif invalid == "ignore":
            def invalid(value):
                return None
        else:
            assert invalid == "keep"
            def invalid(value):
                return value
    orig = value
    m = _re_email_title.match(value)
    if m:
        name, value = m.group(1, 2)
    else:
        name = None
    m = _re_email_addr.match(value)
    if m:
        local, domain = m.group(1, 2)
        addr = "%s@%s" % (local, domain)
    else:
        return invalid(orig)
    if name:
        return "%s <%s>" % (name, addr)
    else:
        return addr

def norm_attachments(value):
    """
    normalize attachment input.
    can be list or dict.

    returns list of (name,filepath) pairs
    """
    #TODO: have this check the filepaths exist,
    #and issue a warning (dropping the path) if they don't
    if not value:
        return []
    if isinstance(value, (list, tuple)):
        return [
            norm_attachment(None, source)
            for source in value
        ]
    else:
        return [
            norm_attachment(name, source)
            for name, source in value.iteritems()
        ]

def norm_attachment(name, source):
    if isinstance(source, tuple):
        alt_name, source = source
        if name is None:
            name = alt_name
    stype = get_input_type(source)
    if stype == "raw" or stype == "stream":
        raise NotImplementedError, "need to store string/buffer in temp file"
    else:
        assert stype == "path"
        path = filepath(source).abspath
        if name is None:
            name = path.name
        return name, path

#=========================================================
#eof
#=========================================================
