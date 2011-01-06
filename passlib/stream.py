"""bps.stream -- stream and buffer related functions"""
#=========================================================
#imports
#=========================================================
#core
import os
#local
__all__ = [
    #nb read
    'nb_read',
    'nb_readline_iter',
    'nb_readline_list',

    #guesser
    'get_input_type', 'BT',
]

#=========================================================
#misc
#=========================================================
def get_stream_size(stream, abs=False):
    """return size of stream.

    :param stream:
        This must be a *seekable* stream object.
        This function will return the size of the stream
        by seeking to the end, recording the information,
        and then restoring the original location in the stream.

    :param abs:
        If ``True``, the absolute size of the stream is reported.
        If ``False`` (the default), the number of remaining bytes
        relative to the current position is reported.

    :returns:
        Number of bytes in stream as an integer.
    """
    pos = stream.tell()
    try:
        stream.seek(0, 2) #seek to end
        if abs:
            return stream.tell()
        else:
            return stream.tell()-pos
    finally:
        stream.seek(pos)

##def iter_stream_records(stream, size=None, count=None, notail=False, map=None):
##    """read a series of fixed-size records from stream,
##    returning them via an iterator.
##
##    :param stream:
##        the stream to read from.
##    :param size:
##        size of the record in bytes.
##    :param count:
##        [Optional]
##        Exact number of records that should be read.
##        Stops when that many have been read.
##        If stream runs out before *count* records have been read, raises ValueError.
##        If count is not specified, will read to end of stream.
##
##    :param notail:
##        If *count* is specified and this is ``True``,
##        a ValueError will be raised if any data is left in the stream
##        after reading off max records.
##
##    :param map:
##        Optional mapping function to apply.
##    """
##    cur = 0
##    while True:
##        chunk = buffer.read(size)
##        if not chunk:
##            if count is not None:
##                raise ValueError, "too few records!"
##            return
##        if len(chunk) < size:
##            raise ValueError, "chunk unexpectedly too small"
##        assert len(chunk) == size
##        if map:
##            yield map(chunk)
##        else:
##            yield chunk
##        cur += 1
##        if count is not None and cur == count:
##            if notail:
##                #should we leave it in stream if possible?
##                #makes behavior unpredictable.
####                if hasattr(buffer, "seek"):
####                    pos = buffer.tell()
####                    chunk = buffer.read()
####                    buffer.seek(pos, 0)
####                else:
##                chunk = buffer.read()
##                if chunk:
##                    raise ValueError, "unexpected data at end of buffer: %r" % chunk
##            return

##def unpack_from_stream(fmt, stream):
##    """helper for quickly unpacking chunks from stream using struct module.
##
##    :param fmt:
##        valid :mod:`struct` format string
##    :param stream:
##        stream to read from
##
##    :returns:
##        unpacked array
##    """
##    size = struct.calcsize(fmt)
##    chunk = stream.read(size)
##    return struct.unpack(fmt, chunk)

#=========================================================
#
#=========================================================
#NOTE: this probably works, just not used or tested yet.
##class unbuffered(object):
##    "wrapper around stream object which disables buffering"
##    buffered = False #flag so we can be called on something that's already unbuffered
##    raw_stream = None #stream we're wrapping
##
##    def __new__(cls, stream):
##        if not getattr(stream, "buffered", True):
##            return stream
##        if not hasattr(stream, "flush"):
##            warn("can't disable buffering for stream: %r" % (stream,))
##            return stream
##        self = object.__init__(cls)
##        self.raw_stream = stream
##        if hasattr(stream, "writelines"):
##            self.writelines = self.__writelines
##        return self
##
##    def write(self, arg):
##        retval = self.raw_stream.write(arg)
##        self.raw_stream.flush()
##        return retval
##
##    def __writelines(self, arg):
##        retval = self.raw_stream.writelines(arg)
##        self.raw_stream.flush()
##        return retval
##
##    def __getattr__(self, attr):
##        return getattr(self.raw_stream, attr)
##
##    #TODO: needs dir() wrapper, maybe repr/str wrappers to, check Proxy object for source.

#=========================================================
#non-blocking pipe reader
#=========================================================
#NOTE: low level nb read code adapted from http://code.activestate.com/recipes/440554/

def nb_read(stream, maxsize=-1):
    """read bytes from a stream in non-blocking fashion.

    This attempts to perform nonblocking read on a stream,
    and do this uniformly across operating systems.

    .. note::
        Under windows, PeekNamedPipe is used,
        which required the pywin32 package.
        For other OSes, :mod:`fcntrl` is used.

    :arg stream:
        The stream to read from.
        Currently only file() handles are supported,
        but this may be enhanced in the future.

    :param maxsize:
        If ``-1``, the maximum available characters will be read.
        Otherwise, up to *maxsize* characters will be returned.

    :Returns:
        String containing characters, with at length of at most *maxsize*.
        The empty string is returned if no data is available.
    """
    if maxsize == 0:
        return ''
    if maxsize < -1:
        raise ValueError, "maxsize must be -1, or > 0"
    #TODO: check for none-filetype streams
    return _nb_read(stream, maxsize)

#---------------------------------------------------
#windows version
#---------------------------------------------------
if os.name == "nt":
    from win32file import ReadFile
    from win32pipe import PeekNamedPipe
    from msvcrt import get_osfhandle
    import errno

    def _nb_read(pipe, maxsize):
        try:
            x = get_osfhandle(pipe.fileno())
            (read, avail, msg) = PeekNamedPipe(x, 0)
            if maxsize != -1 and maxsize < avail:
                avail = maxsize
            if avail > 0:
                (errnum, read) = ReadFile(x, avail, None)
                return read
            else:
                return ''
        except ValueError:
            return '' #pipe is closed
        except (subprocess.pywintypes.error, Exception), err:
            if err[0] in (109, errno.ESHUTDOWN):
                return '' #pipe is closed
            raise

#---------------------------------------------------
#posix version
#---------------------------------------------------
else:
    import fcntl
    import select

    def _nb_read(pipe, maxsize):
        flags = fcntl.fcntl(pipe, fcntl.F_GETFL)
        if not pipe.closed:
            fcntl.fcntl(pipe, fcntl.F_SETFL, flags| os.O_NONBLOCK)
        try:
            if not select.select([pipe], [], [], 0)[0]:
                return ''
            if maxsize == -1:
                return pipe.read()
            else:
                return pipe.read(maxsize)
        finally:
            if not pipe.closed:
                fcntl.fcntl(pipe, fcntl.F_SETFL, flags)

#---------------------------------------------------
#TODO: other OSes
#---------------------------------------------------

#=========================================================
#nb_read helpers
#=========================================================
def nb_readline_iter(stream, chop=False, chunk_size=256):
    """generator which does non-blocking readline of stream,
    taking care of assembling and returning only full lines.

    :arg stream:
        stream to read
    :param chop:
        whether to strip linefeeds from end
    :param chunk_size:
        how much to read at a time

    :returns:
        Calling this returns a generator bound to the stream,
        which maintains an internal cache of bytes read.

        When iterated over, it will read in all data available from the pipe.
        It will then yield ``None`` if no complete line is available,
        otherwise it will yield the next available line as a string.
        If the stream closes, the last line returned may not have a linefeed at the end.

    .. seealso::
        :class:`nb_readline_list` which wraps this function
    """
    buf = ''
    while True:
        #check for next line in buffer
        idx = buf.find("\n")+1 #FIXME: replace w/ bps.mime.utils's find_eol()
        if idx > 0:
            out, buf = buf[:idx], buf[idx:]
            if chop:
                out = out.rstrip()
            yield out
            continue
        #try to populate the buffer
        chunk = nb_read(stream, chunk_size)
        if chunk:
            buf += chunk
            continue
        #send last bit if stream is closed
        if stream.closed:
            if buf:
                yield buf
            return
        #else yield exhausted signal
        yield None

class nb_readline_list(list):
    """
    List subclass which is designed to accumlate
    parsed lines read (via :func:`nb_read`) from a stream.
    Call this ``self.flush()`` method to load any more lines
    that are available in the stream.

    :param stream:
        The stream to read from.

    :param chop:
        whether to strip linefeeds from end.

    Usage example::

        >>> from bps.stream import nb_readline_list
        >>> fh = file("/home/elic/myfile.txt")
        >>> lines = nb_readline_list(fh)
        >>> lines
            []
        >>> lines.flush() #flush will append any more lines available on fh
            True
        >>> lines
            ['line1\\n', 'line2\\n' ]
        >>> # ... do stuff such as popping existing lines ...
        >>> lines.pop(0)
            'line1\\n'
        >>> # Now assume file was being written to concurrently,
        >>> # next flush will append any more lines
        >>> lines.flush()
            True
        >>> lines
            [ 'line2\\n', 'line3\\n' ]

    """
    def __init__(self, stream, **kwds):
        self.reader = nb_readline_iter(stream, **kwds)

    def flush(self):
        "flush any pending lines from stream into buffer. returns False if stream is closed"
        if not self.reader: #stream closed during previous call
            return False
        for line in self.reader:
            if line is None: #no more data for now
                return True
            self.append(line)
        else: #stream closed itself
            self.reader = None
            return False

#=========================================================
#buffer funcs
#=========================================================

#XXX: rename to ByteSourceType?
class BT:
    """The common byte-source types.

    This class defines three constants,
    which represent the possible sources for a string of bytes.
    This is mainly useful for functions which take in / return
    bytes in various formats. The following constants
    provide a useful standard for referring to these:

        =============   ============    =======================================
        Constant Name   String Value    Meaning
        -------------   ------------    ---------------------------------------
        ``BT.RAW``      ``"raw"``       The source is a raw string of bytes.
        ``BT.STREAM``   ``"stream"``    The source is a file handle or
                                        other stream-like object from which
                                        bytes can be read.
        ``BT.PATH``     ``"path"``      The source is string which points
                                        to a path on the local filesystem.
        =============   ============    =======================================

    The constant ``BT.values`` is also available,
    which is a list of all possible values.

    .. seealso::
        * :func:`get_input_type` which can autodetect the various byte-source types.
    """
    RAW = "raw"
    STREAM = "stream"
    PATH = "path"
    values = (RAW, STREAM, PATH)

    VALUES = values #deprecated alias

BAD_CHARS = "\x00\x09\r\n"
def get_input_type(source, source_type=None, max_path=512, bad_chars=None):
    """This function detects whether the provided object
    is a filepath, buffer, or a raw string. This allows many functions
    to take in a data source without having to specify multiple variants
    of the function to handle the different datatypes.

    While buffers are easy to detect, the distinction between filepath & string
    relies on a fuzzier set of criteria: it makes the assumption that any filepath
    will never contain certain characters (null, cr, lf), while source data
    is almost certain too (if this is untrue for a particular domain of source data,
    this function will not be very much help).

    :Parameters:
        source
            The source object to test
        max_path
            Maximum length that we should expect for a filepath.
        bad_chars
            String of characters that we should never expect to see
            in a filepath. Setting this to ``"\x00"`` may allow
            certain rare paths to be detected that would otherwise be skipped.
            By default, this list includes NUL, TAB, CR, and LF.
        source_type
            Limits types to be considered. For example, if it is known
            that the source must be either a filepath or buffer,
            set this value to ``['path','stream']``, and the 'string'
            option will be not considered. By default, all possibilities
            (``['path', 'stream', 'raw']``) will be considered.

    :Returns:
        Returns one of the following strings:

            'path'
                This source represents a path to a file.
                :class:`bps.fs.FilePath` objects will be detects with
                100% reliability based on their attributes.
                Otherwise, this option is guessed based on the string's contents.

            'stream'
                This source is a stream (file, StringIO, etc).
                These are detected with 100% reliability based on their attributes.

            'raw'
                This source is a string containing raw data.
                This will be used as the fallback choice.

            ``None``
                returned if ``source`` is None.

        Otherwise a TypeError will be raised.

        If the source is determined for certain,
        but does not match one of the source types
        allows by the *source_type* keyword,
        a ValueError will be raised.

        .. todo::
            Document the BT enumerated type here.

    Usage Example::

        >>> from bps.stream import get_input_type
        >>> get_input_type(r"c:\Documents and Settings\Administrator")
            'path'
        >>> get_input_type(r"a\nb\nc")
            'raw'
        >>> from cStringIO import StringIO
        >>> buf = StringIO()
        >>> get_input_type(buf)
            'stream'

    """
    if source is None:
        return None
    if isinstance(source_type, str):
        return source_type
    elif source_type is None:
        source_type = BT.values
    if bad_chars is None:
        bad_chars = BAD_CHARS

    #check for filepath objects [reliable]
    if hasattr(source, "normpath"):
        if BT.PATH not in source_type:
            raise ValueError, "source appears to be a file path!"
        return BT.PATH

    #check for buffer [reliable]
    if hasattr(source, "read"):
        if BT.STREAM not in source_type:
            raise ValueError, "source appears to be a stream!"
        return BT.STREAM

    #check size [this is just a guess, but reasonable]
    if (len(source) == 0 or len(source) > max_path) and BT.RAW in source_type:
        return BT.RAW

    #look for chars we'll never see in a path [default set is pretty certain; and if bad_chars="\x00", near dead certain]
    if any(char in source for char in bad_chars):
        if BT.RAW not in source_type:
            raise ValueError, "source appears to be a raw string!"
        return BT.RAW

    #assume it's a path [this is just a guess],
    #since it appears to have all the right properties,
    #and only small single-line non-binary strings could get here.
    if BT.PATH in source_type:
        return BT.PATH
    elif BT.RAW in source_type: #path-type wasn't on the list, assume a string
        return BT.RAW
    else:
        raise ValueError, "source appears to be a raw string or file path!"

#=========================================================
#get_input_type wrappers
#=========================================================

#useful but unused
##def get_input_buffer(source, **kwds):
##    """helper using guess_input_type() which always returns a buffer, whether passed file, string, or buffer"""
##    #XXX: what if we want to open in text mode?
##    # we'll need to decode / adapt the buffer as well!
##    type = get_input_type(source, **kwds)
##    if type == BT.PATH:
##        return file(source, "rb")
##    elif type == BT.RAW:
##        return StringIO(source)
##    else:
##        assert type == BT.STREAM
##        return source

#useful but unused
##def open_input_buffer(source, **kwds):
##    "context-manager version of get_input_buffer"
##    type = guess_input_type(source, **kwds)
##    if type == BT.PATH:
##        return file(source, "rb")
##    elif type == BT.RAW:
##        buffer = StringIO(source)
##    else:
##        assert type == BT.STREAM
##        buffer = source
##    @contextmanager
##    def noop():
##        yield buffer
##    return noop()

#might be useful, but untested, and may be incomplete
##class autoflush(object):
##    """creates wrapped version of stream which auto-flushes after writes.
##
##    Usage Example::
##
##        >>> from bps.stream import autoflush
##        >>> f = file("out.txt","w")
##        >>> f2 = autoflush(f)
##        >>> f2.write("test\n") #will be automatically flushed.
##    """
##
##    def __init__(self, stream):
##        self.__dict__['stream'] = stream
##
##        if hasattr(stream, "write"):
##            def write(*a, **k):
##                ret = stream.write(*a, **k)
##                stream.flush()
##                return ret
##            self.__dict__['write'] = write
##
##        if hasattr(stream, "writeln"):
##            def writeln(self, *a, **k):
##                ret = stream.writeln(*a, **k)
##                stream.flush()
##                return ret
##            self.__dict__['writeln'] = writeln
##
##    def __getattr__(self, attr):
##        "proxy all attribute reads to the proxy target"
##        return getattr(self.stream, attr)
##
##    def __setattr__(self, attr, value):
##        "proxy all attribute writes to the proxy target"
##        setattr(self.stream, attr, value)
##
##    def __delattr__(self, attr):
##        "proxy all attribute deletes to the proxy target"
##        delattr(self.stream, attr)
##
##    def __dir__(self):
##        "reports list of all of proxy object's attrs as well as target object's attributes (if any)"
##        attrs = set(dir(self.__class__))
##        attrs.update(self.__dict__)
##        attrs.update(dir(self.stream))
##        return sorted(attrs)
##
##    def __repr__(self):
##        return "<autoflush: %r>" % (self.stream,)

#=========================================================
#EOC
#=========================================================
