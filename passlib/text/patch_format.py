"""bps.text.patch_format -- automatically patches python 2.5 to support format()"""
#=========================================================
#patch python
#=========================================================
if not hasattr('', 'format'): #py26 at on will have proper implemenation
    from bps.text._string_format import format, _formatter

    __builtins__['format'] = format

    def patch_string_types():
        """insert a format() method to the builtin str & unicode types.

        credit the following blog for this bit of ctypes evil :)
           http://comex.wordpress.com/2009/01/19/how-to-add-methods-to-a-python-built-in-type/

        =======================
        WARNING WARNING WARNING
        =======================
        Seriously, monkeypatching the builtin types just shouldn't be done.
        if you came this far, and want to use this code yourself,
        PLEASE choose another route. If such behavior became prevalent,
        the core types would become unpredictable in all kinds of ways,
        and down that road lies madness. The only reason we *barely* have
        an excuse in this case:
            * It's backward compatible with python 2.5,
              there was no format method on str or anything else to conflict with.
            * It's a Python 2.6 feature, so nothing is being done to the namespace
              of str or unicode which GvR didn't approve... He just didn't
              approve it for Python 2.5 :)
            * BPS tries to provide a reasonably faithful replica of Python 2.6's format method.
              Any deviations from it will be patched as soon as they are found,
              so 2.5 users should not come to rely on non-standard behavior.
            * If the code you're patching in does not satisfy ALL of the above conditions,
              please don't monkeypatch the builtin types!
            * Though if you do get this far, we'll be happy to rework this code
              so you can use BPS to handle the grunt work, so there's only
              one implementation of the ctypes patcher floating around.

        .. todo::
            If this gets deployed under Jython or something else,
            we'll need to use a different patching strategy.
        """
        from ctypes import pythonapi, Structure, c_long, c_char_p, POINTER, py_object

        class py_type(Structure):
            _fields_ = [
                # 1, type, zero,
                ('ob_refcnt', c_long),
                ('ob_type', POINTER(c_long)), # could be different
                ('ob_size', c_long), # size
                ('name', c_char_p),
                ('tp_basicsize', c_long),
                ('tp_itemsize', c_long),
                ('tp_dealloc', POINTER(c_long)),
                ('tp_print', POINTER(c_long)),
                ('tp_getattr', POINTER(c_long)),
                ('tp_getattr', POINTER(c_long)),
                ('tp_compare', POINTER(c_long)),
                ('tp_repr', POINTER(c_long)),
                ('tp_as_number', POINTER(c_long)),
                ('tp_as_sequence', POINTER(c_long)),
                ('tp_as_mapping', POINTER(c_long)),
                ('tp_hash', POINTER(c_long)),
                ('tp_call', POINTER(c_long)),
                ('tp_str', POINTER(c_long)),
                ('getattrofunc', POINTER(c_long)),
                ('setattrofunc', POINTER(c_long)),
                ('tp_as_buffer', POINTER(c_long)),
                ('tp_flags', c_long),
                ('tp_doc', c_char_p),
                ('tp_traverse', POINTER(c_long)),
                ('tp_clear', POINTER(c_long)),
                ('tp_richcompare', POINTER(c_long)),
                ('tp_weaklistoffset', POINTER(c_long)),
                ('tp_iter', POINTER(c_long)),
                ('tp_iternext', POINTER(c_long)),
                ('tp_methods', POINTER(c_long)),
                ('tp_members', POINTER(c_long)),
                ('tp_getset', POINTER(c_long)),
                ('tp_base', POINTER(c_long)),
                ('tp_dict', py_object)

            ]

        render = _formatter.format
        def wrapper(self, *args, **kwds):
            """pure-python implementation of python 2.6's str.format() method, provided by BPS"""
            return render(self, *args, **kwds)
        wrapper.__name__ = "format"

        po = py_type.in_dll(pythonapi, "PyString_Type")
        po.tp_dict['format'] = wrapper

        po = py_type.in_dll(pythonapi, "PyUnicode_Type")
        po.tp_dict['format'] = wrapper

    patch_string_types()
