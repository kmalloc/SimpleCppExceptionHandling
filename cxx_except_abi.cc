#include "cxx_except_abi.h"

#include <iostream>

#include <stdlib.h>
#include <unwind.h>

#include <assert.h>

using namespace std;

/* Pointer encodings, from dwarf2.h.  */
#define DW_EH_PE_absptr         0x00
#define DW_EH_PE_omit           0xff

#define DW_EH_PE_uleb128        0x01
#define DW_EH_PE_udata2         0x02
#define DW_EH_PE_udata4         0x03
#define DW_EH_PE_udata8         0x04
#define DW_EH_PE_sleb128        0x09
#define DW_EH_PE_sdata2         0x0A
#define DW_EH_PE_sdata4         0x0B
#define DW_EH_PE_sdata8         0x0C
#define DW_EH_PE_signed         0x08

#define DW_EH_PE_pcrel          0x10
#define DW_EH_PE_textrel        0x20
#define DW_EH_PE_datarel        0x30
#define DW_EH_PE_funcrel        0x40
#define DW_EH_PE_aligned        0x50

#define DW_EH_PE_indirect	0x80

#define _uleb128_t   _Unwind_Word
#define _sleb128_t   _Unwind_Sword

enum
{
    to_terminate,
    to_do_nothing,
    to_do_cleanup,
    to_do_handler,
};

struct lsda_header_info
{
    _Unwind_Ptr Start;
    _Unwind_Ptr LPStart;
    _Unwind_Ptr ttype_base;
    const unsigned char *TType;
    const unsigned char *action_table;
    unsigned char ttype_encoding;
    unsigned char call_site_encoding;
};


namespace __cxxabiv2 {

    extern "C" void * __cxa_allocate_exception(std::size_t thrown_size) throw()
    {
        void *ret;

        thrown_size += sizeof (__cxa_exception);
        ret = malloc (thrown_size);

        assert(ret);

        memset (ret, 0, sizeof (__cxa_exception));

        return (void *)((char *)ret + sizeof (__cxa_exception));
    }

    extern "C" void __cxa_free_exception(void *vptr) throw()
    {
        char *ptr = (char *) vptr;
        free(ptr - sizeof (__cxa_exception));
    }

    inline __cxa_exception* __get_exception_header_from_obj (void *ptr)
    {
        return reinterpret_cast<__cxa_exception *>(ptr) - 1;
    }

    // Acquire the C++ exception header from the generic exception header.
    inline __cxa_exception* __get_exception_header_from_ue (_Unwind_Exception *exc)
    {
        return reinterpret_cast<__cxa_exception *>(exc + 1) - 1;
    }

    void* __cxa_begin_catch(void *exc_obj_in) throw()
    {
        cout << "begin catch" << endl;
        _Unwind_Exception *exceptionObject
            = reinterpret_cast <_Unwind_Exception *>(exc_obj_in);

        return exceptionObject;
    }

    void __cxa_end_catch ()
    {
        cout << "end catch" << endl;
    }

    extern "C" void __cxa_throw (void *obj, std::type_info *tinfo,
            void (*dest) (void *))
    {
        __cxa_exception *header = __get_exception_header_from_obj(obj);

        header->exceptionType = tinfo;
        header->exceptionDestructor = dest;
        header->unexpectedHandler = std::unexpected;
        header->terminateHandler = std::terminate;

        // need to setup unwindHeader, TODO

        _Unwind_RaiseException (&header->unwindHeader);

        __cxa_begin_catch (&header->unwindHeader);
        std::terminate ();
    }
}

using namespace __cxxabiv2;

static const unsigned char *
read_uleb128 (const unsigned char *p, _Unwind_Word *val)
{
    unsigned int shift = 0;
    unsigned char byte;
    _Unwind_Word result;

    result = 0;
    do
    {
        byte = *p++;
        result |= ((_Unwind_Word)byte & 0x7f) << shift;
        shift += 7;
    }
    while (byte & 0x80);

    *val = result;
    return p;
}

/* Similar, but read a signed leb128 value.  */

static const unsigned char *
read_sleb128 (const unsigned char *p, _Unwind_Sword *val)
{
    unsigned int shift = 0;
    unsigned char byte;
    _Unwind_Word result;

    result = 0;
    do
    {
        byte = *p++;
        result |= ((_Unwind_Word)byte & 0x7f) << shift;
        shift += 7;
    }
    while (byte & 0x80);

    /* Sign-extend a negative value.  */
    if (shift < 8 * sizeof(result) && (byte & 0x40) != 0)
        result |= -(((_Unwind_Word)1L) << shift);

    *val = (_Unwind_Sword) result;
    return p;
}

static unsigned int
size_of_encoded_value (unsigned char encoding)
{
    if (encoding == DW_EH_PE_omit)
        return 0;

    switch (encoding & 0x07)
    {
        case DW_EH_PE_absptr:
            return sizeof (void *);
        case DW_EH_PE_udata2:
            return 2;
        case DW_EH_PE_udata4:
            return 4;
        case DW_EH_PE_udata8:
            return 8;
    }

    assert(0);
}

static _Unwind_Ptr
base_of_encoded_value (unsigned char encoding, struct _Unwind_Context *context)
{
    if (encoding == DW_EH_PE_omit)
        return 0;

    switch (encoding & 0x70)
    {
        case DW_EH_PE_absptr:
        case DW_EH_PE_pcrel:
        case DW_EH_PE_aligned:
      return 0;

    case DW_EH_PE_textrel:
      return _Unwind_GetTextRelBase (context);
    case DW_EH_PE_datarel:
      return _Unwind_GetDataRelBase (context);
    case DW_EH_PE_funcrel:
      return _Unwind_GetRegionStart (context);
    }

  assert(0);
}

static const unsigned char *
read_encoded_value_with_base(unsigned char encoding, _Unwind_Ptr base,
        const unsigned char *p, _Unwind_Ptr *val)
{
    union unaligned
    {
        void *ptr;
        unsigned u2 __attribute__ ((mode (HI)));
        unsigned u4 __attribute__ ((mode (SI)));
        unsigned u8 __attribute__ ((mode (DI)));
        signed s2 __attribute__ ((mode (HI)));
        signed s4 __attribute__ ((mode (SI)));
        signed s8 __attribute__ ((mode (DI)));
    } __attribute__((__packed__));

    const union unaligned *u = (const union unaligned *) p;
    _Unwind_Internal_Ptr result;

    if (encoding == DW_EH_PE_aligned)
    {
        _Unwind_Internal_Ptr a = (_Unwind_Internal_Ptr) p;
        a = (a + sizeof (void *) - 1) & - sizeof(void *);
        result = *(_Unwind_Internal_Ptr *) a;
        p = (const unsigned char *) (_Unwind_Internal_Ptr) (a + sizeof (void *));
    }
    else
    {
        switch (encoding & 0x0f)
        {
            case DW_EH_PE_absptr:
                result = (_Unwind_Internal_Ptr) u->ptr;
                p += sizeof (void *);
                break;

            case DW_EH_PE_uleb128:
                {
                    _uleb128_t tmp;
                    p = read_uleb128 (p, &tmp);
                    result = (_Unwind_Internal_Ptr) tmp;
                }
                break;

            case DW_EH_PE_sleb128:
                {
                    _sleb128_t tmp;
                    p = read_sleb128 (p, &tmp);
                    result = (_Unwind_Internal_Ptr) tmp;
                }
                break;

            case DW_EH_PE_udata2:
                result = u->u2;
                p += 2;
                break;
            case DW_EH_PE_udata4:
                result = u->u4;
                p += 4;
                break;
            case DW_EH_PE_udata8:
                result = u->u8;
                p += 8;
                break;

            case DW_EH_PE_sdata2:
                result = u->s2;
                p += 2;
                break;
            case DW_EH_PE_sdata4:
                result = u->s4;
                p += 4;
                break;
            case DW_EH_PE_sdata8:
                result = u->s8;
                p += 8;
                break;
            default:
                assert(0);
        }

        if (result != 0)
        {
            result += ((encoding & 0x70) == DW_EH_PE_pcrel
                    ? (_Unwind_Internal_Ptr) u : base);
            if (encoding & DW_EH_PE_indirect)
                result = *(_Unwind_Internal_Ptr *) result;
        }
    }

    *val = result;
    return p;
}

static inline const unsigned char *
read_encoded_value (struct _Unwind_Context *context, unsigned char encoding,
        const unsigned char *p, _Unwind_Ptr *val)
{
    return read_encoded_value_with_base (encoding,
            base_of_encoded_value (encoding, context), p, val);
}

static const std::type_info*
get_ttype_entry (lsda_header_info *info, _Unwind_Word i)
{
  _Unwind_Ptr ptr;

  i *= size_of_encoded_value (info->ttype_encoding);
  read_encoded_value_with_base (info->ttype_encoding, info->ttype_base,
				info->TType - i, &ptr);

  return reinterpret_cast<const std::type_info *>(ptr);
}

static bool
check_exception_spec(lsda_header_info* info, std::type_info* throw_type,
		       _Unwind_Sword filter_value)
{
  const unsigned char *e = info->TType - filter_value - 1;

  while (1)
    {
      const std::type_info *catch_type;
      _Unwind_Word tmp;

      e = read_uleb128(e, &tmp);

      // Zero signals the end of the list.  If we've not found
      // a match by now, then we've failed the specification.
      if (tmp == 0)
        return false;

      // Match a ttype entry.
      catch_type = get_ttype_entry(info, tmp);

      // ??? There is currently no way to ask the RTTI code about the
      // relationship between two types without reference to a specific
      // object.  There should be; then we wouldn't need to mess with
      // thrown_ptr here.
      if (catch_type->name() == throw_type->name())
          return true;
    }
}
static bool empty_exception_spec (lsda_header_info *info, _Unwind_Sword filter_value)
{
  const unsigned char *e = info->TType - filter_value - 1;
  _Unwind_Word tmp;

  e = read_uleb128 (e, &tmp);
  return tmp == 0;
}

static const unsigned char *
parse_lsda_header (struct _Unwind_Context *context, const unsigned char *p,
        lsda_header_info *info)
{
    _Unwind_Word tmp;
    unsigned char lpstart_encoding;

    info->Start = (context ? _Unwind_GetRegionStart(context) : 0);

    /* Find @LPStart, the base to which landing pad offsets are relative.  */
    lpstart_encoding = *p++;
    if (lpstart_encoding != DW_EH_PE_omit)
        p = read_encoded_value (context, lpstart_encoding, p, &info->LPStart);
    else
        info->LPStart = info->Start;

    /* Find @TType, the base of the handler and exception spec type data.  */
    info->ttype_encoding = *p++;
    if (info->ttype_encoding != DW_EH_PE_omit)
    {
        p = read_uleb128 (p, &tmp);
        info->TType = p + tmp;
    }
    else
        info->TType = 0;

    /* The encoding and length of the call-site table; the action table
       immediately follows.  */
    info->call_site_encoding = *p++;
    p = read_uleb128 (p, &tmp);
    info->action_table = p + tmp;

    return p;
}

extern "C" _Unwind_Reason_Code __gxx_personality_v0(int version,
        _Unwind_Action actions,
        _Unwind_Exception_Class exception_class,
        struct _Unwind_Exception *ue_header,
        struct _Unwind_Context *context)
{
    cout << "personality routine" << endl;

    lsda_header_info info;
    const unsigned char *language_specific_data, *p, *action_record;
    _Unwind_Ptr landing_pad, ip;

    if (version != 1) return _URC_FATAL_PHASE1_ERROR;

    language_specific_data = (const unsigned char *)
        _Unwind_GetLanguageSpecificData (context);

    /* If no LSDA, then there are no handlers or cleanups.  */
    if (!language_specific_data) return _URC_CONTINUE_UNWIND;

    /* Parse the LSDA header.  */
    p = parse_lsda_header (context, language_specific_data, &info);
    ip = _Unwind_GetIP (context) - 1;
    landing_pad = 0;

    __cxa_exception* xh = __get_exception_header_from_ue(ue_header);

    int handler_switch_value = 0;
    int found_type = to_terminate;

    /* Search the call-site table for the action associated with this IP.  */
    while (p < info.action_table)
    {
        _Unwind_Ptr cs_start, cs_len, cs_lp;
        _Unwind_Word cs_action;

        /* Note that all call-site encodings are "absolute" displacements.  */
        p = read_encoded_value (0, info.call_site_encoding, p, &cs_start);
        p = read_encoded_value (0, info.call_site_encoding, p, &cs_len);
        p = read_encoded_value (0, info.call_site_encoding, p, &cs_lp);
        p = read_uleb128 (p, &cs_action);

        /* The table is sorted, so if we've passed the ip, stop.  */
        if (ip < info.Start + cs_start)
        {
            p = info.action_table;
        }
        else if (ip < info.Start + cs_start + cs_len)
        {
            if (cs_lp)
            {
                cout << "find landing pad" << endl;
                landing_pad = info.LPStart + cs_lp;
            }
            if (cs_action)
            {
                cout << "find call site action" << endl;
                action_record = info.action_table + cs_action - 1;
            }
            goto found_something;
        }
    }

    /* IP is not in table.  No associated cleanups.  */
    /* ??? This is where C++ calls std::terminate to catch throw
       from a destructor.  */
    return _URC_CONTINUE_UNWIND;


found_something:
    if (landing_pad == 0)
    {
        /* IP is present, but has a null landing pad.
           No handler to be run.  */
        cout << "no landing pad for current func" << endl;
        found_type = to_do_nothing;
    }
    else if (action_record == 0)
    {
        found_type = to_do_cleanup;
        cout << "find no catch for current function, but need to do cleanup" << endl;
    }
    else
    {
        // Otherwise we have a catch handler or exception specification.

        _Unwind_Sword ar_filter, ar_disp;
        const std::type_info* catch_type;
        bool saw_cleanup = false;
        bool saw_handler = false;

        // During forced unwinding, we only run cleanups.  With a foreign
        // exception class, there's no exception type.
        // ??? What to do about GNU Java and GNU Ada exceptions.

        std::type_info* throw_type = xh->exceptionType;

        while (1)
        {
            p = action_record;
            p = read_sleb128 (p, &ar_filter);
            read_sleb128 (p, &ar_disp);

            if (ar_filter == 0)
            {
                // Zero filter values are cleanups.
                saw_cleanup = true;
            }
            else if (ar_filter > 0)
            {
                // Positive filter values are handlers.
                catch_type = get_ttype_entry (&info, ar_filter);

                // Null catch type is a catch-all handler; we can catch foreign
                // exceptions with this.  Otherwise we must match types.
                if (!catch_type || (throw_type && throw_type->name() == catch_type->name()))
                {
                    saw_handler = true;
                    break;
                }
            }
            else
            {
                // Negative filter values are exception specifications.
                // ??? How do foreign exceptions fit in?  As far as I can
                // see we can't match because there's no __cxa_exception
                // object to stuff bits in for __cxa_call_unexpected to use.
                // Allow them iff the exception spec is non-empty.  I.e.
                // a throw() specification results in __unexpected.
                if (throw_type
                        ? !check_exception_spec(&info, throw_type, ar_filter)
                        : empty_exception_spec(&info, ar_filter))
                {
                    saw_handler = true;
                    break;
                }
            }

            if (ar_disp == 0)
                break;
            action_record = p + ar_disp;
        }

        if (saw_handler)
        {
            handler_switch_value = ar_filter;
            found_type = to_do_handler;
        }
        else
        {
            found_type = (saw_cleanup ? to_do_cleanup : to_do_nothing);
        }
    }

    if (found_type == to_do_nothing)
        return _URC_CONTINUE_UNWIND;

    if (actions & _UA_SEARCH_PHASE)
    {
        if (found_type == to_do_cleanup)
            return _URC_CONTINUE_UNWIND;

        return _URC_HANDLER_FOUND;
    }

    if (found_type == to_terminate)
    {
        std::terminate();
    }

    if (handler_switch_value < 0)
    {
        parse_lsda_header(context, language_specific_data, &info);
        xh->catchTemp = base_of_encoded_value(info.ttype_encoding, context);
    }

    _Unwind_SetGR (context, __builtin_eh_return_data_regno(0),
            __builtin_extend_pointer(ue_header));
    _Unwind_SetGR (context, __builtin_eh_return_data_regno(1), handler_switch_value);
    _Unwind_SetIP (context, landing_pad);
    return _URC_INSTALL_CONTEXT;
}

