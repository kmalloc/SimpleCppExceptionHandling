#ifndef CXX_EXCEPT_ABI_H_
#define CXX_EXCEPT_ABI_H_

#include <typeinfo>
#include <cstddef>
#include <unwind.h>

namespace __cxxabiv2
{
    struct __cxa_exception
    {
        // Manage the exception object itself.
        std::type_info *exceptionType;
        void (*exceptionDestructor)(void *);

        // The C++ standard has entertaining rules wrt calling set_terminate
        // and set_unexpected in the middle of the exception cleanup process.
        std::unexpected_handler unexpectedHandler;
        std::terminate_handler terminateHandler;

        // The caught exception stack threads through here.
        __cxa_exception *nextException;

        // How many nested handlers have caught this exception.  A negated
        // value is a signal that this object has been rethrown.
        int handlerCount;

        // Cache parsed handler data from the personality routine Phase 1
        // for Phase 2 and __cxa_call_unexpected.
        int handlerSwitchValue;
        const unsigned char *actionRecord;
        const unsigned char *languageSpecificData;
        _Unwind_Ptr catchTemp;
        void *adjustedPtr;

        // The generic exception header.  Must be last.
        _Unwind_Exception unwindHeader;
    };

    // Allocate memory for the exception plus the thown object.
    extern "C" void *__cxa_allocate_exception(std::size_t thrown_size) throw();

    // Free the space allocated for the exception.
    extern "C" void __cxa_free_exception(void *thrown_exception) throw();

    // Throw the exception.
    extern "C" void __cxa_throw (void *thrown_exception,
            std::type_info *tinfo,
            void (*dest) (void *))
        __attribute__((noreturn));

    // Used to implement exception handlers.
    extern "C" void *__cxa_get_exception_ptr (void *) throw();
    extern "C" void *__cxa_begin_catch (void *) throw();
    extern "C" void __cxa_end_catch ();
    extern "C" void __cxa_rethrow () __attribute__((noreturn));
}

#endif

