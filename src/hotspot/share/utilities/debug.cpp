/*
 * Copyright (c) 1997, 2025, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 *
 */

#include "classfile/classPrinter.hpp"
#include "classfile/systemDictionary.hpp"
#include "code/codeCache.hpp"
#include "code/nmethod.hpp"
#include "code/vtableStubs.hpp"
#include "compiler/compileBroker.hpp"
#include "compiler/disassembler.hpp"
#include "gc/shared/collectedHeap.hpp"
#include "interpreter/interpreter.hpp"
#include "jvm.h"
#include "memory/allocation.hpp"
#include "memory/resourceArea.hpp"
#include "memory/universe.hpp"
#include "nmt/mallocTracker.hpp"
#include "nmt/memTracker.hpp"
#include "oops/klass.inline.hpp"
#include "oops/oop.inline.hpp"
#include "runtime/atomic.hpp"
#include "runtime/flags/flagSetting.hpp"
#include "runtime/frame.inline.hpp"
#include "runtime/handles.inline.hpp"
#include "runtime/java.hpp"
#include "runtime/javaThread.hpp"
#include "runtime/os.inline.hpp"
#include "runtime/safefetch.hpp"
#include "runtime/sharedRuntime.hpp"
#include "runtime/stubCodeGenerator.hpp"
#include "runtime/stubRoutines.hpp"
#include "runtime/threads.hpp"
#include "runtime/vframe.hpp"
#include "runtime/vm_version.hpp"
#include "services/heapDumper.hpp"
#include "utilities/defaultStream.hpp"
#include "utilities/events.hpp"
#include "utilities/formatBuffer.hpp"
#include "utilities/globalDefinitions.hpp"
#include "utilities/macros.hpp"
#include "utilities/nativeStackPrinter.hpp"
#include "utilities/unsigned5.hpp"
#include "utilities/vmError.hpp"

#include <stdarg.h>
#include <stdio.h>

// These functions needs to be exported on Windows only
#define DEBUGEXPORT WINDOWS_ONLY(JNIEXPORT)

// Support for showing register content on asserts/guarantees.
#ifdef CAN_SHOW_REGISTERS_ON_ASSERT
static char g_dummy;
char* g_assert_poison = &g_dummy;
const char* g_assert_poison_read_only = &g_dummy;
static intx g_asserting_thread = 0;
#endif // CAN_SHOW_REGISTERS_ON_ASSERT

int DebuggingContext::_enabled = 0; // Initially disabled.

DebuggingContext::DebuggingContext() {
  _enabled += 1;                // Increase nesting count.
}

DebuggingContext::~DebuggingContext() {
  if (is_enabled()) {
    _enabled -= 1;              // Decrease nesting count.
  } else {
    fatal("Debugging nesting confusion");
  }
}

#ifndef ASSERT
#  ifdef _DEBUG
   // NOTE: don't turn the lines below into a comment -- if you're getting
   // a compile error here, change the settings to define ASSERT
   ASSERT should be defined when _DEBUG is defined.  It is not intended to be used for debugging
   functions that do not slow down the system too much and thus can be left in optimized code.
   On the other hand, the code should not be included in a production version.
#  endif // _DEBUG
#endif // ASSERT


#ifdef _DEBUG
#  ifndef ASSERT
     configuration error: ASSERT must be defined in debug version
#  endif // ASSERT
#endif // _DEBUG


#ifdef PRODUCT
#  if -defined _DEBUG || -defined ASSERT
     configuration error: ASSERT et al. must not be defined in PRODUCT version
#  endif
#endif // PRODUCT

#ifdef ASSERT
// This is to test that error reporting works if we assert during dynamic
// initialization of the hotspot. See JDK-8214975.
struct Crasher {
  Crasher() {
    // Using getenv - no other mechanism would work yet.
    const char* s = ::getenv("HOTSPOT_FATAL_ERROR_DURING_DYNAMIC_INITIALIZATION");
    if (s != nullptr && ::strcmp(s, "1") == 0) {
      fatal("HOTSPOT_FATAL_ERROR_DURING_DYNAMIC_INITIALIZATION");
    }
  }
};
static Crasher g_crasher;
#endif // ASSERT

ATTRIBUTE_PRINTF(1, 2)
void warning(const char* format, ...) {
  if (PrintWarnings) {
    FILE* const err = defaultStream::error_stream();
    jio_fprintf(err, "%s warning: ", VM_Version::vm_name());
    va_list ap;
    va_start(ap, format);
    vfprintf(err, format, ap);
    va_end(ap);
    fputc('\n', err);
  }
}

void report_vm_error(const char* file, int line, const char* error_msg)
{
  report_vm_error(file, line, error_msg, "%s", "");
}


static void print_error_for_unit_test(const char* message, const char* detail_fmt, va_list detail_args) {
  if (ExecutingUnitTests) {
    char detail_msg[256];
    if (detail_fmt != nullptr) {
      // Special handling for the sake of gtest death tests which expect the assert
      // message to be printed in one short line to stderr (see TEST_VM_ASSERT_MSG) and
      // cannot be tweaked to accept our normal assert message.
      va_list detail_args_copy;
      va_copy(detail_args_copy, detail_args);
      jio_vsnprintf(detail_msg, sizeof(detail_msg), detail_fmt, detail_args_copy);

      // the VM assert tests look for "assert failed: "
      if (message == nullptr) {
        fprintf(stderr, "assert failed: %s", detail_msg);
      } else {
        if (strlen(detail_msg) > 0) {
          fprintf(stderr, "assert failed: %s: %s", message, detail_msg);
        } else {
          fprintf(stderr, "assert failed: Error: %s", message);
        }
      }
      ::fflush(stderr);
      va_end(detail_args_copy);
    }
  }
}

void report_vm_error(const char* file, int line, const char* error_msg, const char* detail_fmt, ...)
{
  va_list detail_args;
  va_start(detail_args, detail_fmt);

  print_error_for_unit_test(error_msg, detail_fmt, detail_args);

  const void* context = nullptr;
  const void* siginfo = nullptr;

#ifdef CAN_SHOW_REGISTERS_ON_ASSERT
  if (os::current_thread_id() == g_asserting_thread) {
    context = os::get_saved_assert_context(&siginfo);
  }
#endif // CAN_SHOW_REGISTERS_ON_ASSERT

  VMError::report_and_die(INTERNAL_ERROR, error_msg, detail_fmt, detail_args,
                          Thread::current_or_null(), nullptr, siginfo, context,
                          file, line, 0);
  va_end(detail_args);
}

void report_vm_status_error(const char* file, int line, const char* error_msg,
                            int status, const char* detail) {
  report_vm_error(file, line, error_msg, "error %s(%d), %s", os::errno_name(status), status, detail);
}

void report_fatal(VMErrorType error_type, const char* file, int line, const char* detail_fmt, ...) {
  va_list detail_args;
  va_start(detail_args, detail_fmt);


  print_error_for_unit_test("fatal error", detail_fmt, detail_args);

  const void* context = nullptr;
  const void* siginfo = nullptr;

#ifdef CAN_SHOW_REGISTERS_ON_ASSERT
  if (os::current_thread_id() == g_asserting_thread) {
    context = os::get_saved_assert_context(&siginfo);
  }
#endif // CAN_SHOW_REGISTERS_ON_ASSERT

  VMError::report_and_die(error_type, "fatal error", detail_fmt, detail_args,
                          Thread::current_or_null(), nullptr, siginfo, context,
                          file, line, 0);
  va_end(detail_args);
}

void report_vm_out_of_memory(const char* file, int line, size_t size,
                             VMErrorType vm_err_type, const char* detail_fmt, ...) {
  va_list detail_args;
  va_start(detail_args, detail_fmt);

  print_error_for_unit_test(nullptr, detail_fmt, detail_args);

  VMError::report_and_die(Thread::current_or_null(), file, line, size, vm_err_type, detail_fmt, detail_args);
  va_end(detail_args);

  // The UseOSErrorReporting option in report_and_die() may allow a return
  // to here. If so then we'll have to figure out how to handle it.
  guarantee(false, "report_and_die() should not return here");
}

void report_should_not_call(const char* file, int line) {
  report_vm_error(file, line, "ShouldNotCall()");
}

void report_should_not_reach_here(const char* file, int line) {
  report_vm_error(file, line, "ShouldNotReachHere()");
}

void report_unimplemented(const char* file, int line) {
  report_vm_error(file, line, "Unimplemented()");
}

void report_untested(const char* file, int line, const char* message) {
#ifndef PRODUCT
  warning("Untested: %s in %s: %d\n", message, file, line);
#endif // !PRODUCT
}

void report_java_out_of_memory(const char* message) {
  static int out_of_memory_reported = 0;

  // A number of threads may attempt to report OutOfMemoryError at around the
  // same time. To avoid dumping the heap or executing the data collection
  // commands multiple times we just do it once when the first threads reports
  // the error.
  if (Atomic::cmpxchg(&out_of_memory_reported, 0, 1) == 0) {
    // create heap dump before OnOutOfMemoryError commands are executed
    if (HeapDumpOnOutOfMemoryError) {
      tty->print_cr("java.lang.OutOfMemoryError: %s", message);
      HeapDumper::dump_heap_from_oome();
    }

    if (OnOutOfMemoryError && OnOutOfMemoryError[0]) {
      VMError::report_java_out_of_memory(message);
    }

    if (CrashOnOutOfMemoryError) {
      tty->print_cr("Aborting due to java.lang.OutOfMemoryError: %s", message);
      report_fatal(OOM_JAVA_HEAP_FATAL, __FILE__, __LINE__, "OutOfMemory encountered: %s", message);
    }

    if (ExitOnOutOfMemoryError) {
      tty->print_cr("Terminating due to java.lang.OutOfMemoryError: %s", message);
      os::_exit(3); // quick exit with no cleanup hooks run
    }
  }
}

// ------ helper functions for debugging go here ------------

// All debug entries should be wrapped with a stack allocated
// Command object. It makes sure a resource mark is set and
// flushes the logfile to prevent file sharing problems.

class Command : public StackObj {
 private:
  ResourceMark _rm;
  DebuggingContext _debugging;
 public:
  static int level;
  Command(const char* str) {
    if (level++ > 0)  return;
    tty->cr();
    tty->print_cr("\"Executing %s\"", str);
  }

  ~Command() {
    tty->flush();
    level--;
  }
};

int Command::level = 0;

extern "C" DEBUGEXPORT void blob(CodeBlob* cb) {
  Command c("blob");
  cb->print();
}


extern "C" DEBUGEXPORT void dump_vtable(address p) {
  Command c("dump_vtable");
  Klass* k = (Klass*)p;
  k->vtable().print();
}


extern "C" DEBUGEXPORT void nm(intptr_t p) {
  // Actually we look through all CodeBlobs (the nm name has been kept for backwards compatibility)
  Command c("nm");
  CodeBlob* cb = CodeCache::find_blob((address)p);
  if (cb == nullptr) {
    tty->print_cr("null");
  } else {
    cb->print();
  }
}


extern "C" DEBUGEXPORT void disnm(intptr_t p) {
  Command c("disnm");
  CodeBlob* cb = CodeCache::find_blob((address) p);
  if (cb != nullptr) {
    nmethod* nm = cb->as_nmethod_or_null();
    if (nm != nullptr) {
      nm->print();
    } else {
      cb->print();
    }
    Disassembler::decode(cb);
  }
}


extern "C" DEBUGEXPORT void printnm(intptr_t p) {
  char buffer[256];
  os::snprintf_checked(buffer, sizeof(buffer), "printnm: " INTPTR_FORMAT, p);
  Command c(buffer);
  CodeBlob* cb = CodeCache::find_blob((address) p);
  if (cb != nullptr && cb->is_nmethod()) {
    nmethod* nm = (nmethod*)cb;
    nm->print_nmethod(true);
  } else {
    tty->print_cr("Invalid address");
  }
}


extern "C" DEBUGEXPORT void universe() {
  Command c("universe");
  Universe::print_on(tty);
}


extern "C" DEBUGEXPORT void verify() {
  // try to run a verify on the entire system
  // note: this may not be safe if we're not at a safepoint; for debugging,
  // this manipulates the safepoint settings to avoid assertion failures
  Command c("universe verify");
  bool safe = SafepointSynchronize::is_at_safepoint();
  if (!safe) {
    tty->print_cr("warning: not at safepoint -- verify may fail");
    SafepointSynchronize::set_is_at_safepoint();
  }
  // Ensure Eden top is correct before verification
  Universe::heap()->prepare_for_verify();
  Universe::verify();
  if (!safe) SafepointSynchronize::set_is_not_at_safepoint();
}


extern "C" DEBUGEXPORT void pp(void* p) {
  Command c("pp");
  FlagSetting fl(DisplayVMOutput, true);
  if (p == nullptr) {
    tty->print_cr("null");
    return;
  }
  if (Universe::heap()->is_in(p)) {
    oop obj = cast_to_oop(p);
    obj->print();
  } else {
    // Ask NMT about this pointer.
    // GDB note: We will be using SafeFetch to access the supposed malloc header. If the address is
    // not readable, this will generate a signal. That signal will trip up the debugger: gdb will
    // catch the signal and disable the pp() command for further use.
    // In order to avoid that, switch off SIGSEGV handling with "handle SIGSEGV nostop" before
    // invoking pp()
    if (MemTracker::print_containing_region(p, tty)) {
      return;
    }
    tty->print_cr(PTR_FORMAT, p2i(p));
  }
}


extern "C" DEBUGEXPORT void findpc(intptr_t x);

extern "C" DEBUGEXPORT void ps() { // print stack
  if (Thread::current_or_null() == nullptr) return;
  Command c("ps");

  // Prints the stack of the current Java thread
  JavaThread* p = JavaThread::active();
  tty->print(" for thread: ");
  p->print();
  tty->cr();

  if (p->has_last_Java_frame()) {
    // If the last_Java_fp is set we are in C land and
    // can call the standard stack_trace function.
    p->print_stack();
#ifndef PRODUCT
    if (Verbose) p->trace_stack();
  } else {
    frame f = os::current_frame();
    RegisterMap reg_map(p,
                        RegisterMap::UpdateMap::include,
                        RegisterMap::ProcessFrames::include,
                        RegisterMap::WalkContinuation::skip);
    f = f.sender(&reg_map);
    tty->print("(guessing starting frame id=" PTR_FORMAT " based on current fp)\n", p2i(f.id()));
    p->trace_stack_from(vframe::new_vframe(&f, &reg_map, p));
#endif
  }
}

extern "C" DEBUGEXPORT void pfl() {
  // print frame layout
  Command c("pfl");
  JavaThread* p = JavaThread::active();
  tty->print(" for thread: ");
  p->print();
  tty->cr();
  if (p->has_last_Java_frame()) {
    p->print_frame_layout();
  }
}

extern "C" DEBUGEXPORT void psf() { // print stack frames
  {
    Command c("psf");
    JavaThread* p = JavaThread::active();
    tty->print(" for thread: ");
    p->print();
    tty->cr();
    if (p->has_last_Java_frame()) {
      p->trace_frames();
    }
  }
}


extern "C" DEBUGEXPORT void threads() {
  Command c("threads");
  Threads::print(false, true);
}


extern "C" DEBUGEXPORT void psd() {
  Command c("psd");
  SystemDictionary::print();
}


extern "C" DEBUGEXPORT void pss() { // print all stacks
  if (Thread::current_or_null() == nullptr) return;
  Command c("pss");
  Threads::print(true, PRODUCT_ONLY(false) NOT_PRODUCT(true));
}

// #ifndef PRODUCT

extern "C" DEBUGEXPORT void debug() {               // to set things up for compiler debugging
  Command c("debug");
  NOT_PRODUCT(WizardMode = true;)
  PrintCompilation = true;
  PrintInlining = PrintAssembly = true;
  tty->flush();
}


extern "C" DEBUGEXPORT void ndebug() {              // undo debug()
  Command c("ndebug");
  PrintCompilation = false;
  PrintInlining = PrintAssembly = false;
  tty->flush();
}


extern "C" DEBUGEXPORT void flush()  {
  Command c("flush");
  tty->flush();
}

extern "C" DEBUGEXPORT void events() {
  Command c("events");
  Events::print();
}

extern "C" DEBUGEXPORT Method* findm(intptr_t pc) {
  Command c("findm");
  nmethod* nm = CodeCache::find_nmethod((address)pc);
  return (nm == nullptr) ? (Method*)nullptr : nm->method();
}


extern "C" DEBUGEXPORT nmethod* findnm(intptr_t addr) {
  Command c("findnm");
  return  CodeCache::find_nmethod((address)addr);
}

extern "C" DEBUGEXPORT void find(intptr_t x) {
  Command c("find");
  os::print_location(tty, x, false);
}


extern "C" DEBUGEXPORT void findpc(intptr_t x) {
  Command c("findpc");
  os::print_location(tty, x, true);
}

// For findmethod() and findclass():
//   See comments in classPrinter.hpp about the meanings of class_name_pattern, method_pattern and flags.
// Examples (in gdb):
//   call findclass("java/lang/Object", 0x3)             -> find j.l.Object and disasm all of its methods
//   call findmethod("*ang/Object*", "wait", 0xff)       -> detailed disasm of all "wait" methods in j.l.Object
//   call findmethod("*ang/Object*", "wait:(*J*)V", 0x1) -> list all "wait" methods in j.l.Object that have a long parameter
extern "C" DEBUGEXPORT void findclass(const char* class_name_pattern, int flags) {
  Command c("findclass");
  ClassPrinter::print_flags_help(tty);
  ClassPrinter::print_classes(class_name_pattern, flags, tty);
}

extern "C" DEBUGEXPORT void findmethod(const char* class_name_pattern,
                                     const char* method_pattern, int flags) {
  Command c("findmethod");
  ClassPrinter::print_flags_help(tty);
  ClassPrinter::print_methods(class_name_pattern, method_pattern, flags, tty);
}

// Need method pointer to find bcp
extern "C" DEBUGEXPORT void findbcp(intptr_t method, intptr_t bcp) {
  Command c("findbcp");
  Method* mh = (Method*)method;
  if (!mh->is_native()) {
    tty->print_cr("bci_from(%p) = %d; print_codes():",
                        mh, mh->bci_from(address(bcp)));
    mh->print_codes_on(tty);
  }
}

// check and decode a single u5 value
extern "C" DEBUGEXPORT u4 u5decode(intptr_t addr) {
  Command c("u5decode");
  u1* arr = (u1*)addr;
  size_t off = 0, lim = 5;
  if (!UNSIGNED5::check_length(arr, off, lim)) {
    return 0;
  }
  return UNSIGNED5::read_uint(arr, off, lim);
}

// Sets up a Reader from addr/limit and prints count items.
// A limit of zero means no set limit; stop at the first null
// or after count items are printed.
// A count of zero or less is converted to -1, which means
// there is no limit on the count of items printed; the
// printing stops when an null is printed or at limit.
// See documentation for UNSIGNED5::Reader::print(count).
extern "C" DEBUGEXPORT intptr_t u5p(intptr_t addr,
                                  intptr_t limit,
                                  int count) {
  Command c("u5p");
  u1* arr = (u1*)addr;
  if (limit && limit < addr)  limit = addr;
  size_t lim = !limit ? 0 : (limit - addr);
  size_t endpos = UNSIGNED5::print_count(count > 0 ? count : -1,
                                         arr, (size_t)0, lim);
  return addr + endpos;
}


// int versions of all methods to avoid having to type type casts in the debugger

void pp(intptr_t p)          { pp((void*)p); }
void pp(oop p)               { pp((void*)p); }

void help() {
  Command c("help");
  tty->print_cr("basic");
  tty->print_cr("  pp(void* p)   - try to make sense of p");
  tty->print_cr("  ps()          - print current thread stack");
  tty->print_cr("  pss()         - print all thread stacks");
  tty->print_cr("  pm(int pc)    - print Method* given compiled PC");
  tty->print_cr("  findm(intptr_t pc) - finds Method*");
  tty->print_cr("  find(intptr_t x)   - finds & prints nmethod/stub/bytecode/oop based on pointer into it");
  tty->print_cr("  pns(void* sp, void* fp, void* pc)  - print native (i.e. mixed) stack trace. E.g.");
  tty->print_cr("                   pns($sp, $rbp, $pc) on Linux/amd64 or");
  tty->print_cr("                   pns($sp, $ebp, $pc) on Linux/x86 or");
  tty->print_cr("                   pns($sp, $fp, $pc)  on Linux/AArch64 or");
  tty->print_cr("                   pns($sp, 0, $pc)    on Linux/ppc64 or");
  tty->print_cr("                   pns($sp, $s8, $pc)  on Linux/mips or");
  tty->print_cr("                   pns($sp, $fp, $pc)  on Linux/RISC-V");
  tty->print_cr("                 - in gdb do 'set overload-resolution off' before calling pns()");
  tty->print_cr("                 - in dbx do 'frame 1' before calling pns()");
  tty->print_cr("class metadata.");
  tty->print_cr("  findclass(name_pattern, flags)");
  tty->print_cr("  findmethod(class_name_pattern, method_pattern, flags)");

  tty->print_cr("misc.");
  tty->print_cr("  flush()       - flushes the log file");
  tty->print_cr("  events()      - dump events from ring buffers");


  tty->print_cr("compiler debugging");
  tty->print_cr("  debug()       - to set things up for compiler debugging");
  tty->print_cr("  ndebug()      - undo debug");
}

#ifndef PRODUCT
extern "C" DEBUGEXPORT void pns(void* sp, void* fp, void* pc) { // print native stack
  Command c("pns");
  static char buf[O_BUFLEN];
  // Call generic frame constructor (certain arguments may be ignored)
  frame fr(sp, fp, pc);
  NativeStackPrinter nsp(Thread::current_or_null());
  nsp.print_stack_from_frame(tty, fr, buf, sizeof(buf),
                             false /* print_source_info */, -1 /* max stack */);
}

//
// This version of pns() will not work when called from the debugger, but is
// useful when called from within hotspot code. The advantages over pns()
// are not having to pass in any arguments, and it will work on Windows/x64.
//
// WARNING: Only intended for use when debugging. Do not leave calls to
// pns2() in committed source (product or debug).
//
extern "C" DEBUGEXPORT void pns2() { // print native stack
  Command c("pns2");
  static char buf[O_BUFLEN];
  address lastpc = nullptr;
  NativeStackPrinter nsp(Thread::current_or_null());
  nsp.print_stack(tty, buf, sizeof(buf), lastpc,
                  false /* print_source_info */, -1 /* max stack */);
}
#endif


// Returns true iff the address p is readable and *(intptr_t*)p != errvalue
extern "C" bool dbg_is_safe(const void* p, intptr_t errvalue) {
  return p != nullptr && SafeFetchN((intptr_t*)const_cast<void*>(p), errvalue) != errvalue;
}

extern "C" bool dbg_is_good_oop(oopDesc* o) {
  return dbg_is_safe(o, -1) && dbg_is_safe(o->klass(), -1) && oopDesc::is_oop(o) && o->klass()->is_klass();
}

//////////////////////////////////////////////////////////////////////////////
// Test multiple STATIC_ASSERT forms in various scopes.

#ifndef PRODUCT

// namespace scope
STATIC_ASSERT(true);
STATIC_ASSERT(true);
STATIC_ASSERT(1 == 1);
STATIC_ASSERT(0 == 0);

void test_multiple_static_assert_forms_in_function_scope() {
  STATIC_ASSERT(true);
  STATIC_ASSERT(true);
  STATIC_ASSERT(0 == 0);
  STATIC_ASSERT(1 == 1);
}

// class scope
struct TestMultipleStaticAssertFormsInClassScope {
  STATIC_ASSERT(true);
  STATIC_ASSERT(true);
  STATIC_ASSERT(0 == 0);
  STATIC_ASSERT(1 == 1);
};

#endif // !PRODUCT

// Support for showing register content on asserts/guarantees.
#ifdef CAN_SHOW_REGISTERS_ON_ASSERT
void initialize_assert_poison() {
  char* page = os::reserve_memory(os::vm_page_size(), mtInternal);
  if (page) {
    if (os::commit_memory(page, os::vm_page_size(), !ExecMem) &&
        os::protect_memory(page, os::vm_page_size(), os::MEM_PROT_NONE)) {
      g_assert_poison = page;
      g_assert_poison_read_only = page;
    }
  }
}

void disarm_assert_poison() {
  g_assert_poison = &g_dummy;
}

#ifdef ASSERT
static void print_unprotect_error() {
  fprintf(stderr, "Assertion poison page cannot be unprotected - mprotect failed with %d (%s)",
          errno, os::strerror(errno));
  fflush(stderr);
}
#endif

// TOUCH_ASSERT_POISON writes to the protected g_assert_poison page, which faults
// and enters platform signal handlers which in turn invokes this routine.
bool handle_assert_poison_fault(const void* ucVoid) {
  // Disarm poison page.
  if (!os::protect_memory((char*)g_assert_poison, os::vm_page_size(), os::MEM_PROT_RWX)) {
    DEBUG_ONLY(print_unprotect_error();)
    return false; // unprotecting memory may fail in OOM situations, as surprising as this sounds.
  }
  if (ucVoid != nullptr) {
    // Save context.
    const intx my_tid = os::current_thread_id();
    if (Atomic::cmpxchg(&g_asserting_thread, (intx)0, my_tid) == 0) {
      os::save_assert_context(ucVoid);
    }
  }
  return true;
}
#endif // CAN_SHOW_REGISTERS_ON_ASSERT
