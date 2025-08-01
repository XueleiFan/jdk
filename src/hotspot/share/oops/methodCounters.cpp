/*
 * Copyright (c) 2013, 2025, Oracle and/or its affiliates. All rights reserved.
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

#include "cds/cdsConfig.hpp"
#include "compiler/compiler_globals.hpp"
#include "compiler/compilerOracle.hpp"
#include "memory/metaspaceClosure.hpp"
#include "memory/resourceArea.hpp"
#include "oops/method.hpp"
#include "oops/methodCounters.hpp"
#include "oops/trainingData.hpp"
#include "runtime/handles.inline.hpp"

MethodCounters::MethodCounters(const methodHandle& mh) :
  _method(mh()),
  _method_training_data(method_training_data_sentinel()),
  _prev_time(0),
  _rate(0),
  _highest_comp_level(0),
  _highest_osr_comp_level(0)
{
  set_interpreter_throwout_count(0);
  JVMTI_ONLY(clear_number_of_breakpoints());
  invocation_counter()->init();
  backedge_counter()->init();

  // Set per-method thresholds.
  double scale = 1.0;
  CompilerOracle::has_option_value(mh, CompileCommandEnum::CompileThresholdScaling, scale);

  _invoke_mask = right_n_bits(CompilerConfig::scaled_freq_log(Tier0InvokeNotifyFreqLog, scale)) << InvocationCounter::count_shift;
  _backedge_mask = right_n_bits(CompilerConfig::scaled_freq_log(Tier0BackedgeNotifyFreqLog, scale)) << InvocationCounter::count_shift;
}

#if INCLUDE_CDS
MethodCounters::MethodCounters() {
  // Used by cppVtables.cpp only
  assert(CDSConfig::is_dumping_static_archive() || UseSharedSpaces, "only for CDS");
}
#endif

MethodCounters* MethodCounters::allocate_no_exception(const methodHandle& mh) {
  ClassLoaderData* loader_data = mh->method_holder()->class_loader_data();
  return new(loader_data, method_counters_size(), MetaspaceObj::MethodCountersType) MethodCounters(mh);
}

MethodCounters* MethodCounters::allocate_with_exception(const methodHandle& mh, TRAPS) {
  ClassLoaderData* loader_data = mh->method_holder()->class_loader_data();
  return new(loader_data, method_counters_size(), MetaspaceObj::MethodCountersType, THREAD) MethodCounters(mh);
}

void MethodCounters::clear_counters() {
  invocation_counter()->reset();
  backedge_counter()->reset();
  set_interpreter_throwout_count(0);
  set_prev_time(0);
  set_prev_event_count(0);
  set_rate(0);
  set_highest_comp_level(0);
  set_highest_osr_comp_level(0);
}

void MethodCounters::metaspace_pointers_do(MetaspaceClosure* it) {
  log_trace(aot, training)("Iter(MethodCounters): %p", this);
  it->push(&_method);
  it->push(&_method_training_data);
}

#if INCLUDE_CDS
void MethodCounters::remove_unshareable_info() {
}
void MethodCounters::restore_unshareable_info(TRAPS) {
  _method_training_data = method_training_data_sentinel();
}
#endif // INCLUDE_CDS

void MethodCounters::print_on(outputStream* st) const {
  assert(is_methodCounters(), "should be method counters");
  st->print("method counters");
  print_data_on(st);
}

void MethodCounters::print_data_on(outputStream* st) const {
  ResourceMark rm;
  st->print_cr("  - invocation_counter: %d carry=%d", _invocation_counter.count(), _invocation_counter.carry());
  st->print_cr("  - backedge_counter: %d carry=%d",   _backedge_counter.count(), _backedge_counter.carry());
  st->print_cr("  - prev_time: " JLONG_FORMAT,        _prev_time);
  st->print_cr("  - rate: %.3f",             _rate);
  st->print_cr("  - invoke_mask: %d",        _invoke_mask);
  st->print_cr("  - backedge_mask: %d",      _backedge_mask);
  st->print_cr("  - prev_event_count: %d",   _prev_event_count);
#if COMPILER2_OR_JVMCI
  st->print_cr("  - interpreter_throwout_count: %u", _interpreter_throwout_count);
#endif
#if INCLUDE_JVMTI
  st->print_cr("  - number_of_breakpoints: %u", _number_of_breakpoints);
#endif
  st->print_cr("  - highest_comp_level: %u", _highest_comp_level);
  st->print_cr("  - highest_osr_comp_level: %u", _highest_osr_comp_level);
}

void MethodCounters::print_value_on(outputStream* st) const {
  assert(is_methodCounters(), "must be methodCounters");
  st->print("method counters");
  print_address_on(st);
}


