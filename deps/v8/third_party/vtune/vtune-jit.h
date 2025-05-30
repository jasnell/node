/*
   This file is provided under a dual BSD/GPLv2 license.  When using or
   redistributing this file, you may do so under either license.

   Contact Information:
   http://software.intel.com/en-us/articles/intel-vtune-amplifier-xe/

   BSD LICENSE

   Copyright(c) 2005-2012 Intel Corporation. All rights reserved.
   All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:

     * Redistributions of source code must retain the above copyright
       notice, this list of conditions and the following disclaimer.
     * Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in
       the documentation and/or other materials provided with the
       distribution.
     * Neither the name of Intel Corporation nor the names of its
       contributors may be used to endorse or promote products derived
       from this software without specific prior written permission.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef VTUNE_VTUNE_JIT_H_
#define VTUNE_VTUNE_JIT_H_

#include "third_party/ittapi/include/jitprofiling.h"

#define VTUNERUNNING (iJIT_IsProfilingActive() == iJIT_SAMPLING_ON)

namespace v8 {
struct JitCodeEvent;
}

namespace vTune {
namespace internal {
using namespace v8;
class VTUNEJITInterface {
 public:
  static void event_handler(const v8::JitCodeEvent* event);

 private:
  //static Mutex* vtunemutex_;
};


} }  // namespace vTune::internal


#endif  // VTUNE_VTUNE_JIT_H_

