#pragma once
// Original Work copyright (c) Oleksandr Tkachenko
// Modified Work copyright (x) 2021 Microsoft Research
// \author Oleksandr Tkachenko
// \email tkachenko@encrypto.cs.tu-darmstadt.de
// \organization Cryptography and Privacy Engineering Group (ENCRYPTO)
// \TU Darmstadt, Computer Science department
//
// \copyright The MIT License. Copyright Oleksandr Tkachenko
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the Software
// is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
// INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR
// A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
// OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// Modified by Akash Shah

#include <memory>
#include <string>
#include "EzPC/SCI/src/OT/emp-ot.h"
#include "EzPC/SCI/src/utils/emp-tool.h"
#include "abycore/aby/abyparty.h"
#include "helpers.h"
#include "ots/block_op_ots.h"
#include "psi_analytics_context.h"
#include "socket.h"

#define ceil_divide(x, y) ((((x) + (y)-1) / (y)))

#include <vector>

#define C_CONST 8459320670953116686
#define S_CONST 18286333650295995643

namespace RELAXEDNS {
// Run relaxed OPPRF protocol
void run_relaxed_opprf(std::vector<std::vector<std::uint64_t>> &sub_bins, ENCRYPTO::PsiAnalyticsContext &context,
                       const std::vector<std::uint64_t> &inputs, std::vector<std::unique_ptr<CSocket>> &allsocks,
                       std::vector<osuCrypto::Channel> &chls);

// Run OPPRF protocol for threshold PSI
void run_threshold_relaxed_opprf(std::vector<std::vector<std::uint8_t>> &sub_bins,
                                 ENCRYPTO::PsiAnalyticsContext &context, const std::vector<std::uint64_t> &inputs,
                                 std::vector<std::unique_ptr<CSocket>> &allsocks, std::vector<osuCrypto::Channel> &chls,
                                 std::vector<sci::NetIO *> &ioArr);

// Parallelise the various subprotocols
void multi_oprf_thread(int tid, std::vector<std::vector<osuCrypto::block>> &masks_with_dummies,
                       std::vector<std::uint64_t> table, ENCRYPTO::PsiAnalyticsContext &context,
                       std::vector<osuCrypto::Channel> &chls);

void multi_hint_thread(int tid, std::vector<std::vector<std::uint64_t>> &sub_bins,
                       std::vector<std::uint64_t> &cuckoo_table_v,
                       std::vector<std::vector<osuCrypto::block>> &masks_with_dummies,
                       ENCRYPTO::PsiAnalyticsContext &context, std::vector<std::unique_ptr<CSocket>> &allsocks,
                       std::vector<osuCrypto::Channel> &chls);

void multi_boolean_conn(int tid, std::vector<sci::NetIO *> &ioArr, ENCRYPTO::PsiAnalyticsContext &context);

void multi_otpack_setup(int tid, std::vector<sci::NetIO *> &ioArr, std::vector<sci::OTPack<sci::NetIO> *> &otpackArr,
                        ENCRYPTO::PsiAnalyticsContext &context);

void multi_equality_thread(int tid, std::vector<std::vector<std::uint64_t>> &x, int party, int num_cmps,
                           std::vector<std::vector<std::uint8_t>> &z,
                           std::vector<std::vector<std::uint8_t>> &a_shares_bins,
                           std::vector<std::vector<std::uint64_t>> &aux_bins, std::vector<sci::NetIO *> &ioArr,
                           std::vector<sci::OTPack<sci::NetIO> *> &otpackArr, ENCRYPTO::PsiAnalyticsContext &context,
                           std::vector<std::unique_ptr<CSocket>> &allsocks);

// Run the leader party's end of the protocol
void OpprgPsiLeader(std::vector<std::uint64_t> &content_of_bins, std::vector<std::uint64_t> &cuckoo_table_v,
                    const std::vector<std::vector<osuCrypto::block>> &masks_with_dummies,
                    ENCRYPTO::PsiAnalyticsContext &context, std::unique_ptr<CSocket> &sock, osuCrypto::Channel &chl);

// Run the other parties' end of the protocol
void OpprgPsiNonLeader(std::vector<std::uint64_t> &actual_contents_of_bins,
                       std::vector<std::vector<osuCrypto::block>> &masks, ENCRYPTO::PsiAnalyticsContext &context,
                       std::unique_ptr<CSocket> &sock, osuCrypto::Channel &chl,
                       std::chrono::_V2::system_clock::time_point &begin);

// Handle communication measurements for threshold PSI
void ResetCommunicationThreshold(std::vector<sci::NetIO *> &ioArr, ENCRYPTO::PsiAnalyticsContext &context);

void AccumulateCommunicationThreshold(std::vector<sci::NetIO *> &ioArr, ENCRYPTO::PsiAnalyticsContext &context);
}  // namespace RELAXEDNS
