#pragma once
//
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

#include "abycore/aby/abyparty.h"
#include <string>
#include <memory>
#include "socket.h"
#include "helpers.h"
#include "psi_analytics_context.h"
#include "ots/block_op_ots.h"
#include "EzPC/SCI/src/OT/emp-ot.h"
#include "EzPC/SCI/src/utils/emp-tool.h"

#define ceil_divide(x, y)			(( ((x) + (y)-1)/(y)))

#include <vector>

#define C_CONST 8459320670953116686
#define S_CONST 18286333650295995643

namespace RELAXEDNS {

void run_relaxed_opprf(std::vector<std::vector<uint64_t>> &sub_bins, ENCRYPTO::PsiAnalyticsContext &context, const std::vector<std::uint64_t> &inputs,
					 std::vector<std::unique_ptr<CSocket>> &allsocks, std::vector<osuCrypto::Channel> &chls);

void run_threshold_relaxed_opprf(std::vector<std::vector<uint64_t>> &sub_bins, ENCRYPTO::PsiAnalyticsContext &context, const std::vector<std::uint64_t> &inputs,
					 std::vector<std::unique_ptr<CSocket>> &allsocks, std::vector<osuCrypto::Channel> &chls, std::vector<sci::NetIO*> &ioArr);


/*//Receives OPRF
std::vector<uint64_t> LeaderOprf(PsiAnalyticsContext &context, int server_index, const std::vector<uint64_t> &cuckoo_table_v,
				 osuCrypto::Channel &chl);

//OPRF Sender
std::vector<std::vector<uint64_t>> ClientOprf(PsiAnalyticsContext &context, const std::vector<std::vector<uint64_t>> &simple_table_v,
						osuCrypto::Channel &chl);

//Construct polynomial hints
std::vector<uint64_t> ClientEvaluateHint(PsiAnalyticsContext &context, const std::vector<std::vector<uint64_t>> &masks);

//Receive hint
std::vector<uint8_t> LeaderReceiveHint(PsiAnalyticsContext &context, std::unique_ptr<CSocket> &sock);

//Evaluate received hint
std::vector<uint64_t> LeaderEvaluateHint(PsiAnalyticsContext &context, std::vector<uint8_t> &poly_rcv_buffer,
					 const std::vector<uint64_t> &masks_with_dummies);

//Send hint
std::vector<uint64_t> ClientSendHint(PsiAnalyticsContext &context, std::unique_ptr<CSocket> &sock,
					const std::vector<uint64_t> &polynomials);*/

//Interpolate polynomial for hint
/*void multi_eval_thread(int tid, std::vector<std::vector<uint8_t>> poly_rcv_buffer, std::vector<std::vector<uint64_t>> masks_with_dummies,
		       PsiAnalyticsContext &context, std::vector<std::vector<uint64_t>> &sub_bins);
void multi_hint_thread(int tid, std::vector<std::vector<uint8_t>> &poly_rcv, PsiAnalyticsContext &context,
			std::vector<std::unique_ptr<CSocket>> &allsocks);*/
void multi_oprf_thread(int tid, std::vector<std::vector<osuCrypto::block>> &masks_with_dummies, std::vector<uint64_t> table,
			ENCRYPTO::PsiAnalyticsContext &context, std::vector<osuCrypto::Channel> &chls);

void multi_hint_thread(int tid, std::vector<std::vector<uint64_t>> &sub_bins, std::vector<uint64_t> &cuckoo_table_v, std::vector<std::vector<osuCrypto::block>> &masks_with_dummies, ENCRYPTO::PsiAnalyticsContext &context, std::vector<std::unique_ptr<CSocket>> &allsocks, std::vector<osuCrypto::Channel> &chls);
void multi_boolean_conn(int tid, std::vector<sci::NetIO*> &ioArr, ENCRYPTO::PsiAnalyticsContext &context);
void multi_otpack_setup(int tid, std::vector<sci::NetIO*> &ioArr, std::vector<sci::OTPack<sci::NetIO>*> &otpackArr, ENCRYPTO::PsiAnalyticsContext &context);
void multi_equality_thread(int tid, std::vector<std::vector<uint64_t>> &x, int party, int num_cmps, std::vector<std::vector<uint8_t>> &z, std::vector<std::vector<uint64_t>> &a_shares_bins, std::vector<std::vector<uint64_t>> &aux_bins, std::vector<sci::NetIO*> &ioArr, std::vector<sci::OTPack<sci::NetIO>*> &otpackArr, ENCRYPTO::PsiAnalyticsContext &context, std::vector<std::unique_ptr<CSocket>> &allsocks);
//void multi_B2A_thread(int tid, std::vector<std::vector<uint8_t>> &inputs, std::vector<std::vector<uint64_t>> &outputs, std::vector<std::vector<uint64_t>> &a_shares_bins, ENCRYPTO::PsiAnalyticsContext &context);
void OpprgPsiLeader(std::vector<uint64_t> &content_of_bins, std::vector<uint64_t> &cuckoo_table_v, const std::vector<std::vector<osuCrypto::block>> &masks_with_dummies, ENCRYPTO::PsiAnalyticsContext &context, std::unique_ptr<CSocket> &sock, osuCrypto::Channel &chl);
void OpprgPsiNonLeader(std::vector<uint64_t> &actual_contents_of_bins, std::vector<std::vector<osuCrypto::block>> &masks, ENCRYPTO::PsiAnalyticsContext & context, std::unique_ptr<CSocket> &sock, osuCrypto::Channel &chl);

void ResetCommunicationThreshold(std::vector<sci::NetIO*> &ioArr, ENCRYPTO::PsiAnalyticsContext &context);
void AccumulateCommunicationThreshold(std::vector<sci::NetIO*> &ioArr, ENCRYPTO::PsiAnalyticsContext &context);
}
