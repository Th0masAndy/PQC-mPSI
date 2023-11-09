// Original Work copyright (c) Oleksandr Tkachenko
// Modified Work copyright (c) 2021 Microsoft Research
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
//
// Modified by Akash Shah

#include "relaxed_opprf.h"
#include "psi_analytics.h"
// #include "constants.h"
#include "connection.h"
#include "socket.h"
// #include "abycore/sharing/boolsharing.h"
// #include "abycore/sharing/sharing.h"
#include "equality.h"
// #include "ots/ots.h"
#include "polynomials/Poly.h"

#include "HashingTables/cuckoo_hashing/cuckoo_hashing.h"
#include "HashingTables/simple_hashing/simple_hashing.h"
#include "psi_analytics_context.h"
#include "table_opprf.h"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <random>
#include <ratio>
#include <thread>
#include <unordered_set>

namespace RELAXEDNS {
struct hashlocmap {
    int bin;
    int index;
};

// using share_ptr = std::shared_ptr<share>;

using milliseconds_ratio = std::ratio<1, 1000>;
using duration_millis = std::chrono::duration<double, milliseconds_ratio>;

/*
 * Reset communication for new execution
 */
void ResetCommunicationThreshold(std::vector<sci::NetIO*>& ioArr, ENCRYPTO::PsiAnalyticsContext& context) {
    if (context.role == P_0) {
        context.sci_io_start.resize(2 * (context.np - 1));
        for (std::uint64_t i = 0; i < 2 * (context.np - 1); i++) {
            context.sci_io_start[i] = ioArr[i]->counter;
        }
    } else {
        context.sci_io_start.resize(2);
        for (int i = 0; i < 2; i++) {
            context.sci_io_start[i] = ioArr[i]->counter;
        }
    }
}

/*
 * Measure communication
 */
void AccumulateCommunicationThreshold(std::vector<sci::NetIO*>& ioArr, ENCRYPTO::PsiAnalyticsContext& context) {
    if (context.role == P_0) {  // Accumulate from all parties
        for (std::uint64_t i = 0; i < 2 * (context.np - 1); i++) {
            context.sentBytesSCI += ioArr[i]->counter - context.sci_io_start[i];
        }
    } else {
        for (int i = 0; i < 2; i++) {
            context.sentBytesSCI += ioArr[i]->counter - context.sci_io_start[i];
        }
    }

    // Holds due to symmetricity
    context.recvBytesSCI = context.sentBytesSCI;
}

/*
 * Parallelise leader's execution of OPRF for relaxed batch OPPRF subprotocols with other parties
 */
void multi_oprf_thread(int tid, std::vector<std::vector<osuCrypto::block>>& masks_with_dummies,
                       std::vector<std::uint64_t> table, ENCRYPTO::PsiAnalyticsContext& context,
                       std::vector<osuCrypto::Channel>& chl) {
    for (std::uint64_t i = tid; i < context.np - 1; i = i + context.nthreads) {
        masks_with_dummies[i] = RELAXEDNS::ot_receiver(table, chl[i], context);
    }
}

/*
 * OPPRF for other (non-leader) parties
 */
void OpprgPsiNonLeader(std::vector<std::uint64_t>& actual_contents_of_bins,
                       std::vector<std::vector<std::uint64_t>>& simple_table_v,
                       std::vector<std::vector<osuCrypto::block>>& masks, ENCRYPTO::PsiAnalyticsContext& context,
                       std::unique_ptr<CSocket>& sock, osuCrypto::Channel& chl) {
    auto begin = std::chrono::high_resolution_clock::now();

    std::vector<std::uint64_t> content_of_bins;
    std::uint64_t bufferlength = (std::uint64_t)ceil(context.nbins / 2.0);
    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed(), bufferlength);

    for (std::uint64_t i = 0; i < context.nbins; i++) {
        content_of_bins.push_back(prng.get<std::uint64_t>());
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);

    printf("S1 Time measured: %.3f seconds. OPPRF start\n", elapsed.count() * 1e-9);

    std::unordered_map<std::uint64_t, hashlocmap> tloc;
    std::vector<std::uint64_t> filterinputs;
    for (std::uint64_t i = 0; i < context.nbins; i++) {
        int binsize = simple_table_v[i].size();
        for (int j = 0; j < binsize; j++) {
            tloc[simple_table_v[i][j]].bin = i;
            tloc[simple_table_v[i][j]].index = j;
            filterinputs.push_back(simple_table_v[i][j]);
        }
    }
    ENCRYPTO::CuckooTable cuckoo_table(static_cast<std::size_t>(context.fbins));
    cuckoo_table.SetNumOfHashFunctions(context.ffuns);
    cuckoo_table.Insert(filterinputs);
    cuckoo_table.MapElements();
    // cuckoo_table.Print();
    end = std::chrono::high_resolution_clock::now();
    elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
    printf("S2 Time measured: %.3f seconds. for cuckoo hash\n", elapsed.count() * 1e-9);

    if (cuckoo_table.GetStashSize() > 0u) {
        std::cerr << "[Error] Stash of size " << cuckoo_table.GetStashSize() << " occured in OPPRF\n";
    }

    std::vector<std::uint64_t> garbled_cuckoo_filter;
    garbled_cuckoo_filter.reserve(context.fbins);

    bufferlength = (std::uint64_t)ceil(context.fbins - 3 * context.nbins);
    osuCrypto::PRNG prngo(osuCrypto::sysRandomSeed(), bufferlength);

    for (std::uint64_t i = 0; i < context.fbins; i++) {
        if (!cuckoo_table.hash_table_.at(i).IsEmpty()) {
            std::uint64_t element = cuckoo_table.hash_table_.at(i).GetElement();
            std::uint64_t function_id = cuckoo_table.hash_table_.at(i).GetCurrentFunctinId();
            hashlocmap hlm = tloc[element];
            osuCrypto::PRNG prng(masks[hlm.bin][hlm.index], 2);
            std::uint64_t pad = 0u;
            for (std::uint64_t j = 0; j <= function_id; j++) {
                pad = prng.get<std::uint64_t>();
            }
            garbled_cuckoo_filter[i] = content_of_bins[hlm.bin] ^ pad;
        } else {
            garbled_cuckoo_filter[i] = prngo.get<std::uint64_t>();
        }
    }
    end = std::chrono::high_resolution_clock::now();
    elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
    printf("S3 Time measured: %.3f seconds. for intert table(hints) RB-OPPRF\n", elapsed.count() * 1e-9);

    sock->Send(garbled_cuckoo_filter.data(), context.fbins * sizeof(std::uint64_t));

    end = std::chrono::high_resolution_clock::now();
    elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
    printf("S4 Time measured: %.3f seconds. send hints \n", elapsed.count() * 1e-9);

    end = std::chrono::high_resolution_clock::now();
    elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);

    const int ts = 4;
    auto masks_with_dummies = RELAXEDNS::ot_receiver(content_of_bins, chl, context);

    std::vector<osuCrypto::block> padding_vals;
    padding_vals.reserve(context.nbins);
    std::vector<std::uint64_t> table_opprf;
    table_opprf.reserve(ts * context.nbins);

    // Receive nonces
    sock->Receive(padding_vals.data(), context.nbins * sizeof(osuCrypto::block));
    // Receive table
    sock->Receive(table_opprf.data(), context.nbins * ts * sizeof(std::uint64_t));

    end = std::chrono::high_resolution_clock::now();
    elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
    printf("S5 Time measured: %.3f seconds. receive table\n", elapsed.count() * 1e-9);
    // context.timings.table_transmission = ttrans_duration.count();

    std::uint64_t addresses1;
    std::uint8_t bitaddress;
    std::uint64_t mask_ad = (1ULL << 2) - 1;

    // actual_contents_of_bins.reserve(context.nbins);

    for (std::uint64_t i = 0; i < context.nbins; i++) {
        addresses1 = hashToPosition(reinterpret_cast<std::uint64_t*>(&masks_with_dummies[i])[0], padding_vals[i]);
        bitaddress = addresses1 & mask_ad;
        actual_contents_of_bins[i] =
            reinterpret_cast<std::uint64_t*>(&masks_with_dummies[i])[0] ^ table_opprf[ts * i + bitaddress];
    }
    end = std::chrono::high_resolution_clock::now();
    elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
    printf("S6 Time measured: %.3f seconds. OPPRF end\n", elapsed.count() * 1e-9);
}

/*
 * Relaxed batch OPPRF for leader party
 */
void OpprgPsiLeader(std::vector<std::uint64_t>& content_of_bins, std::vector<std::uint64_t>& cuckoo_table_v,
                    std::vector<osuCrypto::block>& masks_with_dummies, ENCRYPTO::PsiAnalyticsContext& context,
                    std::unique_ptr<CSocket>& sock, osuCrypto::Channel& chl) {
    std::vector<std::uint64_t> garbled_cuckoo_filter;
    garbled_cuckoo_filter.reserve(context.fbins);

    sock->Receive(garbled_cuckoo_filter.data(), context.fbins * sizeof(std::uint64_t));

    ENCRYPTO::CuckooTable garbled_cuckoo_table(static_cast<std::size_t>(context.fbins));
    garbled_cuckoo_table.SetNumOfHashFunctions(context.ffuns);
    garbled_cuckoo_table.Insert(cuckoo_table_v);
    auto addresses = garbled_cuckoo_table.GetElementAddresses();

    std::vector<std::vector<std::uint64_t>> opprf_values(context.nbins, std::vector<std::uint64_t>(context.ffuns));

    for (std::uint64_t i = 0; i < context.nbins; i++) {
        osuCrypto::PRNG prngo(masks_with_dummies[i], 2);
        for (std::uint64_t j = 0; j < context.ffuns; j++) {
            opprf_values[i][j] = garbled_cuckoo_filter[addresses[i * context.ffuns + j]] ^ prngo.get<std::uint64_t>();
        }
    }

    const int ts = 4;
    auto table_masks = RELAXEDNS::ot_sender(opprf_values, chl, context);

    std::uint64_t bufferlength = (std::uint64_t)ceil(context.nbins / 2.0);
    osuCrypto::PRNG tab_prng(osuCrypto::sysRandomSeed(), bufferlength);

    for (std::uint64_t i = 0; i < context.nbins; i++) {
        content_of_bins[i] = tab_prng.get<std::uint64_t>();
    }

    std::vector<osuCrypto::block> padding_vals;
    padding_vals.reserve(context.nbins);
    std::vector<std::uint64_t> table_opprf;
    table_opprf.reserve(ts * context.nbins);
    osuCrypto::PRNG padding_prng(osuCrypto::sysRandomSeed(), 2 * context.nbins);

    bufferlength = (std::uint64_t)ceil(context.nbins / 2.0);
    osuCrypto::PRNG dummy_prng(osuCrypto::sysRandomSeed(), bufferlength);

    // Get addresses
    std::uint64_t addresses1[context.ffuns];
    std::uint8_t bitaddress[context.ffuns];
    std::uint8_t bitindex[ts];
    std::uint64_t mask_ad = (1ULL << 2) - 1;

    double ave_ctr = 0.0;

    for (std::uint64_t i = 0; i < context.nbins; i++) {
        bool uniqueMap = false;
        int ctr = 0;
        while (!uniqueMap) {
            auto nonce = padding_prng.get<osuCrypto::block>();

            for (std::uint64_t j = 0; j < context.ffuns; j++) {
                addresses1[j] = hashToPosition(reinterpret_cast<std::uint64_t*>(&table_masks[i][j])[0], nonce);
                bitaddress[j] = addresses1[j] & mask_ad;
            }

            uniqueMap = true;
            for (int j = 0; j < ts; j++) bitindex[j] = ts;
            for (std::uint8_t j = 0; j < context.ffuns; j++) {
                if (bitindex[bitaddress[j]] != ts) {
                    uniqueMap = false;
                    break;
                } else {
                    bitindex[bitaddress[j]] = j;
                }
            }
            if (uniqueMap) {
                padding_vals.push_back(nonce);
                for (int j = 0; j < ts; j++) {
                    if (bitindex[j] != -1) {
                        table_opprf[i * ts + j] =
                            reinterpret_cast<std::uint64_t*>(&table_masks[i][bitindex[j]])[0] ^ content_of_bins[i];
                    } else {
                        table_opprf[i * ts + j] = dummy_prng.get<std::uint64_t>();
                    }
                }
                ave_ctr += ctr;
            }
            ctr++;
        }
    }

    ave_ctr = ave_ctr / context.nbins;

    // Send nonces
    sock->Send(padding_vals.data(), context.nbins * sizeof(osuCrypto::block));
    // Send table
    sock->Send(table_opprf.data(), context.nbins * ts * sizeof(std::uint64_t));
}

/*
 * Parallelise hint transmission between leader and all parties
 */
void multi_hint_thread(int tid, std::vector<std::vector<std::uint64_t>>& sub_bins,
                       std::vector<std::uint64_t>& cuckoo_table_v,
                       std::vector<std::vector<osuCrypto::block>>& masks_with_dummies,
                       ENCRYPTO::PsiAnalyticsContext& context, std::vector<std::unique_ptr<CSocket>>& allsocks,
                       std::vector<osuCrypto::Channel>& chls) {
    for (std::uint64_t i = tid; i < context.np - 1; i = i + context.nthreads) {
        OpprgPsiLeader(sub_bins[i], cuckoo_table_v, masks_with_dummies[i], context, allsocks[i], chls[i]);
    }
}

/*
 * Parallelise setting up connections for equality phase
 */
void multi_boolean_conn(int tid, std::vector<sci::NetIO*>& ioArr, ENCRYPTO::PsiAnalyticsContext& context) {
    for (std::uint64_t i = tid; i < context.np - 1; i = i + context.nthreads) {
        for (int j = 0; j < 2; j++) {
            ioArr[2 * i + j] = new sci::NetIO(context.address[i].c_str(), REF_SCI_PORT + 2 * i + j);
        }
    }
}

/*
 * Parallelise setup of OT connections
 */
void multi_otpack_setup(int tid, std::vector<sci::NetIO*>& ioArr, std::vector<sci::OTPack<sci::NetIO>*>& otpackArr,
                        ENCRYPTO::PsiAnalyticsContext& context) {
    // std::cout<<"Cp 3"<<context.radixparam<<": "<< context.bitlen<< std::endl;
    for (std::uint64_t i = tid; i < context.np - 1; i = i + context.nthreads) {
        for (int j = 0; j < 2; j++) {
            if (j == 0) {
                otpackArr[2 * i + j] = new OTPack<NetIO>(ioArr[2 * i + j], 2, context.radixparam, context.bitlen);
            } else if (j == 1) {
                otpackArr[2 * i + j] = new OTPack<NetIO>(ioArr[2 * i + j], 1, context.radixparam, context.bitlen);
            }
        }
    }
}

/*
 * Parallelise equality phase
 */
void multi_equality_thread(int tid, std::vector<std::vector<std::uint64_t>>& x, int party, int num_cmps,
                           std::vector<std::vector<std::uint8_t>>& z,
                           std::vector<std::vector<std::uint8_t>>& a_shares_bins,
                           std::vector<std::vector<std::uint64_t>>& aux_bins, std::vector<sci::NetIO*>& ioArr,
                           std::vector<sci::OTPack<sci::NetIO>*>& otpackArr, ENCRYPTO::PsiAnalyticsContext& context,
                           std::vector<std::unique_ptr<CSocket>>& allsocks) {
    for (std::uint64_t i = tid; i < context.np - 1; i = i + context.nthreads) {
        sci::NetIO* ioThreadArr[2];
        sci::OTPack<sci::NetIO>* otThreadpackArr[2];
        for (int j = 0; j < 2; j++) {
            ioThreadArr[j] = ioArr[2 * i + j];
            otThreadpackArr[j] = otpackArr[2 * i + j];
        }
        perform_equality(x[i].data(), party, context.bitlen, context.radixparam, num_cmps, z[i].data(),
                         a_shares_bins[i].data(), ioThreadArr, otThreadpackArr, context.smallmod);
    }
}

/*
 * Run relaxed batch OPPRF for all parties
 */
void run_relaxed_opprf(std::vector<std::vector<std::uint64_t>>& sub_bins, ENCRYPTO::PsiAnalyticsContext& context,
                       const std::vector<std::uint64_t>& inputs, std::vector<std::unique_ptr<CSocket>>& allsocks,
                       std::vector<osuCrypto::Channel>& chls) {
    if (context.role == P_0) {  // Protocol for leader party
        sub_bins.resize(context.np - 1, std::vector<std::uint64_t>(context.nbins, 0));

        // Hashing
        std::vector<std::uint64_t> table;
        std::vector<std::vector<osuCrypto::block>> masks_with_dummies(context.np - 1);
        table = ENCRYPTO::cuckoo_hash(context, inputs);

        // OPRF
        const auto oprf_start_time = std::chrono::system_clock::now();
        std::thread oprf_threads[context.nthreads];
        for (std::uint64_t i = 0; i < context.nthreads; i++) {
            oprf_threads[i] = std::thread(multi_oprf_thread, i, std::ref(masks_with_dummies), table, std::ref(context),
                                          std::ref(chls));
        }
        for (std::uint64_t i = 0; i < context.nthreads; i++) {
            oprf_threads[i].join();
        }
        const auto oprf_end_time = std::chrono::system_clock::now();
        const duration_millis oprf_duration = oprf_end_time - oprf_start_time;
        context.timings.oprf = oprf_duration.count();

        // Hints
        const auto phase_ts_time = std::chrono::system_clock::now();
        std::thread hint_threads[context.nthreads];
        for (std::uint64_t i = 0; i < context.nthreads; i++) {
            hint_threads[i] =
                std::thread(multi_hint_thread, i, std::ref(sub_bins), std::ref(table), std::ref(masks_with_dummies),
                            std::ref(context), std::ref(allsocks), std::ref(chls));
        }
        for (std::uint64_t i = 0; i < context.nthreads; i++) {
            hint_threads[i].join();
        }
        const auto phase_te_time = std::chrono::system_clock::now();
        const duration_millis phase_two_duration = phase_te_time - phase_ts_time;
        context.timings.polynomials = phase_two_duration.count();

    } else {  // For non leader parties
              // Hashing
        auto begin = std::chrono::high_resolution_clock::now();

        auto simple_table_v = ENCRYPTO::simple_hash(context, inputs);
        // OPRF
        auto masks = RELAXEDNS::ot_sender(simple_table_v, chls[0], context);
        sub_bins.resize(1, std::vector<std::uint64_t>(context.nbins, 0));
        // Protocol for non-leader

        auto end = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
        printf("S0 Time measured: %.3f seconds.\n", elapsed.count() * 1e-9);
        printf("---------------------------------------\n");
        OpprgPsiNonLeader(sub_bins[0], simple_table_v, masks, context, allsocks[0], chls[0]);
    }
}

/*
 * Run relaxed batch OPPRF and equality check for all parties
 */
void run_threshold_relaxed_opprf(std::vector<std::vector<std::uint8_t>>& a_shares_bins,
                                 ENCRYPTO::PsiAnalyticsContext& context, const std::vector<std::uint64_t>& inputs,
                                 std::vector<std::unique_ptr<CSocket>>& allsocks, std::vector<osuCrypto::Channel>& chls,
                                 std::vector<sci::NetIO*>& ioArr) {
    int padded_size = ((context.neles + 7) / 8) * 8;

    if (context.role == P_0) {  // Protocol for leader party

        a_shares_bins.resize(context.np - 1, std::vector<std::uint8_t>(padded_size, 0));

        std::vector<std::vector<std::uint64_t>> sub_bins(context.np - 1);
        for (std::uint64_t i = 0; i < context.np - 1; i++) {
            sub_bins[i].reserve(padded_size);
        }

        // Hashing

        // OPRF
        const auto oprf_start_time = std::chrono::system_clock::now();

        const auto oprf_end_time = std::chrono::system_clock::now();
        const duration_millis oprf_duration = oprf_end_time - oprf_start_time;
        context.timings.oprf = oprf_duration.count();

        // Hints
        const auto phase_ts_time = std::chrono::system_clock::now();

        std::vector<sci::OTPack<sci::NetIO>*> otpackArr(2 * (context.np - 1));
        std::thread ot_pack_threads[context.nthreads];
        for (std::uint64_t i = 0; i < context.nthreads; i++) {
            ot_pack_threads[i] =
                std::thread(multi_otpack_setup, i, std::ref(ioArr), std::ref(otpackArr), std::ref(context));
        }

        for (std::uint64_t i = 0; i < context.nthreads; i++) {
            ot_pack_threads[i].join();
        }

        for (std::uint64_t i = 0; i < context.np - 1; i++) {
            for (int j = 0; j < context.neles; j++) sub_bins[i][j] = inputs[j];
            for (int j = context.neles; j < padded_size; j++) sub_bins[i][j] = S_CONST;
        }

        std::vector<std::vector<std::uint8_t>> res_bins(context.np - 1);
        for (std::uint64_t i = 0; i < context.np - 1; i++) res_bins[i].resize(padded_size, 1);

        std::vector<std::vector<std::uint64_t>> aux_bins(context.np - 1);

        auto b2a_s = std::chrono::system_clock::now();
        // Equality
        std::thread equality_threads[context.nthreads];
        for (std::uint64_t i = 0; i < context.nthreads; i++) {
            equality_threads[i] =
                std::thread(multi_equality_thread, i, std::ref(sub_bins), 2, padded_size, std::ref(res_bins),
                            std::ref(a_shares_bins), std::ref(aux_bins), std::ref(ioArr), std::ref(otpackArr),
                            std::ref(context), std::ref(allsocks));
        }
        for (std::uint64_t i = 0; i < context.nthreads; i++) {
            equality_threads[i].join();
        }
        auto b2a_e = std::chrono::system_clock::now();
        const duration_millis d = b2a_e - b2a_s;
        context.timings.eq = d.count();

        const auto phase_te_time = std::chrono::system_clock::now();
        const duration_millis phase_two_duration = phase_te_time - phase_ts_time;
        context.timings.polynomials = phase_two_duration.count();

    } else {  // Protocol for non-leader parties

        auto begin = std::chrono::high_resolution_clock::now();

        a_shares_bins.resize(1, std::vector<std::uint8_t>(padded_size, 0));

        // Hashing

        auto end = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
        printf("SH Time measured: %.3f seconds.\n", elapsed.count() * 1e-9);

        // OPRF
        // auto masks = RELAXEDNS::ot_sender(simple_table_v, chls[0], context);
        std::vector<std::uint64_t> actual_contents_of_bins;
        actual_contents_of_bins.reserve(padded_size);

        end = std::chrono::high_resolution_clock::now();
        elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
        printf("S0 Time measured: %.3f seconds. For OPRF and then OPPRF start\n", elapsed.count() * 1e-9);

        printf("-----------------Internal time---------------------\n");
        // Relaxed batch OPPRF protocol for non-leader
        // OpprgPsiNonLeader(actual_contents_of_bins, simple_table_v, masks, context, allsocks[0], chls[0]);
        printf("-----------------Internal time---------------------\n");

        end = std::chrono::high_resolution_clock::now();
        elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
        printf("S8 Time measured: %.3f seconds. End For OPPRF \n", elapsed.count() * 1e-9);

        // Equality
        std::vector<sci::OTPack<sci::NetIO>*> otpackArr(2);
        for (int j = 0; j < 2; j++) {
            if (j == 0) {
                otpackArr[j] = new OTPack<NetIO>(ioArr[j], 1, context.radixparam, context.bitlen);
            } else if (j == 1) {
                otpackArr[j] = new OTPack<NetIO>(ioArr[j], 2, context.radixparam, context.bitlen);
            }
        }
        for (int j = 0; j < context.neles; j++) actual_contents_of_bins[j] = inputs[j];
        for (int j = context.neles; j < padded_size; j++) actual_contents_of_bins[j] = C_CONST;
        std::vector<std::uint8_t> res_bins;
        res_bins.resize(padded_size, 0);

        sci::NetIO* ioThreadArr[2];
        sci::OTPack<sci::NetIO>* otThreadpackArr[2];
        for (int j = 0; j < 2; j++) {
            ioThreadArr[j] = ioArr[j];
            otThreadpackArr[j] = otpackArr[j];
        }

        auto b2a_s = std::chrono::system_clock::now();
        perform_equality(actual_contents_of_bins.data(), 1, context.bitlen, context.radixparam, padded_size,
                         res_bins.data(), a_shares_bins[0].data(), ioThreadArr, otThreadpackArr, context.smallmod);

        auto b2a_e = std::chrono::system_clock::now();
        const duration_millis d = b2a_e - b2a_s;
        context.timings.eq = d.count();

        end = std::chrono::high_resolution_clock::now();
        elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
        printf("S9 Time measured: %.3f seconds. After EQ+B2A\n", elapsed.count() * 1e-9);

        cout << "EQ + B2A cost "
             << ioArr[0]->counter - context.sci_io_start[0] + ioArr[1]->counter - context.sci_io_start[1] << "Bytes"
             << endl;
    }
}

}  // namespace RELAXEDNS
