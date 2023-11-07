// Original Work copyright (c) Oleksandr Tkachenko
// Modified Work copyright (c) 2021 Microsoft Research
//
// \file psi_analytics_example.cpp
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
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
// INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR
// A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
// OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// Modified by Akash Shah, Nishka Dasgupta
//

#include <cassert>
#include <iostream>

#include <boost/program_options.hpp>
#include <fstream>
#include "abycore/aby/abyparty.h"

#include <inttypes.h>
#include <smmintrin.h>
#include <stdio.h>
#include "MPCHonestMajority/CircuitPSI.h"
#include "MPCHonestMajority/MPSI_Party.h"
#include "MPCHonestMajority/Threshold.h"
#include "MPCHonestMajority/ZpKaratsubaElement.h"
#include "MPCHonestMajority/ZpMersenneByteElement.h"

#include <thread>
#include "common/constants.h"
#include "common/psi_analytics.h"
#include "common/psi_analytics_context.h"
#include "common/relaxed_opprf.h"

using milliseconds_ratio = std::ratio<1, 1000>;
using duration_millis = std::chrono::duration<double, milliseconds_ratio>;

/*
 * Parse user-input options and create object
 */
auto read_test_options(int32_t argcp, char** argvp) {
    namespace po = boost::program_options;
    ENCRYPTO::PsiAnalyticsContext context;
    po::options_description allowed("Allowed options");
    std::string type;
    std::string opprf_type;

    // clang-format off

    allowed.add_options()("help,h", "produce this message")
        ("role,r", po::value<decltype(context.role)>(&context.role)->required(), "Role of the node")
        ("neles,n", po::value<decltype(context.neles)>(&context.neles)->default_value(4096u), "Number of my elements")
        ("bit-length,b", po::value<decltype(context.bitlen)>(&context.bitlen)->default_value(61u), "Bit-length of the elements")
        ("epsilon,e", po::value<decltype(context.epsilon)>(&context.epsilon)->default_value(1.28f), "Epsilon, a table size multiplier")
        ("threads,t", po::value<decltype(context.nthreads)>(&context.nthreads)->default_value(1), "Number of threads")
        ("threshold,c", po::value<decltype(context.threshold)>(&context.threshold)->default_value(2u), "Threshold Parameter, default: 2")
        //("nmegabins,m",    po::value<decltype(context.nmegabins)>(&context.nmegabins)->default_value(1u),                 "Number of mega bins")
        //("polysize,s",     po::value<decltype(context.polynomialsize)>(&context.polynomialsize)->default_value(0u),       "Size of the polynomial(s), default: neles")
        ("functions,f", po::value<decltype(context.nfuns)>(&context.nfuns)->default_value(3u), "Number of hash functions in hash tables")
        ("num_parties,N", po::value<decltype(context.np)>(&context.np)->default_value(5u), "Number of parties")
        ("file_address,F", po::value<decltype(context.file_address)>(&context.file_address)->default_value("../../files/addresses"), "IP Addresses")
        ("type,y", po::value<std::string>(&type)->default_value("PSI"), "Function type {None, PSI, Threshold, Circuit}")
        ("opprf_type,o", po::value<std::string>(&opprf_type)->default_value("Poly"), "OPPRF type {Poly, Relaxed}")
        ("radixparam,R", po::value<decltype(context.radixparam)>(&context.radixparam)->default_value(4u), "Radix Parameter, default: 4");

    // clang-format on

    po::variables_map vm;
    try {
        po::store(po::parse_command_line(argcp, argvp, allowed), vm);
        po::notify(vm);
    } catch (const boost::exception_detail::clone_impl<
             boost::exception_detail::error_info_injector<boost::program_options::required_option>>& e) {
        if (!vm.count("help")) {
            std::cout << e.what() << std::endl;
            std::cout << allowed << std::endl;
            exit(EXIT_FAILURE);
        }
    }

    if (vm.count("help")) {
        std::cout << allowed << std::endl;
        exit(EXIT_SUCCESS);
    }

    // Setting analytics type
    // For full non-circuit PSI we set the field as ZpMersenne61 for statistical correctness
    // For circuit and threshold PSI we can achieve correctness in a smaller field
    if (type.compare("None") == 0) {
        context.analytics_type = ENCRYPTO::PsiAnalyticsContext::NONE;
    } else if (type.compare("PSI") == 0) {
        context.fieldType = "ZpMersenne61";
        context.analytics_type = ENCRYPTO::PsiAnalyticsContext::PSI;
    } else if (type.compare("Threshold") == 0) {
        context.fieldType = "ZpMersenneByte";
        context.analytics_type = ENCRYPTO::PsiAnalyticsContext::THRESHOLD;
    } else if (type.compare("Circuit") == 0) {
        context.fieldType = "ZpMersenneByte";
        context.analytics_type = ENCRYPTO::PsiAnalyticsContext::CIRCUIT;
    } else {
        std::string error_msg(std::string("Unknown analytics type: " + type));
        throw std::runtime_error(error_msg.c_str());
    }

    // Setting OPPRF type
    if (opprf_type.compare("Poly") == 0) {
        context.opprf_type = ENCRYPTO::PsiAnalyticsContext::POLY;
    } else if (opprf_type.compare("Relaxed") == 0) {
        context.opprf_type = ENCRYPTO::PsiAnalyticsContext::RELAXED;
    } else {
        std::string error_msg(std::string("Unknown opprf type: " + opprf_type));
        throw std::runtime_error(error_msg.c_str());
    }

    // Setting number of threads
    if (context.nthreads == 0) {
        context.nthreads = std::thread::hardware_concurrency();
    }

    if (context.nthreads > context.np - 1) {
        context.nthreads = context.np - 1;
    }

    context.neles = 6400 * 5;
    context.nbins = 8192 * 5;

    // context.nbins = 1350 * context.epsilon;

    // Setting parameters for polynomial OPPRF, based on Pinkas et al, 2019
    int logn = int(std::log2(context.neles));
    if (logn == 12) {
        context.polynomialsize = 975;
        context.nmegabins = 16;
    } else if (logn > 12 && logn <= 16) {
        context.polynomialsize = 1021;
        context.nmegabins = 248;
    } else if (logn > 16 && logn <= 20) {
        context.polynomialsize = 1024;
        context.nmegabins = 4002;
    } else {
        context.polynomialsize = context.neles * context.nfuns;
        context.nmegabins = context.nbins;
    }
    context.polynomialbytelength = context.polynomialsize * sizeof(std::uint64_t);

    // Setting parameters for relaxed batch OPPRF

    context.ffuns = 3u;
    context.fepsilon = 1.31f;
    context.fbins = context.fepsilon * context.neles * context.nfuns;

    // if (context.role == P_0) {
    //     context.neles = 1350;
    // }

    // Setting parameters for circuit
    context.outputFileName = "output.txt";
    context.circuitFileName = "ic.txt";
    context.partiesFile = "Parties.txt";
    context.genRandomSharesType = "HIM";
    context.multType = "DN";
    context.verifyType = "Single";

    // Setting prime modulus for field in Circuit and Threshold variants
    // Must be a Mersenne prime > # of parties, less than a byte in length
    // E.g 31, 127
    // IF you change this be sure to change the prime and its bitlength in ZpMersenneByteElement.cpp
    // as well
    context.smallmod = 31;

    // Setting network parameters
    if (context.role == P_0) {
        context.port.reserve(context.np);
        // store addresses of other parties
        std::ifstream in(context.file_address, std::ifstream::in);
        /*if(!exists(filename)) {
         * std::cerr << "Address file doesn't exist" << std::endl;
         * exit(-1);
         * }*/
        // std::cout<< "Total Number of Parties: " << context.np <<", File Name: " <<
        // context.file_address << std::endl;
        std::string address;
        for (int i = 0; i < context.np; i++) {
            in >> address;
            // std::cout<< "Address: " << address << std::endl;
            context.address.push_back(address);
            context.port[i] = REF_PORT + i * 2;
        }
        in.close();
    } else {
        context.port.reserve(1);
        context.address.push_back(DEF_ADDRESS);
        context.port[0] = REF_PORT + 2 * (context.role - 1);
    }

    return context;
}

/*
 * Convert strings to char *
 */
void stringToChar(char* arg, std::string s) { strcpy(arg, s.c_str()); }

/*
 * Set arguments in format parseable by circuit code
 */
void prepareArgs(ENCRYPTO::PsiAnalyticsContext context, char** circuitArgv) {
    stringToChar(circuitArgv[0], "./build/MPCHonestMajority");
    stringToChar(circuitArgv[1], "-partyID");
    sprintf(circuitArgv[2], "%u", context.role);
    stringToChar(circuitArgv[3], "-partiesNumber");
    sprintf(circuitArgv[4], "%lu", context.np);
    stringToChar(circuitArgv[5], "-numBins");
    sprintf(circuitArgv[6], "%lu", context.nbins);
    stringToChar(circuitArgv[7], "-inputsFile");
    std::string arg_val = "../in_party_" + to_string(context.role) + ".txt";
    stringToChar(circuitArgv[8], arg_val);
    stringToChar(circuitArgv[9], "-outputsFile");
    strcpy(circuitArgv[10], context.outputFileName.c_str());
    stringToChar(circuitArgv[11], "-circuitFile");
    strcpy(circuitArgv[12], context.circuitFileName.c_str());
    stringToChar(circuitArgv[13], "-fieldType");
    strcpy(circuitArgv[14], context.fieldType.c_str());
    stringToChar(circuitArgv[15], "-genRandomSharesType");
    strcpy(circuitArgv[16], context.genRandomSharesType.c_str());
    stringToChar(circuitArgv[17], "-multType");
    strcpy(circuitArgv[18], context.multType.c_str());
    stringToChar(circuitArgv[19], "-verifyType");
    strcpy(circuitArgv[20], context.verifyType.c_str());
    stringToChar(circuitArgv[21], "-partiesFile");
    strcpy(circuitArgv[22], context.partiesFile.c_str());
    stringToChar(circuitArgv[23], "-internalIterationsNumber");
    stringToChar(circuitArgv[24], "1");
}

/*
 * Run the full PSI (non-circuit) protocol
 */
void MPSI_execution(ENCRYPTO::PsiAnalyticsContext& context, std::vector<std::uint64_t>& inputs,
                    std::vector<std::unique_ptr<CSocket>>& allsocks, std::vector<osuCrypto::Channel>& chl,
                    MPSI_Party<ZpMersenneLongElement>& mpsi) {
    ResetCommunication(allsocks, chl, context);
    auto start_time = std::chrono::system_clock::now();
    std::vector<std::vector<std::uint64_t>> sub_bins;
    std::uint64_t int_count;

    switch (context.opprf_type) {
        case ENCRYPTO::PsiAnalyticsContext::POLY: {
            ENCRYPTO::run_psi_analytics(sub_bins, context, inputs, allsocks, chl);
        } break;

        case ENCRYPTO::PsiAnalyticsContext::RELAXED: {
            RELAXEDNS::run_relaxed_opprf(sub_bins, context, inputs, allsocks, chl);
        } break;
    }

    auto t1 = std::chrono::system_clock::now();
    const duration_millis opprf_time = t1 - start_time;
    context.timings.opprf = opprf_time.count();

    // cout << context.role << ": PSI circuit successfully executed: " << bins[0] << endl;
    // cout << context.role << ": Passing inputs..." << endl;
    mpsi.readMPSIInputs(sub_bins, context.nbins);

    // cout << context.role << ": Running circuit..." << endl;
    auto t2 = std::chrono::system_clock::now();
    int_count = mpsi.runMPSI();
    auto end_time = std::chrono::system_clock::now();

    const duration_millis circuit_time = end_time - t2;
    context.timings.circuit = circuit_time.count();

    const duration_millis duration = end_time - start_time;
    context.timings.total = (duration).count();

    context.sentBytesCircuit = mpsi.sent_bytes;
    context.recvBytesCircuit = mpsi.recv_bytes;

    AccumulateCommunicationPSI(allsocks, chl, context);
    PrintTimings(context);
    PrintCommunication(context);
}

/*
 * Run the threshold PSI protocol
 */
void MPSI_threshold_execution(ENCRYPTO::PsiAnalyticsContext& context, std::vector<std::uint64_t>& inputs,
                              std::vector<std::unique_ptr<CSocket>>& allsocks, std::vector<osuCrypto::Channel>& chl,
                              std::vector<sci::NetIO*> ioArr, Threshold<ZpMersenneByteElement>& mpsi) {
    ResetCommunication(allsocks, chl, context);
    RELAXEDNS::ResetCommunicationThreshold(ioArr, context);
    auto start_time = std::chrono::system_clock::now();
    std::vector<std::vector<std::uint8_t>> sub_bins;
    std::uint64_t int_count;

    for (auto& e : inputs) {
        std::cout << e << " ";
    }
    std::cout << std::endl;

    switch (context.opprf_type) {
        case ENCRYPTO::PsiAnalyticsContext::POLY: {
            std::string error_msg("Not implemented currently.");
            throw std::runtime_error(error_msg.c_str());
        } break;

        case ENCRYPTO::PsiAnalyticsContext::RELAXED: {
            RELAXEDNS::run_threshold_relaxed_opprf(sub_bins, context, inputs, allsocks, chl, ioArr);
        } break;
    }

    for (auto& v : sub_bins) {
        for (auto& e : v) {
            printf("%d ", e);
        }
        printf("\n");
    }

    auto t1 = std::chrono::system_clock::now();
    const duration_millis opprf_time = t1 - start_time;
    context.timings.opprf = opprf_time.count();

    // cout << context.role << ": PSI circuit successfully executed: " << bins[0] << endl;
    // cout << context.role << ": Passing inputs..." << endl;
    mpsi.readMPSIInputs(sub_bins, context.nbins);

    // cout << context.role << ": Running circuit..." << endl;
    auto t2 = std::chrono::system_clock::now();
    int_count = mpsi.runMPSI();
    auto end_time = std::chrono::system_clock::now();

    const duration_millis circuit_time = end_time - t2;
    context.timings.circuit = circuit_time.count();

    const duration_millis duration = end_time - start_time;
    context.timings.total = (duration).count();

    context.sentBytesCircuit = mpsi.sent_bytes;
    context.recvBytesCircuit = mpsi.recv_bytes;

    AccumulateCommunicationPSI(allsocks, chl, context);
    RELAXEDNS::AccumulateCommunicationThreshold(ioArr, context);
    PrintTimings(context);
    cout << endl;
    PrintCommunication(context);
}

/*
 * Run the Circuit PSI protocol
 */
void MPSI_circuit_execution(ENCRYPTO::PsiAnalyticsContext& context, std::vector<std::uint64_t>& inputs,
                            std::vector<std::unique_ptr<CSocket>>& allsocks, std::vector<osuCrypto::Channel>& chl,
                            std::vector<sci::NetIO*> ioArr, CircuitPSI<ZpMersenneByteElement>& mpsi) {
    ResetCommunication(allsocks, chl, context);
    RELAXEDNS::ResetCommunicationThreshold(ioArr, context);
    auto start_time = std::chrono::system_clock::now();
    std::vector<std::vector<std::uint8_t>> sub_bins;
    std::uint64_t int_count;

    switch (context.opprf_type) {
        case ENCRYPTO::PsiAnalyticsContext::POLY: {
            std::string error_msg("Not implemented currently.");
            throw std::runtime_error(error_msg.c_str());
        } break;

        case ENCRYPTO::PsiAnalyticsContext::RELAXED: {
            RELAXEDNS::run_threshold_relaxed_opprf(sub_bins, context, inputs, allsocks, chl, ioArr);
        } break;
    }

    auto t1 = std::chrono::system_clock::now();
    const duration_millis opprf_time = t1 - start_time;
    context.timings.opprf = opprf_time.count();

    // cout << context.role << ": Passing inputs..." << endl;
    mpsi.readMPSIInputs(sub_bins, context.nbins);

    // cout << context.role << ": Running circuit..." << endl;
    auto t2 = std::chrono::system_clock::now();
    int_count = mpsi.runMPSI();
    auto end_time = std::chrono::system_clock::now();
    const duration_millis circuit_time = end_time - t2;

    context.timings.circuit = circuit_time.count();
    const duration_millis total_time = end_time - start_time;
    context.timings.total = total_time.count();

    context.sentBytesCircuit = mpsi.sent_bytes;
    context.recvBytesCircuit = mpsi.recv_bytes;

    AccumulateCommunicationPSI(allsocks, chl, context);
    RELAXEDNS::AccumulateCommunicationThreshold(ioArr, context);
    PrintTimings(context);
    PrintCommunication(context);
}

/*
 * Set up connections between parties for OPPRF phase
 */
void synchronize_parties(ENCRYPTO::PsiAnalyticsContext& context, std::vector<std::unique_ptr<CSocket>>& allsocks,
                         std::vector<osuCrypto::Channel>& chl, osuCrypto::IOService& ios,
                         std::vector<osuCrypto::Session>& ep) {
    if (context.role == P_0) {
        chl.resize(context.np - 1);
        for (int i = 0; i < context.np - 1; i++) {
            // osuCrypto::IOService thisio;
            ep.push_back(ENCRYPTO::ot_receiver_connect(context, i, ios, chl[i]));
            // ios[i] = thisio;
        }
        allsocks.resize(context.np - 1);
        std::thread conn_threads[context.nthreads];
        // std::vector<std::unique_ptr<CSocket>> allsocks(context.np-1);
        for (int i = 0; i < context.nthreads; i++) {
            conn_threads[i] = std::thread(ENCRYPTO::multi_conn_thread, i, std::ref(allsocks), std::ref(context));
        }

        for (int i = 0; i < context.nthreads; i++) {
            conn_threads[i].join();
        }

        std::thread sync_threads[context.nthreads];
        for (int i = 0; i < context.nthreads; i++) {
            sync_threads[i] = std::thread(ENCRYPTO::multi_sync_thread, i, std::ref(allsocks), std::ref(context));
        }

        for (int i = 0; i < context.nthreads; i++) {
            sync_threads[i].join();
        }
    } else {
        chl.resize(1);
        /// osuCrypto::IOService thisio;
        ep.push_back(ENCRYPTO::ot_sender_connect(context, ios, chl[0]));
        std::vector<std::uint8_t> testdata(1000, 0);
        allsocks.resize(1);
        allsocks[0] =
            ENCRYPTO::EstablishConnection(context.address[0], context.port[0], static_cast<e_role>(context.role));
        allsocks[0]->Receive(testdata.data(), 1000);
        // ios[0] = thisio;
    }

    // cout << context.role << ": Running protocol..." << endl;
}

/*
 * Generate the sets, parse user inputs, and run the appropriate protocol
 */
int main(int argc, char** argv) {
    auto context = read_test_options(argc, argv);
    auto gen_bitlen = static_cast<std::size_t>(std::ceil(std::log2(context.neles))) + 3;
    int size, party, times;
    char** circuitArgv;

    std::vector<sci::NetIO*> ioArr;

    CmdParser parser;
    std::vector<std::uint64_t> bins;

    std::vector<std::unique_ptr<CSocket>> allsocks;
    std::vector<osuCrypto::Channel> chl;
    osuCrypto::IOService ios;
    std::vector<osuCrypto::Session> ep;

    // Generate input sets
    // Different sets, pseudorandom
    // auto inputs = ENCRYPTO::GeneratePseudoRandomElements(context.neles, gen_bitlen, context.role
    // * 12345) Same sets, pseudorandom auto inputs =
    // ENCRYPTO::GeneratePseudoRandomElements(context.neles, gen_bitlen); Same sets, sequential
    //  if (context.role == P_0) {
    //      context.neles = 1000;
    //  }
    auto inputs = ENCRYPTO::GenerateSequentialElements(context.neles);
    // Even-numbered parties have identical sets, ditto odd-numbered parties
    /*auto inputs = ENCRYPTO::GenerateSequentialElements(context.neles);
    for (int i=0; i < inputs.size(); i++) {
        inputs[i] = inputs[i] * ((context.role % 2) + 1);
    }*/

    if (context.analytics_type == ENCRYPTO::PsiAnalyticsContext::THRESHOLD) {
        size = 29;
    } else if (context.analytics_type == ENCRYPTO::PsiAnalyticsContext::CIRCUIT) {
        size = 27;
    } else {
        size = 25;
    }

    circuitArgv = (char**)malloc(sizeof(char*) * (size));
    for (int i = 0; i < size; i++) {
        circuitArgv[i] = (char*)malloc(sizeof(char) * 50);
    }

    prepareArgs(context, circuitArgv);
    if (context.analytics_type == ENCRYPTO::PsiAnalyticsContext::THRESHOLD) {
        stringToChar(circuitArgv[25], "-threshold");
        sprintf(circuitArgv[26], "%lu", context.threshold);
        stringToChar(circuitArgv[27], "-primemod");
        sprintf(circuitArgv[28], "%d", context.smallmod);
    } else if (context.analytics_type == ENCRYPTO::PsiAnalyticsContext::CIRCUIT) {
        stringToChar(circuitArgv[25], "-primemod");
        sprintf(circuitArgv[26], "%d", context.smallmod);
    }

    auto parameters = parser.parseArguments("", size, circuitArgv);
    times = stoi(parser.getValueByKey(parameters, "internalIterationsNumber"));
    std::string fieldType(parser.getValueByKey(parameters, "fieldType"));

    /*std::vector<uint64_t> inputs;
    for(int i=0; i<1024; i++) {
        uint64_t val = i + context.role;
        inputs.push_back(val);
        std::cout << val << " ";
    }
    //std::cout << std::endl;
    */

    if ((context.analytics_type == ENCRYPTO::PsiAnalyticsContext::THRESHOLD) ||
        (context.analytics_type == ENCRYPTO::PsiAnalyticsContext::CIRCUIT)) {
        if (context.role == P_0) {
            std::thread boolean_conn_threads[context.nthreads];
            party = 1;
            ioArr.resize(2 * (context.np - 1));
            for (int i = 0; i < context.nthreads; i++) {
                boolean_conn_threads[i] =
                    std::thread(RELAXEDNS::multi_boolean_conn, i, std::ref(ioArr), std::ref(context));
            }

            for (int i = 0; i < context.nthreads; i++) {
                boolean_conn_threads[i].join();
            }
        } else {
            party = 2;
            ioArr.resize(2);
            for (int i = 0; i < 2; i++) {
                ioArr[i] = new sci::NetIO(nullptr, REF_SCI_PORT + 2 * (context.role - 1) + i);
            }
        }
    }

    switch (context.analytics_type) {
        case ENCRYPTO::PsiAnalyticsContext::PSI: {
            // MPSI_Party<ZpMersenneLongElement> mpsi(size, circuitArgv);
            MPSI_Party<ZpMersenneLongElement> mpsi(size, circuitArgv);
            synchronize_parties(context, allsocks, chl, ios, ep);
            MPSI_execution(context, inputs, allsocks, chl, mpsi);
        } break;

        case ENCRYPTO::PsiAnalyticsContext::THRESHOLD: {
            Threshold<ZpMersenneByteElement> mpsi(size, circuitArgv);
            synchronize_parties(context, allsocks, chl, ios, ep);
            MPSI_threshold_execution(context, inputs, allsocks, chl, ioArr, mpsi);
        } break;

        case ENCRYPTO::PsiAnalyticsContext::CIRCUIT: {
            CircuitPSI<ZpMersenneByteElement> mpsi(size, circuitArgv);
            synchronize_parties(context, allsocks, chl, ios, ep);
            MPSI_circuit_execution(context, inputs, allsocks, chl, ioArr, mpsi);
        } break;

        case ENCRYPTO::PsiAnalyticsContext::NONE: {
            std::string error_msg("Not implemented currently.");
            throw std::runtime_error(error_msg.c_str());
        } break;
    }

    // bins = ENCRYPTO::run_psi_analytics(context, inputs, allsocks, chl);
    // std::vector<uint64_t> bins = ENCRYPTO::GeneratePseudoRandomElements(context.nbins,
    // gen_bitlen);

    // std::string outfile = "../in_party_"+std::to_string(context.role)+".txt";
    // std::cout << "Printing " << bins[0] << " to " << outfile << std::endl;
    // ENCRYPTO::PrintBins(bins, outfile, context);
    // PrintTimings(context);

    for (int i = 0; i < chl.size(); i++) {
        chl[i].close();
        ep[i].stop();
    }
    ios.stop();

    std::cout << "end main" << std::endl;
    return EXIT_SUCCESS;
}
