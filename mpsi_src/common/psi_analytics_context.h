#pragma once
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
// Modified by Akash Shah, Nishka Dasgupta

namespace ENCRYPTO {

struct PsiAnalyticsContext {
    uint32_t role;
    uint64_t bitlen;
    uint64_t neles;
    uint64_t nbins;
    uint64_t notherpartyselems;
    uint64_t nthreads;
    uint64_t nfuns;  //< number of hash functions in the hash table
    uint64_t threshold;
    uint64_t polynomialsize;
    uint64_t polynomialbytelength;
    uint64_t nmegabins;
    double epsilon;
    uint64_t np;
    uint64_t radixparam;
    uint8_t smallmod;

    uint64_t sentBytesOPRF;
    uint64_t recvBytesOPRF;
    uint64_t sentBytesHint;
    uint64_t recvBytesHint;
    uint64_t sentBytesCircuit;
    uint64_t recvBytesCircuit;
    uint64_t sentBytesSCI;
    uint64_t recvBytesSCI;

    uint64_t sentBytes;
    uint64_t recvBytes;

    // relaxed batched opprf params
    uint64_t ffuns;
    uint64_t fbins;
    double fepsilon;

    std::string fieldType;
    std::string genRandomSharesType;
    std::string multType;
    std::string verifyType;
    std::string partiesFile;
    std::string circuitFileName;
    std::string outputFileName;

    std::vector<uint64_t> content_of_bins;
    std::vector<uint64_t> sci_io_start;

    std::string file_address;
    std::vector<std::string> address;
    std::vector<uint16_t> port;

    enum { NONE, PSI, THRESHOLD, CIRCUIT } analytics_type;

    enum { POLY, RELAXED } opprf_type;

    const uint64_t maxbitlen = 61;

    struct {
        double hashing;
        double base_ots_aby;
        double base_ots_libote;
        double oprf;
        double opprf;
        double polynomials;
        double polynomials_transmission;
        double aggregation;
        double eq;
        // double aby_setup;
        // double aby_online;
        // double aby_total;
        double circuit;
        double total;
    } timings;
};

}  // namespace ENCRYPTO
