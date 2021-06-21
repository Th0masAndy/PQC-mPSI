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

#include "psi_analytics.h"
//#include "constants.h"
#include "connection.h"
#include "socket.h"
//#include "abycore/sharing/boolsharing.h"
//#include "abycore/sharing/sharing.h"

//#include "ots/ots.h"
#include "polynomials/Poly.h"

#include "HashingTables/cuckoo_hashing/cuckoo_hashing.h"
#include "HashingTables/simple_hashing/simple_hashing.h"
#include "psi_analytics_context.h"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <random>
#include <ratio>
#include <unordered_set>
#include <thread>

namespace ENCRYPTO {

using milliseconds_ratio = std::ratio<1, 1000>;
using duration_millis = std::chrono::duration<double, milliseconds_ratio>;

/*
 * Perform stashless cuckoo hashing, 1 element per bin
 */
std::vector<std::uint64_t> cuckoo_hash(PsiAnalyticsContext &context, const std::vector<std::uint64_t> &elements) {
  const auto hashing_start_time = std::chrono::system_clock::now();

  ENCRYPTO::CuckooTable cuckoo_table(static_cast<std::size_t>(context.nbins));
  cuckoo_table.SetNumOfHashFunctions(context.nfuns);
  cuckoo_table.Insert(elements);
  cuckoo_table.MapElements();
  // cuckoo_table.Print();

  if (cuckoo_table.GetStashSize() > 0u) {
    std::cerr << "[Error] Stash of size " << cuckoo_table.GetStashSize() << " occured\n";
  }

  auto cuckoo_table_v = cuckoo_table.AsRawVector();

  const auto hashing_end_time = std::chrono::system_clock::now();
  const duration_millis hashing_duration = hashing_end_time - hashing_start_time;
  context.timings.hashing = hashing_duration.count();

  return cuckoo_table_v;
}

/*
 * Perform simple hashing, multiple elements per bin
 */
std::vector<std::vector<std::uint64_t>> simple_hash(PsiAnalyticsContext &context, const std::vector<std::uint64_t> &elements) {
  const auto hashing_start_time = std::chrono::system_clock::now();

  ENCRYPTO::SimpleTable simple_table(static_cast<std::size_t>(context.nbins));
  simple_table.SetNumOfHashFunctions(context.nfuns);
  simple_table.Insert(elements);
  simple_table.MapElements();
  // simple_table.Print();

  auto simple_table_v = simple_table.AsRaw2DVector();
  // context.simple_table = simple_table_v;
  const auto hashing_end_time = std::chrono::system_clock::now();
  const duration_millis hashing_duration = hashing_end_time - hashing_start_time;
  context.timings.hashing = hashing_duration.count();

  return simple_table_v;
}

/*
 * Perform leader party's share of OPRF protocol
 */
std::vector<std::uint64_t> LeaderOprf(PsiAnalyticsContext &context, int server_index, const std::vector<std::uint64_t> &cuckoo_table_v,
				      osuCrypto::Channel &recvChl) {
  std::vector<std::uint64_t> masks_with_dummies = ot_receiver(cuckoo_table_v, recvChl, context, server_index);

  return masks_with_dummies;
}

/*
 * Perform client parties' end of OPRF
 */
std::vector<std::vector<std::uint64_t>> ClientOprf(PsiAnalyticsContext &context, const std::vector<std::vector<std::uint64_t>> &simple_table_v,
						   osuCrypto::Channel &sendChl) {
  const auto oprf_start_time = std::chrono::system_clock::now();
  auto masks = ot_sender(simple_table_v, sendChl, context);
  const auto oprf_end_time = std::chrono::system_clock::now();
  const duration_millis oprf_duration = oprf_end_time - oprf_start_time;
  context.timings.oprf = oprf_duration.count();

  return masks;
}

/*
 * Client parties' hint evaluation
 */
std::vector<std::uint64_t> ClientEvaluateHint(PsiAnalyticsContext &context, const std::vector<std::vector<std::uint64_t>> &masks) {
  const auto polynomials_start_time = std::chrono::system_clock::now();

  std::vector<std::uint64_t> polynomials(context.nmegabins * context.polynomialsize, 0);
  std::vector<std::uint64_t> content_of_bins(context.nbins);

  std::random_device urandom("/dev/urandom");
  std::uniform_int_distribution<std::uint64_t> dist(0, (1ull << context.maxbitlen) - 1);  // [0,2^elebitlen)

  // generate random numbers to use for mapping the polynomial to
  std::generate(content_of_bins.begin(), content_of_bins.end(), [&]() { return dist(urandom); });
  {
    auto tmp = content_of_bins;
    std::sort(tmp.begin(), tmp.end());
    auto last = std::unique(tmp.begin(), tmp.end());
    tmp.erase(last, tmp.end());
    assert(tmp.size() == content_of_bins.size());
  }

  InterpolatePolynomials(context, polynomials, content_of_bins, masks);
  context.content_of_bins = content_of_bins;

  const auto polynomials_end_time = std::chrono::system_clock::now();
  const duration_millis polynomials_duration = polynomials_end_time - polynomials_start_time;
  context.timings.polynomials = polynomials_duration.count();
  return polynomials;
}

/*
 * Leader party hint receive
 */
std::vector<std::uint8_t> LeaderReceiveHint(PsiAnalyticsContext &context, std::unique_ptr<CSocket> &sock) {
  std::vector<std::uint8_t> poly_rcv_buffer(context.nmegabins * context.polynomialbytelength, 0);

  sock->Receive(poly_rcv_buffer.data(), context.nmegabins * context.polynomialbytelength);
  sock->Close();

  return poly_rcv_buffer;
}

/*
 * Leader evaluates received hint
 */
std::vector<std::uint64_t> LeaderEvaluateHint(PsiAnalyticsContext &context, std::vector<std::uint8_t> &poly_rcv_buffer,
					      const std::vector<std::uint64_t> &masks_with_dummies) {
  const auto nbinsinmegabin = ceil_divide(context.nbins, context.nmegabins);
  std::vector<std::vector<ZpMersenneLongElement1>> polynomials(context.nmegabins);
  std::vector<ZpMersenneLongElement1> X(context.nbins), Y(context.nbins);
  for (auto &polynomial : polynomials) {
    polynomial.resize(context.polynomialsize);
  }

  for (auto i = 0ull; i < X.size(); ++i) {
    X.at(i).elem = masks_with_dummies.at(i);
  }

  for (auto poly_i = 0ull; poly_i < polynomials.size(); ++poly_i) {
    for (auto coeff_i = 0ull; coeff_i < context.polynomialsize; ++coeff_i) {
      polynomials.at(poly_i).at(coeff_i).elem = (reinterpret_cast<std::uint64_t *>(
          poly_rcv_buffer.data()))[poly_i * context.polynomialsize + coeff_i];
    }
  }


  for (auto i = 0ull; i < X.size(); ++i) {
    std::size_t p = i / nbinsinmegabin;
    Poly::evalMersenne(Y.at(i), polynomials.at(p), X.at(i));
  }
  std::vector<std::uint64_t> raw_bin_result;
  raw_bin_result.reserve(X.size());
  for (auto i = 0ull; i < X.size(); ++i) {
    raw_bin_result.push_back(X[i].elem ^ Y[i].elem);
  }

  return raw_bin_result;
}

/*
 * Client parties send polynomial hint
 */
std::vector<std::uint64_t> ClientSendHint(PsiAnalyticsContext &context, std::unique_ptr<CSocket> &sock,
					  const std::vector<std::uint64_t> &polynomials) {
  const auto sending_start_time = std::chrono::system_clock::now();

  // send polynomials to the receiver
  sock->Send((std::uint8_t *)polynomials.data(), context.nmegabins * context.polynomialbytelength);
  sock->Close();

  const auto sending_end_time = std::chrono::system_clock::now();
  const duration_millis sending_duration = sending_end_time - sending_start_time;
  context.timings.polynomials_transmission = sending_duration.count();

  return context.content_of_bins;
}

/*
 * Interpolate polynomials
 */
void InterpolatePolynomials(PsiAnalyticsContext &context, std::vector<std::uint64_t> &polynomials,
                            std::vector<std::uint64_t> &content_of_bins,
                            const std::vector<std::vector<std::uint64_t>> &masks) {
  std::size_t nbins = masks.size();
  std::size_t masks_offset = 0;
  std::size_t nbinsinmegabin = ceil_divide(nbins, context.nmegabins);

  for (auto mega_bin_i = 0ull; mega_bin_i < context.nmegabins; ++mega_bin_i) {
    auto polynomial = polynomials.begin() + context.polynomialsize * mega_bin_i;
    auto bin = content_of_bins.begin() + nbinsinmegabin * mega_bin_i;
    auto masks_in_bin = masks.begin() + nbinsinmegabin * mega_bin_i;

    if ((masks_offset + nbinsinmegabin) > masks.size()) {
      auto overflow = (masks_offset + nbinsinmegabin) % masks.size();
      nbinsinmegabin -= overflow;
    }

    InterpolatePolynomialsPaddedWithDummies(context, polynomial, bin, masks_in_bin, nbinsinmegabin);
    masks_offset += nbinsinmegabin;
  }

  assert(masks_offset == masks.size());
}

/*
 * Interpolate polynomials, adding dummy elements to mask degree
 */
void InterpolatePolynomialsPaddedWithDummies(PsiAnalyticsContext &context,
					     std::vector<std::uint64_t>::iterator polynomial_offset,
					     std::vector<std::uint64_t>::const_iterator random_value_in_bin,
					     std::vector<std::vector<std::uint64_t>>::const_iterator masks_for_elems_in_bin,
					     std::size_t nbins_in_megabin) {
  std::uniform_int_distribution<std::uint64_t> dist(0,
                                                    (1ull << context.maxbitlen) - 1);  // [0,2^61)
  std::random_device urandom("/dev/urandom");
  auto my_rand = [&urandom, &dist]() { return dist(urandom); };

  std::vector<ZpMersenneLongElement1> X(context.polynomialsize), Y(context.polynomialsize),
      coeff(context.polynomialsize);

  for (auto i = 0ull, bin_counter = 0ull; i < context.polynomialsize;) {
    if (bin_counter < nbins_in_megabin) {
      if ((*masks_for_elems_in_bin).size() > 0) {
        for (auto &mask : *masks_for_elems_in_bin) {
          X.at(i).elem = mask & __61_bit_mask;
          Y.at(i).elem = X.at(i).elem ^ *random_value_in_bin;
          ++i;
        }
      }
      ++masks_for_elems_in_bin;
      ++random_value_in_bin;  // proceed to the next bin (iterator)
      ++bin_counter;
    } else {  // generate dummy elements for polynomial interpolation
      X.at(i).elem = my_rand();
      Y.at(i).elem = my_rand();
      ++i;
    }
  }

  Poly::interpolateMersenne(coeff, X, Y);

  auto coefficient = coeff.begin();
  for (auto i = 0ull; i < coeff.size(); ++i, ++polynomial_offset, ++coefficient) {
    *polynomial_offset = (*coefficient).elem;
  }
}

/*
 * Connect leader / server party with all others
 */
std::unique_ptr<CSocket> EstablishConnection(const std::string &address, std::uint16_t port,
                                             e_role role) {
  std::unique_ptr<CSocket> socket;
  if (role != SERVER) {
    socket = Listen(address.c_str(), port);
  } else {
    socket = Connect(address.c_str(), port);
  }
  assert(socket);
  return socket;
}

/*
 * Output intersection size directly from input sets (useful as test)
 */
std::size_t PlainIntersectionSize(std::vector<std::uint64_t> v1, std::vector<std::uint64_t> v2) {
  std::vector<std::uint64_t> intersection_v;

  std::sort(v1.begin(), v1.end());
  std::sort(v2.begin(), v2.end());

  std::set_intersection(v1.begin(), v1.end(), v2.begin(), v2.end(), back_inserter(intersection_v));
  return intersection_v.size();
}

/*
 * Output timings, subprotocols and total
 */
void PrintTimings(const PsiAnalyticsContext &context) {
  std::cout << context.role << ": Printing timings..." << std::endl;
  std::cout << context.role << ": Time for hashing " << context.timings.hashing << " ms\n";
  std::cout << context.role << ": Time for OPRF " << context.timings.oprf << " ms\n";
  std::cout << context.role << ": Time for polynomials " << context.timings.polynomials << " ms\n";
  std::cout << context.role << ": Time for transmission of the polynomials "
            << context.timings.polynomials_transmission << " ms\n";
  std::cout << context.role << ": Time for OPPRF " << context.timings.opprf << " ms\n";
  std::cout << context.role << ": Time for circuit " << context.timings.circuit << " ms\n";

  std::cout << context.role << ": Total runtime: " << context.timings.total << "ms\n";
}

/*
 * Print bins to file (useful for tests)
 */
void PrintBins(std::vector<std::uint64_t> &bins, std::string outFile, PsiAnalyticsContext &context) {
  std::ofstream myfile;
  uint64_t i;
  std::cout << "Writing " << context.nbins << " values to " << outFile << std::endl;
  myfile.open(outFile);
  for(i=0; i<context.nbins; i++) {
    myfile << bins[i] << "\n";
  }
  myfile.close();
  std::cout << "Written outputs to file.";
}

/*
 * Parallelise the subprotocols for leader to interact with other parties
 */
//Evaluate polynomial on values
void multi_eval_thread(int tid, std::vector<std::vector<std::uint8_t>> poly_rcv_buffer, std::vector<std::vector<std::uint64_t>> masks_with_dummies,
			PsiAnalyticsContext &context, std::vector<std::vector<std::uint64_t>> &sub_bins) {
  for(std::uint64_t i=tid; i < context.np-1; i = i+context.nthreads) {
    sub_bins[i] = LeaderEvaluateHint(context, poly_rcv_buffer[i], masks_with_dummies[i]);
  }
}

//Receive hints
void multi_hint_thread(int tid, std::vector<std::vector<std::uint8_t>> &poly_rcv, PsiAnalyticsContext &context,
			std::vector<std::unique_ptr<CSocket>> &allsocks) {
    for(std::uint64_t i=tid; i < context.np-1; i=i+context.nthreads) {
      poly_rcv[i] = LeaderReceiveHint(context, allsocks[i]);
    }
}

//Perform OPRF
void multi_oprf_thread(int tid, std::vector<std::vector<std::uint64_t>> &masks_with_dummies, std::vector<std::uint64_t> table,
			PsiAnalyticsContext &context, std::vector<osuCrypto::Channel> &chl) {
  for(std::uint64_t i=tid; i<context.np-1; i=i+context.nthreads) {
    masks_with_dummies[i] = LeaderOprf(context, i, table, chl[i]);
  }
}

//Set up connections
void multi_conn_thread(int tid, std::vector<std::unique_ptr<CSocket>> &socks, PsiAnalyticsContext &context) {
  for(std::uint64_t i=tid; i<context.np-1; i=i+context.nthreads) {
    socks[i] = EstablishConnection(context.address[i], context.port[i], static_cast<e_role>(context.role));
  }
}

//Sync to establish that all connections are online
void multi_sync_thread(int tid, std::vector<std::unique_ptr<CSocket>> &socks, PsiAnalyticsContext &context) {
	for(std::uint64_t i=tid; i<context.np-1; i=i+context.nthreads) {
		std::vector<std::uint8_t> testdata(1000, 0);
		socks[i]->Send(testdata.data(), 1000);
	}
}

/*
 * Clear communication counts for new execution
 */
void ResetCommunication(std::vector<std::unique_ptr<CSocket>> &allsocks, std::vector<osuCrypto::Channel> &chls, PsiAnalyticsContext &context) {
  if(context.role == P_0) {
    for(std::uint64_t i=0; i<context.np-1; i++) {
      chls[i].resetStats();
      allsocks[i]->ResetSndCnt();
      allsocks[i]->ResetRcvCnt();
    }
  } else {
    chls[0].resetStats();
    allsocks[0]->ResetSndCnt();
    allsocks[0]->ResetRcvCnt();
  }
}

/*
 * Measure communication
 */
void AccumulateCommunicationPSI(std::vector<std::unique_ptr<CSocket>> &allsocks, std::vector<osuCrypto::Channel> &chls, PsiAnalyticsContext &context) {

  context.sentBytesOPRF = 0;
  context.recvBytesOPRF = 0;

  context.sentBytesHint = 0;
  context.recvBytesHint = 0;

  context.sentBytesSCI = 0;
  context.recvBytesSCI = 0;

  if(context.role == P_0) { // leader measures with all other parties
    for(std::uint64_t i=0; i<context.np-1; i++) {
      context.sentBytesOPRF += chls[i].getTotalDataSent();
      context.sentBytesHint += allsocks[i]->getSndCnt();

      context.recvBytesOPRF += chls[i].getTotalDataRecv();
      context.recvBytesHint += allsocks[i]->getRcvCnt();
    }
  } else { // other parties only measure with leader
    context.sentBytesOPRF += chls[0].getTotalDataSent();
    context.sentBytesHint += allsocks[0]->getSndCnt();

    context.recvBytesOPRF += chls[0].getTotalDataRecv();
    context.recvBytesHint += allsocks[0]->getRcvCnt();
  }
}

/*
 * Print communication
 */
void PrintCommunication(PsiAnalyticsContext &context) {
  context.sentBytes = context.sentBytesOPRF + context.sentBytesHint + context.sentBytesCircuit + context.sentBytesSCI;
  context.recvBytes = context.recvBytesOPRF + context.recvBytesHint + context.recvBytesCircuit + context.recvBytesSCI;
  std::cout<< context.role << ": Communication Statistics: "<<std::endl;
  double sentinMB, recvinMB;
  sentinMB = context.sentBytesOPRF/((1.0*(1ULL<<20)));
  recvinMB = context.recvBytesOPRF/((1.0*(1ULL<<20)));
  std::cout<<context.role << ": Sent Data OPRF (MB): "<<sentinMB<<std::endl;
  std::cout<<context.role << ": Received Data OPRF (MB): "<<recvinMB<<std::endl;

  sentinMB = context.sentBytesHint/((1.0*(1ULL<<20)));
  recvinMB = context.recvBytesHint/((1.0*(1ULL<<20)));
  std::cout<<context.role << ": Sent Data Hint (MB): "<<sentinMB<<std::endl;
  std::cout<<context.role << ": Received Data Hint (MB): "<<recvinMB<<std::endl;

  sentinMB = context.sentBytesCircuit/((1.0*(1ULL<<20)));
  recvinMB = context.recvBytesCircuit/((1.0*(1ULL<<20)));
  std::cout<<context.role << ": Sent Data Circuit (MB): "<<sentinMB<<std::endl;
  std::cout<<context.role << ": Received Data Circuit (MB): "<<recvinMB<<std::endl;

  sentinMB = context.sentBytesSCI/((1.0*(1ULL<<20)));
  recvinMB = context.recvBytesSCI/((1.0*(1ULL<<20)));
  std::cout<<context.role << ": Sent Data CryptFlow2 (MB): "<<sentinMB<<std::endl;
  std::cout<<context.role << ": Received Data CryptFlow2 (MB): "<<recvinMB<<std::endl;

  sentinMB = context.sentBytes/((1.0*(1ULL<<20)));
  recvinMB = context.recvBytes/((1.0*(1ULL<<20)));
  std::cout<<context.role << ": Total Sent Data (MB): "<<sentinMB<<std::endl;
  std::cout<<context.role << ": Total Received Data (MB): "<<recvinMB<<std::endl;
}

/*
 * Run the OPPRF phase of the protocol for both leader and clients
 */
void run_psi_analytics(std::vector<std::vector<std::uint64_t>> &sub_bins, PsiAnalyticsContext &context, const std::vector<std::uint64_t> &inputs,
		       std::vector<std::unique_ptr<CSocket>> &allsocks, std::vector<osuCrypto::Channel> &chls) {
  if (context.role == P_0) {//OPPRF phase for leader
    sub_bins.resize(context.np-1, std::vector<std::uint64_t>(context.nbins, 0));

    std::vector<std::vector<std::uint8_t>> poly_rcv(context.np-1);

    //Hash 
    std::vector<std::uint64_t> table;
    std::vector<std::vector<std::uint64_t>> masks_with_dummies(context.np-1);
    table = cuckoo_hash(context, inputs);

    //OPRF
    const auto oprf_start_time = std::chrono::system_clock::now();
    std::thread oprf_threads[context.nthreads];
    for(std::uint64_t i=0; i<context.nthreads; i++) {
      oprf_threads[i] = std::thread(multi_oprf_thread, i, std::ref(masks_with_dummies), table, std::ref(context), std::ref(chls));
    }
    for(std::uint64_t i=0; i<context.nthreads; i++) {
      oprf_threads[i].join();
    }
    const auto oprf_end_time = std::chrono::system_clock::now();
    const duration_millis oprf_duration = oprf_end_time - oprf_start_time;
    context.timings.oprf = oprf_duration.count();

    //Receive hints
    const auto receiving_start_time = std::chrono::system_clock::now();
    std::thread hint_threads[context.nthreads];
    for(std::uint64_t i=0; i<context.nthreads; i++) {
      hint_threads[i] = std::thread(multi_hint_thread, i, std::ref(poly_rcv), std::ref(context), std::ref(allsocks));
    }
    for (std::uint64_t i=0; i<context.nthreads; i++) {
      hint_threads[i].join();
    }
    const auto receiving_end_time = std::chrono::system_clock::now();
    const duration_millis sending_duration = receiving_end_time - receiving_start_time;
    context.timings.polynomials_transmission += sending_duration.count();

    //Evaluate polynomial
    const auto eval_poly_start_time = std::chrono::system_clock::now();
    std::thread eval_threads[context.nthreads];
    for(std::uint64_t i=0; i<context.nthreads; i++) {
      eval_threads[i] = std::thread(multi_eval_thread, i, poly_rcv, masks_with_dummies, std::ref(context), std::ref(sub_bins));
    }
    for(std::uint64_t i=0; i<context.nthreads; i++) {
      eval_threads[i].join();
    }
    const auto eval_poly_end_time = std::chrono::system_clock::now();
    const duration_millis eval_poly_duration = eval_poly_end_time - eval_poly_start_time;
    context.timings.polynomials += eval_poly_duration.count();

  } else {//OPPRF phase for other parties
    sub_bins.resize(1);

    //Hash
    auto simple_table_v = simple_hash(context, inputs);

    //OPRF
    auto masks = ClientOprf(context, simple_table_v, chls[0]);

    //OPPRF hint
    std::vector<std::uint64_t> polynomials = ClientEvaluateHint(context, masks);

    //Send hint
    sub_bins[0] = ClientSendHint(context, allsocks[0], polynomials);
   }
}

}
