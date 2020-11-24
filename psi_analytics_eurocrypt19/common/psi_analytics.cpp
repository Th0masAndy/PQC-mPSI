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

#include "psi_analytics.h"
//#include "constants.h"
#include "connection.h"
#include "socket.h"
//#include "abycore/sharing/boolsharing.h"
//#include "abycore/sharing/sharing.h"

#include "ots/ots.h"
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

//using share_ptr = std::shared_ptr<share>;

using milliseconds_ratio = std::ratio<1, 1000>;
using duration_millis = std::chrono::duration<double, milliseconds_ratio>;

auto cuckoo_hash(const std::vector<uint64_t> &elements, PsiAnalyticsContext &context) {
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

auto simple_hash(const std::vector<uint64_t> &elements, PsiAnalyticsContext &context) {
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

std::vector<uint64_t> OprfClient(const std::vector<uint64_t> &cuckoo_table_v, PsiAnalyticsContext &context, int server_index) {
  const auto oprf_start_time = std::chrono::system_clock::now();

  std::vector<uint64_t> masks_with_dummies = ot_receiver(cuckoo_table_v, context, server_index);

  const auto oprf_end_time = std::chrono::system_clock::now();
  const duration_millis oprf_duration = oprf_end_time - oprf_start_time;
  context.timings.oprf += oprf_duration.count();

  return masks_with_dummies;
}

std::vector<std::vector<uint64_t>> OprfServer(const std::vector<std::vector<uint64_t>> &simple_table_v, PsiAnalyticsContext &context) {
  const auto oprf_start_time = std::chrono::system_clock::now();

  auto masks = ot_sender(simple_table_v, context);
  const auto oprf_end_time = std::chrono::system_clock::now();
  const duration_millis oprf_duration = oprf_end_time - oprf_start_time;
  context.timings.oprf = oprf_duration.count();

  return masks;
}

std::vector<uint64_t> PolynomialsServer(const std::vector<std::vector<uint64_t>> &masks, PsiAnalyticsContext &context) {
  const auto polynomials_start_time = std::chrono::system_clock::now();

  std::vector<uint64_t> polynomials(context.nmegabins * context.polynomialsize, 0);
  std::vector<uint64_t> content_of_bins(context.nbins);

  std::random_device urandom("/dev/urandom");
  std::uniform_int_distribution<uint64_t> dist(0,
                                               (1ull << context.maxbitlen) - 1);  // [0,2^elebitlen)

  // generate random numbers to use for mapping the polynomial to
  std::generate(content_of_bins.begin(), content_of_bins.end(), [&]() { return dist(urandom); });
  {
    auto tmp = content_of_bins;
    std::sort(tmp.begin(), tmp.end());
    auto last = std::unique(tmp.begin(), tmp.end());
    tmp.erase(last, tmp.end());
    assert(tmp.size() == content_of_bins.size());
  }

  InterpolatePolynomials(polynomials, content_of_bins, masks, context);
  context.content_of_bins = content_of_bins;

  const auto polynomials_end_time = std::chrono::system_clock::now();
  const duration_millis polynomials_duration = polynomials_end_time - polynomials_start_time;
  context.timings.polynomials = polynomials_duration.count();
  return polynomials;
}

std::vector<uint64_t> OpprgPsiClient(const std::vector<uint64_t> &elements,
                                     PsiAnalyticsContext &context, int server_index,
				     const std::vector<uint64_t> &cuckoo_table_v) {
  /*  std::unique_ptr<CSocket> sock1 =
      EstablishConnection(context.address[server_index], context.port[server_index], static_cast<e_role>(context.role));
  sock1->Close();*/

  std::vector<uint64_t> masks_with_dummies = OprfClient(cuckoo_table_v, context, server_index);
  std::unique_ptr<CSocket> sock =
      EstablishConnection(context.address[server_index], context.port[server_index], static_cast<e_role>(context.role));

  const auto nbinsinmegabin = ceil_divide(context.nbins, context.nmegabins);
  std::vector<std::vector<ZpMersenneLongElement1>> polynomials(context.nmegabins);
  std::vector<ZpMersenneLongElement1> X(context.nbins), Y(context.nbins);
  for (auto &polynomial : polynomials) {
    polynomial.resize(context.polynomialsize);
  }

  for (auto i = 0ull; i < X.size(); ++i) {
    X.at(i).elem = masks_with_dummies.at(i);
  }

  std::vector<uint8_t> poly_rcv_buffer(context.nmegabins * context.polynomialbytelength, 0);

  const auto receiving_start_time = std::chrono::system_clock::now();

  sock->Receive(poly_rcv_buffer.data(), context.nmegabins * context.polynomialbytelength);
  sock->Close();

  const auto receiving_end_time = std::chrono::system_clock::now();
  const duration_millis sending_duration = receiving_end_time - receiving_start_time;
  context.timings.polynomials_transmission += sending_duration.count();

  const auto eval_poly_start_time = std::chrono::system_clock::now();
  for (auto poly_i = 0ull; poly_i < polynomials.size(); ++poly_i) {
    for (auto coeff_i = 0ull; coeff_i < context.polynomialsize; ++coeff_i) {
      polynomials.at(poly_i).at(coeff_i).elem = (reinterpret_cast<uint64_t *>(
          poly_rcv_buffer.data()))[poly_i * context.polynomialsize + coeff_i];
    }
  }

  for (auto i = 0ull; i < X.size(); ++i) {
    std::size_t p = i / nbinsinmegabin;
    Poly::evalMersenne(Y.at(i), polynomials.at(p), X.at(i));
  }

  const auto eval_poly_end_time = std::chrono::system_clock::now();
  const duration_millis eval_poly_duration = eval_poly_end_time - eval_poly_start_time;
  context.timings.polynomials += eval_poly_duration.count();

  std::vector<uint64_t> raw_bin_result;
  raw_bin_result.reserve(X.size());
  for (auto i = 0ull; i < X.size(); ++i) {
    raw_bin_result.push_back(X[i].elem ^ Y[i].elem);
  }

  return raw_bin_result;
}

std::vector<uint64_t> OpprgPsiServer(const std::vector<uint64_t> &elements,
                                     PsiAnalyticsContext &context) {
  auto simple_table_v = simple_hash(elements, context);

  auto masks = OprfServer(simple_table_v, context);
/*
  const auto polynomials_start_time = std::chrono::system_clock::now();

  std::vector<uint64_t> polynomials(context.nmegabins * context.polynomialsize, 0);
  std::vector<uint64_t> content_of_bins(context.nbins);

  std::random_device urandom("/dev/urandom");
  std::uniform_int_distribution<uint64_t> dist(0,
                                               (1ull << context.maxbitlen) - 1);  // [0,2^elebitlen)

  // generate random numbers to use for mapping the polynomial to
  std::generate(content_of_bins.begin(), content_of_bins.end(), [&]() { return dist(urandom); });
  {
    auto tmp = content_of_bins;
    std::sort(tmp.begin(), tmp.end());
    auto last = std::unique(tmp.begin(), tmp.end());
    tmp.erase(last, tmp.end());
    assert(tmp.size() == content_of_bins.size());
  }

//  std::unique_ptr<CSocket> sock = EstablishConnection(context.address[0], context.port[0], static_cast<e_role>(context.role));

  InterpolatePolynomials(polynomials, content_of_bins, masks, context);

  const auto polynomials_end_time = std::chrono::system_clock::now();
  const duration_millis polynomials_duration = polynomials_end_time - polynomials_start_time;
  context.timings.polynomials = polynomials_duration.count();
*/

  std::vector<uint64_t> polynomials = PolynomialsServer(masks, context);
  std::unique_ptr<CSocket> sock =
      EstablishConnection(context.address[0], context.port[0], static_cast<e_role>(context.role));

  const auto sending_start_time = std::chrono::system_clock::now();

  // send polynomials to the receiver
  sock->Send((uint8_t *)polynomials.data(), context.nmegabins * context.polynomialbytelength);
  sock->Close();

  const auto sending_end_time = std::chrono::system_clock::now();
  const duration_millis sending_duration = sending_end_time - sending_start_time;
  context.timings.polynomials_transmission = sending_duration.count();

  return context.content_of_bins;
}

void InterpolatePolynomials(std::vector<uint64_t> &polynomials,
                            std::vector<uint64_t> &content_of_bins,
                            const std::vector<std::vector<uint64_t>> &masks,
                            PsiAnalyticsContext &context) {
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

    InterpolatePolynomialsPaddedWithDummies(polynomial, bin, masks_in_bin, nbinsinmegabin, context);
    masks_offset += nbinsinmegabin;
  }

  assert(masks_offset == masks.size());
}

void InterpolatePolynomialsPaddedWithDummies(
    std::vector<uint64_t>::iterator polynomial_offset,
    std::vector<uint64_t>::const_iterator random_value_in_bin,
    std::vector<std::vector<uint64_t>>::const_iterator masks_for_elems_in_bin,
    std::size_t nbins_in_megabin, PsiAnalyticsContext &context) {
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

std::unique_ptr<CSocket> EstablishConnection(const std::string &address, uint16_t port,
                                             e_role role) {
  std::unique_ptr<CSocket> socket;
  if (role == SERVER) {
    socket = Listen(address.c_str(), port);
  } else {
    socket = Connect(address.c_str(), port);
  }
  assert(socket);
  return socket;
}

std::size_t PlainIntersectionSize(std::vector<std::uint64_t> v1, std::vector<std::uint64_t> v2) {
  std::vector<std::uint64_t> intersection_v;

  std::sort(v1.begin(), v1.end());
  std::sort(v2.begin(), v2.end());

  std::set_intersection(v1.begin(), v1.end(), v2.begin(), v2.end(), back_inserter(intersection_v));
  return intersection_v.size();
}

void PrintTimings(const PsiAnalyticsContext &context) {
  std::cout << context.role << ": Printing timings..." << std::endl;
  std::cout << context.role << ": Time for hashing " << context.timings.hashing << " ms\n";
  std::cout << context.role << ": Time for OPRF " << context.timings.oprf << " ms\n";
  std::cout << context.role << ": Time for polynomials " << context.timings.polynomials << " ms\n";
  std::cout << context.role << ": Time for transmission of the polynomials "
            << context.timings.polynomials_transmission << " ms\n";
  std::cout << context.role << ": Time for OPPRF " << context.timings.opprf << " ms\n";
  std::cout << context.role << ": Time for circuit " << context.timings.circuit << " ms\n";
//  std::cout << "Time for OPPRF " << context.timings.opprf << " ms\n";

  //std::cout << "ABY timings: online time " << context.timings.aby_online << " ms, setup time "
  //          << context.timings.aby_setup << " ms, total time " << context.timings.aby_total
  //          << " ms\n";

  std::cout << context.role << ": Total runtime: " << context.timings.total << "ms\n";
  //std::cout << "Total runtime w/o base OTs: "
  //          << context.timings.total - context.timings.base_ots_libote
  //          << "ms\n";
}

void PrintBins(std::vector<uint64_t> &bins, std::string outFile, PsiAnalyticsContext &context) {
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

void multi_opprf_thread(int tid, std::vector<std::vector<uint64_t>> &sub_bins, std::vector<uint64_t> inputs,
                        PsiAnalyticsContext &context, std::vector<uint64_t> table) {
    for(int i=tid; i < context.np-1; i=i+context.nthreads) {
      sub_bins[i] = OpprgPsiClient(inputs, context, i, table);
    }
}

std::vector<uint64_t> run_psi_analytics(const std::vector<std::uint64_t> &inputs, PsiAnalyticsContext &context) {
  // establish network connection
  /*std::unique_ptr<CSocket> sock =
      EstablishConnection(context.address, context.port, static_cast<e_role>(context.role));
  sock->Close();
  const auto clock_time_total_start = std::chrono::system_clock::now();
  */
  //const auto start_time = std::chrono::system_clock::now();
  std::vector<uint64_t> bins;

  // create hash tables from the elements
  if (context.role == P_0) {

    bins.reserve(context.nbins);
    for(uint64_t i=0; i<context.nbins; i++) {
    	bins[i] = 0;
    }
    std::vector<std::vector<uint64_t>> sub_bins(context.np-1);
    std::vector<uint64_t> table;
    table = cuckoo_hash(inputs, context);

    std::thread opprf_threads[context.nthreads];
    for(int i=0; i<context.nthreads; i++) {
      opprf_threads[i] = std::thread(multi_opprf_thread, i, std::ref(sub_bins), inputs, std::ref(context), table);
    }

    for (int i=0; i<context.nthreads; i++) {
      opprf_threads[i].join();
    }

    TemplateField<ZpMersenneLongElement1> *field;
    std::vector<ZpMersenneLongElement1> field_bins;
    for(uint64_t j=0; j< context.nbins; j++) {
      field_bins.push_back(field->GetElement(sub_bins[0][j]));
    }

    for(uint64_t i=1; i< context.np-1; i++) {
      for(uint64_t j=0; j< context.nbins; j++) {
          field_bins[j] = field_bins[j]+field->GetElement(sub_bins[i][j]);
      }
    }

    for(uint64_t i=0; i< context.np-1; i++) {
      for(uint64_t j=0; j< context.nbins; j++) {
        bins[j] = field_bins[j].elem;
      }
    }
  } else {
    bins = OpprgPsiServer(inputs, context);
  }

//  std::cout << "First bin of " << context.role << " is " << bins[0] << "\n";

  std::string outfile = "../in_party_" + std::to_string(context.role) + ".txt";

  //PrintBins(bins, outfile, context);
  //const auto end_time = std::chrono::system_clock::now();
  //const duration_millis total_duration = end_time - start_time;
  //context.timings.total = total_duration.count();

  return bins;
}

}
