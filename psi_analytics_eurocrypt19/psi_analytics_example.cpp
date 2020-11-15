//
// \file psi_analytics_example.cpp
// \author Oleksandr Tkachenko
// \email tkachenko@encrypto.cs.tu-darmstadt.de
// \organization Cryptography and Privacy Engineering Group (ENCRYPTO)
// \TU Darmstadt, Computer Science department
//
// \copyright The MIT License. Copyright Oleksandr Tkachenko
//

#include <cassert>
#include <iostream>

#include <boost/program_options.hpp>
#include<fstream>
//#include <ENCRYPTO_utils/crypto/crypto.h>
//#include <ENCRYPTO_utils/parse_options.h>
#include "abycore/aby/abyparty.h"

#include "MPCHonestMajority/MPSI_Party.h"
#include "MPCHonestMajority/ZpKaratsubaElement.h"
#include <smmintrin.h>
#include <inttypes.h>
#include <stdio.h>

#include "common/psi_analytics.h"
#include "common/constants.h"
#include "common/psi_analytics_context.h"
#include <thread>
auto read_test_options(int32_t argcp, char **argvp) {
  namespace po = boost::program_options;
  ENCRYPTO::PsiAnalyticsContext context;
  po::options_description allowed("Allowed options");
  std::string type;
  // clang-format off
  allowed.add_options()("help,h", "produce this message")
  ("role,r",         po::value<decltype(context.role)>(&context.role)->required(),                                  "Role of the node")
  ("neles,n",        po::value<decltype(context.neles)>(&context.neles)->default_value(100u),                      "Number of my elements")
  ("bit-length,b",   po::value<decltype(context.bitlen)>(&context.bitlen)->default_value(61u),                      "Bit-length of the elements")
  ("epsilon,e",      po::value<decltype(context.epsilon)>(&context.epsilon)->default_value(1.27f),                   "Epsilon, a table size multiplier")
  ("threads,t",      po::value<decltype(context.nthreads)>(&context.nthreads)->default_value(1),                    "Number of threads")
  ("threshold,c",    po::value<decltype(context.threshold)>(&context.threshold)->default_value(0u),                 "Show PSI size if it is > threshold")
  ("nmegabins,m",    po::value<decltype(context.nmegabins)>(&context.nmegabins)->default_value(1u),                 "Number of mega bins")
  ("polysize,s",     po::value<decltype(context.polynomialsize)>(&context.polynomialsize)->default_value(0u),       "Size of the polynomial(s), default: neles")
  ("functions,f",    po::value<decltype(context.nfuns)>(&context.nfuns)->default_value(3u),                         "Number of hash functions in hash tables")
  ("num_parties,N",    po::value<decltype(context.np)>(&context.np)->default_value(4u),                         "Number of parties")
  ("file_address,F",    po::value<decltype(context.file_address)>(&context.file_address)->default_value("../../files/addresses"),                         "IP Addresses")
  ("type,y",         po::value<std::string>(&type)->default_value("None"),                                          "Function type {None, Threshold, Sum, SumIfGtThreshold}");
  // clang-format on

  po::variables_map vm;
  try {
    po::store(po::parse_command_line(argcp, argvp, allowed), vm);
    po::notify(vm);
  } catch (const boost::exception_detail::clone_impl<boost::exception_detail::error_info_injector<
               boost::program_options::required_option> > &e) {
    if (!vm.count("help")) {
      std::cout << e.what() << std::endl;
      std::cout << allowed << std::endl;
      exit(EXIT_FAILURE);
    }
  }

  if (vm.count("help")) {
    std::cout << allowed << "\n";
    exit(EXIT_SUCCESS);
  }

  if (type.compare("None") == 0) {
    context.analytics_type = ENCRYPTO::PsiAnalyticsContext::NONE;
  } else if (type.compare("Threshold") == 0) {
    context.analytics_type = ENCRYPTO::PsiAnalyticsContext::THRESHOLD;
  } else if (type.compare("Sum") == 0) {
    context.analytics_type = ENCRYPTO::PsiAnalyticsContext::SUM;
  } else if (type.compare("SumIfGtThreshold") == 0) {
    context.analytics_type = ENCRYPTO::PsiAnalyticsContext::SUM_IF_GT_THRESHOLD;
  } else {
    std::string error_msg(std::string("Unknown function type: " + type));
    throw std::runtime_error(error_msg.c_str());
  }

  if(context.nthreads == 0) {
    context.nthreads = std::thread::hardware_concurrency();
  }

  if(context.nthreads > context.np-1) {
    context.nthreads = context.np-1;
  }

  if (context.polynomialsize == 0) {
    context.polynomialsize = context.neles * context.nfuns;
  }
  context.polynomialbytelength = context.polynomialsize * sizeof(std::uint64_t);

  context.nbins = context.neles * context.epsilon;
  //Setting network parameters
  if(context.role == P_0) {
    context.port.reserve(context.np);
    //store addresses of other parties
    std::ifstream in(context.file_address, std::ifstream::in);
    /*if(!exists(filename)) {
      std::cerr << "Address file doesn't exist" << std::endl;
      exit(-1);
    }*/
    //std::cout<< "Total Number of Parties: " << context.np <<", File Name: " << context.file_address << std::endl;
    std::string address;
    for(int i=0; i< context.np; i++) {
      in >> address;
      //std::cout<< "Address: " << address << std::endl;
      context.address.push_back(address);
      context.port[i] = REF_PORT + i*2;
    }
    in.close();
  } else {
    context.port.reserve(1);
    context.address.push_back(DEF_ADDRESS);
    context.port[0] = REF_PORT + 2*(context.role-1);
  }

  //Setting Circuit Component parameters
  context.outputFileName = "output.txt";
  context.circuitFileName = "ic.txt";
  context.partiesFile = "Parties.txt";

  context.fieldType = "ZpMersenne61";
  context.genRandomSharesType = "HIM";
  context.multType = "DN";
  context.verifyType = "Single";

  return context;
}

void prepareArgs(ENCRYPTO::PsiAnalyticsContext context, int& size, char** circuitArgv) {
size = 25;
circuitArgv = (char **) malloc(sizeof(char*)*(size));
for(int i=0; i < size; i++) {
  circuitArgv[i] = (char *) malloc(sizeof(char)*50);
}
circuitArgv[0] = "./build/MPCHonestMajority";
circuitArgv[1] = "-partyID";
sprintf(circuitArgv[2], "%lu", context.role);
circuitArgv[3] = "-partiesNumber";
sprintf(circuitArgv[4], "%llu", context.np);
/*circuitArgv[4] = to_string(context.np);
circuitArgv[5] = "-numBins";
circuitArgv[6] = to_string(context.nbins);
circuitArgv[7] = "-inputsFile";
circuitArgv[8] = "../../in_party_1.txt";
circuitArgv[9] = "-outputsFile";
circuitArgv[10] = context.
circuitArgv[11] = "-circuitFile";
/*ic.txt
-fieldType
ZpMersenne61
-genRandomSharesType
HIM
-multType
DN
-verifyType
Single
-partiesFile
Parties.txt
-internalIterationsNumber
1*/
}

int main(int argc, char **argv) {
  auto context = read_test_options(argc, argv);
  auto gen_bitlen = static_cast<std::size_t>(std::ceil(std::log2(context.neles))) + 3;
  //auto inputs = ENCRYPTO::GeneratePseudoRandomElements(context.neles, gen_bitlen, context.role * 12345);
  auto inputs = ENCRYPTO::GeneratePseudoRandomElements(context.neles, gen_bitlen);

  int size;
  char** circuitArgv;
  prepareArgs(context, size, circuitArgv);
  for(int i=0; i<1;i++){
      std::cout<< "Circuit Param "<<circuitArgv[i]<<std::endl;
  }

  //auto inputs = ENCRYPTO::GenerateSequentialElements(context.neles);
/*
  std::vector<uint64_t> inputs;
  for(int i=0; i<1024; i++) {
    uint64_t val = i + context.role;
    inputs.push_back(val);
    //std::cout << val << " ";
  }
  //std::cout << std::endl;
*/
  std::vector<uint64_t> bins = ENCRYPTO::run_psi_analytics(inputs, context);
  //std::vector<uint64_t> bins = ENCRYPTO::GeneratePseudoRandomElements(context.nbins, gen_bitlen);
  std::cout << "PSI circuit successfully executed: " << bins[0] << std::endl;
  std::string outfile = "../in_party_"+std::to_string(context.role)+".txt";
  //std::cout << "Printing " << bins[0] << " to " << outfile << std::endl;
  ENCRYPTO::PrintBins(bins, outfile, context);
  PrintTimings(context);

  /*MPSI_Party<ZpMersenneLongElement> mpsi(context.role, context.np, context.nbins, context.outputFileName,
                                         context.circuitFileName, context.fieldType, context.genRandomSharesType,
                                         context.multType, context.verifyType, context.partiesFile, bins);*/



    /*
   CmdParser parser;
   auto parameters = parser.parseArguments("", argc, argv);
   int times = stoi(parser.getValueByKey(parameters, "internalIterationsNumber"));
   string fieldType(parser.getValueByKey(parameters, "fieldType"));

   if(fieldType.compare("ZpMersenne61") == 0)
   {

       MPSI_Party<ZpMersenneLongElement> mpsi(argc, argv);
       auto t1 = high_resolution_clock::now();
       mpsi.runMPSI();

       auto t2 = high_resolution_clock::now();

       auto duration = duration_cast<milliseconds>(t2-t1).count();
       cout << "time in milliseconds for " << times << " runs: " << duration << endl;

       cout << "end main" << '\n';

   }
 */
 return EXIT_SUCCESS;
}
