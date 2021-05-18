#include "MPCHonestMajority/MPSI_Party.h"
#include "MPCHonestMajority/ZpKaratsubaElement.h"
#include <thread>
#include <iostream>
#include <vector>
#include <fstream>
#include <unistd.h>
#include <random>

using namespace std;

vector<vector<uint64_t>> global_bins;

void circuit_thread(int size, char** circuitArgv, vector<uint64_t>& bins, vector<ZpMersenneLongElement>& shares, int nbins) {
    MPSI_Party<ZpMersenneLongElement> mpsi(size, circuitArgv);
    mpsi.convertSharestoFieldType(bins, shares, nbins);
    cout<<"After sharing, thread "<< mpsi.m_partyId <<" : " <<bins[6]<<" "<<shares[6]<<endl;
    vector<ZpMersenneLongElement> secrets;
    mpsi.addShareOpen(nbins, shares, secrets);

    if(mpsi.m_partyId == 0) {
      cout<<"After opening additive share, thread "<< mpsi.m_partyId <<" : " <<shares[6]<<" "<<secrets[6]<<endl;
      vector<uint64_t> total_bin;
      uint64_t np = mpsi.N;
      uint64_t val;
      for(int i=0; i<nbins; i++) {
        val = 0;
        if(i == 6) {
          cout<<"Mid-way totaling, thread "<< mpsi.m_partyId <<" : " <<val <<endl;
        }
        val += global_bins[0][i];
        if(i == 6) {
          cout<<"Mid-way totaling, thread "<< mpsi.m_partyId <<" : " <<val <<endl;
        }
        for(int j=1; j< np; j++) {
          val += global_bins[j][i];
        }
        total_bin.push_back(val);
      }
      vector<ZpMersenneLongElement> totSecrets;
      mpsi.convertSharestoFieldType(total_bin, totSecrets, nbins);
      cout<<"After totaling, thread "<< mpsi.m_partyId <<" : " <<total_bin[6] <<" "<<totSecrets[6]<<" "<< secrets[6]<<endl;
      for(int i=0; i<nbins; i++) {
        if(secrets[i] != totSecrets[i]) {
          cout<<"Not equal at index "<< i << endl;
        }
      }
    }


    cout<<"End of Thread Call"<<endl;
    sleep(10);
    //mpsi.runMPSI();
}

void prepareArgs(char** circuitArgv, uint32_t role, uint64_t np, uint64_t nbins,
                 string outputFileName, string circuitFileName, string partiesFile) {
  circuitArgv[0] = "./build/MPCHonestMajority";
  circuitArgv[1] = "-partyID";
  sprintf(circuitArgv[2], "%lu", role);
  circuitArgv[3] = "-partiesNumber";
  sprintf(circuitArgv[4], "%llu", np);
  circuitArgv[5] = "-numBins";
  sprintf(circuitArgv[6], "%llu", nbins);
  circuitArgv[7] = "-inputsFile";
  string arg_val = "../in_party_" + to_string(role) + ".txt";
  sprintf(circuitArgv[8], arg_val.c_str());
  circuitArgv[9] = "-outputsFile";
  strcpy(circuitArgv[10], outputFileName.c_str());
  circuitArgv[11] = "-circuitFile";
  strcpy(circuitArgv[12], circuitFileName.c_str());
  circuitArgv[13] = "-fieldType";
  circuitArgv[14] = "ZpMersenne61";
  circuitArgv[15] = "-genRandomSharesType";
  circuitArgv[16] = "HIM";
  circuitArgv[17] = "-multType";
  circuitArgv[18] = "DN";
  circuitArgv[19] = "-verifyType";
  circuitArgv[20] = "Single";
  circuitArgv[21] = "-partiesFile";
  strcpy(circuitArgv[22], partiesFile.c_str());
  circuitArgv[23] = "-internalIterationsNumber";
  circuitArgv[24] = "1";
}


int main(int argc, char** argv) {

  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<uint64_t> dis;
  //cout<<"It Works!"<<endl;
  uint64_t np = atoi(argv[1]);
  uint64_t nbins = atoi(argv[2]);
  std::cout<<"Np"<<np<<std::endl;
  std::cout<<"Nbins"<<nbins<<std::endl;

  int size[np];
  char** circuitArgv[np];

  uint64_t val;
  for(uint32_t i=0; i<np; i++) {
    size[i] = 25;
    circuitArgv[i] = (char **) malloc(sizeof(char*)*(size[i]));

    for(int j=0; j < size[i]; j++) {
      circuitArgv[i][j] = (char *) malloc(sizeof(char)*50);
    }
    prepareArgs(circuitArgv[i], i, np, nbins, string(argv[3]), string(argv[4]), string(argv[5]));

    vector<uint64_t> bin;
    ifstream myfile;
    string inputFileName = "../in_party_" + to_string(i) + ".txt";
    myfile.open(inputFileName);
    for(int j=0; j<nbins; j++) {
      myfile >> val;
      //val = dis(gen);
      bin.push_back(val);
    }
    myfile.close();
    global_bins.push_back(bin);
  }

  std::thread cmp_threads[np];
  vector<vector<ZpMersenneLongElement>> shares(np);

  for(int i=0;i<np;i++) {
    cmp_threads[i] = std::thread(circuit_thread, size[i], std::ref(circuitArgv[i]), std::ref(global_bins[i]), std::ref(shares[i]), nbins);
  }

  for(int i=0; i<np; i++) {
    cmp_threads[i].join();
  }

  return 0;
}
