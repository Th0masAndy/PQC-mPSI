/*
 * \author Akash Shah
 * \email akashshah08@outlook.com
 * \organization Microsoft Research India
 *
 * \copyright the MIT License. Copyright (c) 2021 Microsoft Research
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the Software
 * is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMTED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR
 * A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
 * OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include "ProtocolParty2.h"

#define mpsi_print false

template <class FieldType>
class CircuitPSI : public ProtocolParty<FieldType> {
 public:
  /*Inherited from ProtocolParty:
   * Variables:
   * int N, M, T, m_partyId
   * VDM<FieldType> matrix_vand
   * vector<FieldType> firstRowVandInverse
   * TemplateField<FieldType> *field
   * vector<shared_ptr<ProtocolPartyData>> parties
   * vector<FieldType> randomTAnd2TShares
   * (All other variables are protected)
   *
   * Methods:
   * Constructor
   * roundFunctionSync, exchangeData, roundFunctionSyncBroadcast, recData, roundFunctionSyncForP1,
   *   recDataToP1, sendDataToP1, sendFromP1
   * run, runOffline, runOnline
   * readMyInputs
   * initialisationPhase
   * initFirstRowInvVDM
   * preparationPhase, generateBeaverTriples, DNHonestMultiplication, offlineDNForMultiplication
   * broadcast
   * inputPhase, generateRandomShares, generateRandom2TAndTShares
   * reconstructShare, openShare
   * processAdditions, processSubtractions, processMultiplications, processMultDN, processSMult,
   *   processRandoms, processNotMult
   * computationPhase
   * interpolate, tinterpolate
   * generatePseudoRandomElements
   * outputPhase
   * Destructor
   */
  uint64_t prime_val;  // Prime modulus of the field
  uint64_t prime_bitlen;
  uint64_t triple_ctr;      // number of multiplication triples per bin
  vector<uint64_t> sindex;  // indices where the bit representation of the prime has bit 1

  uint64_t num_bins;     // number of bins
  uint64_t num_triples;  // number of multiplication triples
  uint64_t sent_bytes;   // total number of bytes sent
  uint64_t recv_bytes;   // total number of bytes received

  vector<FieldType> masks;    // the shares of the masks s_j for each value to be multiplied with
  vector<FieldType> add_a;    // additive shares of a_j
  vector<FieldType> a_vals;   // threshold shares of a_j
  vector<FieldType> outputs;  // the shares of s_j*a_j
  vector<FieldType> randomTAndAddShares;  // shares of r_j for conversion of inputs to T-sharings
  vector<FieldType> cpsi_outputs;  // shares of multiplication output of polynomial for threshold

  CircuitPSI(int argc, char* argv[]);

  // read num_bins MPSI inputs
  void readMPSIInputs(vector<vector<uint8_t>>& bins, uint64_t nbins);

  // convert shares to field type for testing
  void convertSharestoFieldType(vector<uint8_t>& bins, vector<FieldType>& shares, uint64_t nbins);

  // perform MPSI
  uint64_t runMPSI();

  // prepare additive and T-threshold sharings of secret random value r_j using DN07's protocol
  void modDoubleRandom(uint64_t no_random, vector<FieldType>& randomElementsToFill);

  // make shares of values
  void reshare(vector<FieldType>& vals, vector<FieldType>& shares);

  // evaluate circuit
  uint64_t evaluateCircuit();

  // convert parties' additive shares to T-threshold shares
  void additiveToThreshold();

  // Compute shares of the intersection
  void computeIntersectionShares();

  // open the result shares
  void leaderOpen();

  // open an additive sharing
  // code similar to DNHonestMultiplication() as only P1 opens
  void addShareOpen(uint64_t numShares, vector<FieldType>& Shares, vector<FieldType>& Secrets);

  // print output results
  uint64_t outputPrint();

  ~CircuitPSI() {}

 private:
  // Test the outputs of various functions
  void testOpenAdd();
  void testShareGenNoComm(vector<FieldType>& y1, vector<FieldType>& y2);
  void testShareGenWithComm();
  void testResharing();
  void testConversion();
};

template <class FieldType>
CircuitPSI<FieldType>::CircuitPSI(int argc, char* argv[]) : ProtocolParty<FieldType>(argc, argv) {
  // The call to ProtocolParty constructor initializes inherited variables
  //  N, T, m_partyID, as well as the VDM matrix and related vectors.

  // Initialize global variables that have not been inherited.

  // cout << this->m_partyId << ": Entered constructor." << endl;
  CmdParser parser = this->getParser();

  prime_val = (uint64_t)stoi(parser.getValueByKey(this->arguments, "primemod"));
  prime_bitlen = (uint64_t)(ceil(log2(prime_val)));

  sent_bytes = 0;
  recv_bytes = 0;

  // cout << this->m_partyId << ": Element size is " << this->field->getElementSizeInBytes() << "."
  // << endl;

  // Generation of shared values, such as triples, must be done later.

  // final circuit intersection variables
  uint64_t radix = prime_val - 1;
  int r = 0;
  int i = 0;
  while (radix != 0) {
    r = radix % 2;
    radix = radix / 2;
    if (r == 1) {
      sindex.push_back(i);
    }
    i++;
  }

  triple_ctr = prime_bitlen + sindex.size() - 2;
}

/*
 * read num_bins MPSI inputs from arguments
 */
template <class FieldType>
void CircuitPSI<FieldType>::readMPSIInputs(vector<vector<uint8_t>>& bins, uint64_t nbins) {
  uint8_t input;
  uint64_t i = 0;
  uint64_t j = 0;

  for (int i = 0; i < nbins; i++) {
    add_a.push_back(this->field->GetElement(bins[0][i]));
  }

  if (this->m_partyId == 0) {
    for (int j = 1; j < this->N - 1; j++) {
      for (int i = 0; i < nbins; i++) {
        add_a[i] = add_a[i] + this->field->GetElement(bins[j][i]);
      }
    }
    /*cout<<"Check point 6"<<endl;
    for(int i=0; i< nbins; i++) {
            add_a[i] = *(this->field->GetZero()) - add_a[i];
    }*/
  }

  num_bins = add_a.size();
  // cout<<"Num Bins: "<<num_bins<<endl;
  /*
          if (mpsi_print == true) {
                  cout << this->m_partyId << ": " << num_bins << " values read." << endl;
          }*/
  // cout<<"Num Bins: "<< num_bins<<endl;
  // cout<<"Reading Completed!"<<endl;
}

/*
 * convert shares to field type
 */
template <class FieldType>
void CircuitPSI<FieldType>::convertSharestoFieldType(vector<uint8_t>& bins,
                                                     vector<FieldType>& shares, uint64_t nbins) {
  uint8_t input;
  uint64_t j = 0;
  for (int i = 0; i < nbins; i++) {
    input = bins[j++];
    if (input > 0) {
      shares.push_back(this->field->GetElement(input));
    } else {
      shares.push_back(*(this->field->GetZero()));
    }
    if (this->m_partyId == 0) {
      shares[i] = *(this->field->GetZero()) - shares[i];
    }
  }
}

/*
 * Initialize parameters and shared randomness and call circuit evaluation method
 */
template <class FieldType>
uint64_t CircuitPSI<FieldType>::runMPSI() {
  uint64_t counter = 0;
  masks.resize(num_bins);
  a_vals.resize(num_bins);
  outputs.resize(num_bins);
  cpsi_outputs.resize(num_bins);
  num_triples = triple_ctr * num_bins;

  auto t1 = high_resolution_clock::now();
  this->honestMult->invokeOffline();
  auto t2 = high_resolution_clock::now();
  auto dur1 = duration_cast<milliseconds>(t2 - t1).count();
  // cout << this->m_partyId << ": Time to initialise matrices is: " << dur1 << " milliseconds." <<
  // endl;

  // Generate random T-sharings
  auto t3 = high_resolution_clock::now();
  this->generateRandomShares(num_bins, masks);
  auto t4 = high_resolution_clock::now();
  auto dur2 = duration_cast<milliseconds>(t4 - t3).count();
  // cout << this->m_partyId << ": T-sharings generated in " << dur3 << "milliseconds." << endl;

  // Generate random additive and T-sharings
  auto t5 = high_resolution_clock::now();
  modDoubleRandom(num_bins, randomTAndAddShares);
  auto t6 = high_resolution_clock::now();
  auto dur3 = duration_cast<milliseconds>(t6 - t5).count();
  // cout << this->m_partyId << ": T- and additive sharings generated in " << dur2 << "
  // milliseconds." << endl;

  // Generate random T and 2T sharings for multiplication
  auto t7 = high_resolution_clock::now();
  this->generateRandom2TAndTShares(num_triples, this->randomTAnd2TShares);
  auto t8 = high_resolution_clock::now();
  auto dur4 = duration_cast<milliseconds>(t8 - t7).count();
  // cout << this->m_partyId << ": T- and 2T-sharings generated in " << dur4 << " milliseconds." <<
  // endl;

  // Evaluate the circuit
  counter = evaluateCircuit();
  return counter;
}

/*
 * prepare additive and T-threshold sharings of secret random value r_j using DN07's protocol
 */
template <class FieldType>
void CircuitPSI<FieldType>::modDoubleRandom(uint64_t no_random,
                                            vector<FieldType>& randomElementsToFill) {
  // cout << this->m_partyId <<  ": Generating double sharings..." << endl;
  int index = 0;
  int N = this->N;
  int T = this->T;
  // TemplateField<FieldType> &field = this->field;

  vector<FieldType> x1(N), y1(N), y2(N), t1(N), r1(N), t2(N), r2(N);
  vector<vector<FieldType>> sendBufsElements(N);
  vector<vector<byte>> sendBufsBytes(N);
  vector<vector<byte>> recBufsBytes(N);
  // the number of buckets (each bucket requires one double-sharing
  // from each party and gives N-2T random double-sharings)
  uint64_t no_buckets = (no_random / (N - T)) + 1;
  int fieldByteSize = this->field->getElementSizeInBytes();

  // maybe add some elements if a partial bucket is needed
  randomElementsToFill.resize(no_buckets * (N - T) * 2);

  for (int i = 0; i < N; i++) {
    sendBufsElements[i].resize(no_buckets * 2);
    sendBufsBytes[i].resize(no_buckets * fieldByteSize * 2);
    recBufsBytes[i].resize(no_buckets * fieldByteSize * 2);
  }

  // cout << this->m_partyId << ": no_random: " << no_random << " no_buckets: " << no_buckets << "
  // N: " << N << " T: " << T << endl;

  /**
   *  generate random sharings.
   *  first degree T, then additive
   *
   */
  for (uint64_t k = 0; k < no_buckets; k++) {
    // generate random degree-T polynomial
    for (int i = 0; i < T + 1; i++) {
      // A random field element, uniform distribution,
      // note that x1[0] is the secret which is also random
      x1[i] = this->field->Random();
    }

    this->matrix_vand.MatrixMult(x1, y1, T + 1);  // eval poly at alpha-positions

    y2[0] = x1[0];
    // generate N-1 random elements
    for (int i = 1; i < N; i++) {
      // A random field element, uniform distribution
      y2[i] = this->field->Random();
      // all y2[i] generated so far are additive shares of the secret x1[0]
      y2[0] = y2[0] - y2[i];
    }
    // testShareGenNoComm(y1, y2);

    // prepare shares to be sent
    for (int i = 0; i < N; i++) {
      // cout << "y1[ " <<i<< "]" <<y1[i] << " y2[ " << i << "]" << y2[i] << "\n";
      sendBufsElements[i][2 * k] = y1[i];
      sendBufsElements[i][2 * k + 1] = y2[i];
    }
  }

  for (int i = 0; i < N; i++) {
    for (uint64_t j = 0; j < sendBufsElements[i].size(); j++) {
      this->field->elementToBytes(sendBufsBytes[i].data() + (j * fieldByteSize),
                                  sendBufsElements[i][j]);
    }
  }

  this->roundFunctionSync(sendBufsBytes, recBufsBytes, 1);

  for (uint64_t k = 0; k < no_buckets; k++) {
    for (int i = 0; i < N; i++) {
      t1[i] = this->field->bytesToElement(recBufsBytes[i].data() + (2 * k * fieldByteSize));
      t2[i] = this->field->bytesToElement(recBufsBytes[i].data() + ((2 * k + 1) * fieldByteSize));
    }
    this->matrix_vand_transpose.MatrixMult(t1, r1, N - T);
    this->matrix_vand_transpose.MatrixMult(t2, r2, N - T);

    // copy the resulting vector to the array of randoms
    for (int i = 0; i < (N - T); i++) {
      randomElementsToFill[index * 2] = r1[i];
      randomElementsToFill[index * 2 + 1] = r2[i];
      index++;
    }
  }

  if (mpsi_print == true) {
    cout << this->m_partyId << ": First pair of shares is " << randomElementsToFill[0] << " "
         << randomElementsToFill[1] << endl;
  }
}

/*
 * Leader receives additive shares from everyone else,
 * reconstructs, and saves in secrets
 * DOES NOT SEND reconstructions
 * Code similar to ::DNHonestMultiplication
 */
template <class FieldType>
void CircuitPSI<FieldType>::addShareOpen(uint64_t num_vals, vector<FieldType>& shares,
                                         vector<FieldType>& secrets) {
  // cout << this->m_partyId << ": Reconstructing additive shares..." << endl;

  int fieldByteSize = this->field->getElementSizeInBytes();
  vector<vector<byte>> recBufsBytes;
  vector<byte> sendBufsBytes;
  vector<byte> aPlusRSharesBytes(num_vals * fieldByteSize);
  int i;
  uint64_t j;
  int N = this->N;

  secrets.resize(num_vals);

  for (j = 0; j < num_vals; j++) {
    this->field->elementToBytes(aPlusRSharesBytes.data() + (j * fieldByteSize), shares[j]);
  }

  if (this->m_partyId == 0) {
    recBufsBytes.resize(N);

    for (i = 0; i < N; i++) {
      recBufsBytes[i].resize(num_vals * fieldByteSize);
    }

    // uint64_t recSize = N * num_vals * fieldByteSize;
    // cout << "In addShareOpen(), leader receives: " << recSize << " in total." << endl;

    // receive the shares from all the other parties
    this->roundFunctionSyncForP1(aPlusRSharesBytes, recBufsBytes);
  } else {  // since I am not party 1 parties[0]->getID()=1
    // send the shares to p1
    this->parties[0]->getChannel()->write(aPlusRSharesBytes.data(), aPlusRSharesBytes.size());
  }

  // reconstruct the shares recieved from the other parties
  if (this->m_partyId == 0) {
    for (j = 0; j < num_vals; j++) {
      secrets[j] = *(this->field->GetZero());
      for (i = 0; i < N; i++) {
        secrets[j] += this->field->bytesToElement(recBufsBytes[i].data() + (j * fieldByteSize));
      }
    }
  }
}

/*
 * Share given values as T-shares and send to everyone else
 */
template <class FieldType>
void CircuitPSI<FieldType>::reshare(vector<FieldType>& vals, vector<FieldType>& shares) {
  int N = this->N;
  int T = this->T;
  uint64_t no_vals = vals.size();

  vector<FieldType> x1(N), y1(N);
  vector<vector<FieldType>> sendBufsElements(N);
  vector<vector<byte>> sendBufsBytes(N);
  vector<vector<byte>> recBufsBytes(N);
  vector<vector<FieldType>> recBufsElements(N);

  int fieldByteSize = this->field->getElementSizeInBytes();

  if (this->m_partyId == 0) {
    // generate T-sharings of the values in vals
    for (uint64_t k = 0; k < no_vals; k++) {
      // set x1[0] as the secret to be shared
      x1[0] = vals[k];
      // generate random degree-T polynomial
      for (int i = 1; i < T + 1; i++) {
        // A random field element, uniform distribution
        x1[i] = this->field->Random();
      }

      this->matrix_vand.MatrixMult(x1, y1, T + 1);  // eval poly at alpha-positions

      // prepare shares to be sent
      for (int i = 0; i < N; i++) {
        // cout << "y1[ " <<i<< "]" <<y1[i] << endl;
        sendBufsElements[i].push_back(y1[i]);
      }
      shares[k] = y1[0];
    }

    // cout << "Sharings generated \n";

    for (int i = 0; i < N; i++) {
      sendBufsBytes[i].resize(sendBufsElements[i].size() * fieldByteSize);
      recBufsBytes[i].resize(num_bins * fieldByteSize);
      for (uint64_t j = 0; j < sendBufsElements[i].size(); j++) {
        this->field->elementToBytes(sendBufsBytes[i].data() + (j * fieldByteSize),
                                    sendBufsElements[i][j]);
      }
      // cout << sendBufsElements[i].size() << " " << sendBufsBytes[i].size() << " " <<
      // recBufsBytes[i].size();
    }
  } else {
    for (int i = 0; i < N; i++) {
      sendBufsBytes[i].resize(num_bins * fieldByteSize);
      recBufsBytes[i].resize(num_bins * fieldByteSize);
      for (uint64_t j = 0; j < num_bins; j++) {
        this->field->elementToBytes(sendBufsBytes[i].data(), *(this->field->GetZero()));
      }
    }
  }

  // cout << "byte conversion done \n";

  this->roundFunctionSync(sendBufsBytes, recBufsBytes, 2);

  // cout << "roundFunctionSync() done ";

  if (this->m_partyId != 0) {
    for (uint64_t k = 0; k < no_vals; k++) {
      shares[k] = this->field->bytesToElement(recBufsBytes[0].data() + (k * fieldByteSize));
    }
  }
  // cout << "converted back to field elements...\n";

  if (mpsi_print == true) {
    cout << this->m_partyId << "First t-sharing received is: " << shares[0] << endl;
  }
}

/*
 * Step 1 of the online phase:
 * The parties convert their additive shares to T-threshold shares
 * They do this by collectively adding shares of a shared random value to
 * their additive shares,
 * then the leader reconstructs this masked additive value,
 * and reshares it as T-threshold shares,
 * from which the parties subtract the T-threshold shares of the same random value
 * to get T-threshold shares of the original secret
 */
template <class FieldType>
void CircuitPSI<FieldType>::additiveToThreshold() {
  uint64_t j;
  vector<FieldType> reconar;  // reconstructed aj+rj
  reconar.resize(num_bins);

  // add additive share of rj to corresponding share of aj
  for (j = 0; j < num_bins; j++) {
    add_a[j] = add_a[j] + randomTAndAddShares[j * 2 + 1];
  }

  // reconstruct additive shares, store in reconar
  addShareOpen(num_bins, add_a, reconar);

  // reshare and save in a_vals;
  reshare(reconar, a_vals);

  // subtract rj
  for (j = 0; j < num_bins; j++) {
    a_vals[j] = a_vals[j] - randomTAndAddShares[j * 2];
  }
}

/*
 * Step 2 of the online phase:
 * Compute x^{p-1}
 */
template <class FieldType>
void CircuitPSI<FieldType>::computeIntersectionShares() {
  int offset = 0;

  vector<vector<FieldType>> pow_mult(prime_bitlen);
  vector<FieldType> intermediate_mult(num_bins);
  for (uint64_t i = 0; i < prime_bitlen; i++) {
    pow_mult[i].resize(num_bins);
  }

  for (uint64_t i = 0; i < num_bins; i++) {
    pow_mult[0][i] = a_vals[i] - this->N + 1;
  }

  for (uint64_t i = 1; i < prime_bitlen; i++) {
    this->DNHonestMultiplication(pow_mult[i - 1], pow_mult[i - 1], pow_mult[i], num_bins, offset);
    offset = offset + num_bins * 2;
  }

  for (uint64_t i = 0; i < num_bins; i++) {
    cpsi_outputs[i] = pow_mult[sindex[0]][i];
  }

  for (uint64_t i = 1; i < sindex.size(); i++) {
    this->DNHonestMultiplication(cpsi_outputs, pow_mult[sindex[i]], intermediate_mult, num_bins,
                                 offset);
    offset = offset + num_bins * 2;
    for (uint64_t j = 0; j < num_bins; j++) {
      cpsi_outputs[j] = intermediate_mult[j];
    }
  }

  for (uint64_t j = 0; j < num_bins; j++) {
    cpsi_outputs[j] = *(this->field->GetOne()) - cpsi_outputs[j];
  }
}

/*
 * Step 3 of the online phase:
 * The parties send shares to the leader to open
 */
template <class FieldType>
void CircuitPSI<FieldType>::leaderOpen() {
  int fieldByteSize = this->field->getElementSizeInBytes();
  vector<byte> multbytes(num_bins * fieldByteSize);
  vector<vector<byte>> recBufsBytes;
  int i;
  uint64_t j;

  // Convert shares to bytes
  for (j = 0; j < num_bins; j++) {
    this->field->elementToBytes(multbytes.data() + (j * fieldByteSize), cpsi_outputs[j]);
  }

  if (this->m_partyId == 0) {  // receive from other parties
    recBufsBytes.resize(this->N);
    for (i = 0; i < this->N; i++) {
      recBufsBytes[i].resize(num_bins * fieldByteSize);
    }
    this->roundFunctionSyncForP1(multbytes, recBufsBytes);
  } else {  // send to leader
    this->parties[0]->getChannel()->write(multbytes.data(), multbytes.size());
  }

  if (this->m_partyId == 0) {  // Leader reconstructs shares
    vector<FieldType> x1(this->N);
    for (j = 0; j < num_bins; j++) {
      for (i = 0; i < this->N; i++) {
        x1[i] = this->field->bytesToElement(recBufsBytes[i].data() + (j * fieldByteSize));
      }
      outputs[j] = this->interpolate(x1);
    }
    for (int j = 0; j < 10; j++) {
      if (mpsi_print == true) {
        cout << "outputs " << j << ":" << (int)outputs[j].elem << endl;
      }
    }
  }
}

/*
 * Call the 3 steps of the online phase.
 */
template <class FieldType>
uint64_t CircuitPSI<FieldType>::evaluateCircuit() {
  uint64_t counter = 0;
  auto t9 = high_resolution_clock::now();
  additiveToThreshold();
  computeIntersectionShares();
  leaderOpen();
  auto t10 = high_resolution_clock::now();
  auto dur5 = duration_cast<milliseconds>(t10 - t9).count();
  // cout << this->m_partyId << ": Circuit evaluated in " << dur5 << " milliseconds." << endl;
  if (this->m_partyId == 0) {
    counter = outputPrint();
  }

  for (int i = 0; i < this->parties.size(); i++) {
    sent_bytes += this->parties[i].get()->getChannel().get()->bytesOut;
    recv_bytes += this->parties[i].get()->getChannel().get()->bytesIn;
  }
  // cout << this->m_partyId << ": " << sent_bytes << " bytes sent." << endl;
  // cout << this->m_partyId << ": " << recv_bytes << " bytes received." << endl;
  return counter;
}

/*
 * print output results
 */
template <class FieldType>
uint64_t CircuitPSI<FieldType>::outputPrint() {
  vector<uint64_t> matches;
  uint64_t i;

  for (i = 0; i < num_bins; i++) {
    if (outputs[i] != *(this->field->GetZero())) {
      matches.push_back(i);
    }
  }
  cout << this->m_partyId << ": 0 found at " << matches.size() << " positions. " << endl;
  /*
          for(i=0; i < matches.size(); i++) {
                  cout << matches[i] << " " << outputs[i] << "\n";
          }
  */
  return matches.size();
}

/*
 * Test that field addition works
 */
template <class FieldType>
void CircuitPSI<FieldType>::testOpenAdd() {
  vector<FieldType> sum(1);
  sum[0] = *(this->field->GetZero());
  for (uint64_t i = 0; i < num_bins; i++) {
    sum[0] = sum[0] + add_a[i];
  }
  cout << "Sum: " << sum[0] << "for Party " << this->m_partyId << "\n";
}

/*
 * Compares two threshold sharings (or one threshold and one additive sharing)
 */
template <class FieldType>
void CircuitPSI<FieldType>::testShareGenNoComm(vector<FieldType>& share_t,
                                               vector<FieldType>& share_add) {
  FieldType x1 = this->interpolate(share_t);
  FieldType x2 = this->interpolate(share_add);
  /*	FieldType x2 = *(this->field->GetZero());
          for(int i=0; i<this->N; i++) {
                  x2 = x2 + share_add[i];
          }
  */
  cout << "Reconstructed: " << (this->field->elementToString(x1)) << " "
       << (this->field->elementToString(x2)) << "\n";
}

/*
 * Test modDoubleRandom()
 */
template <class FieldType>
void CircuitPSI<FieldType>::testShareGenWithComm() {
  uint64_t no_random = num_bins;
  vector<FieldType> shares;
  vector<FieldType> share_t, share_add;
  vector<FieldType> TRes, AddRes;
  int i;

  cout << "testing " << this->m_partyId << "\n";

  modDoubleRandom(no_random, shares);

  cout << "modDoubleRandom done";

  for (i = 0; i < num_bins; i++) {
    share_t.push_back(shares[i * 2]);
    share_add.push_back(shares[i * 2 + 1]);
  }

  TRes.resize(num_bins);

  cout << "opening T sharings...\n";
  this->openShare(num_bins, share_t, TRes);
  cout << "opening additive sharings... \n";
  addShareOpen(num_bins, share_add, AddRes);

  if (this->m_partyId == 0) {
    cout << "Leader has recovered shares ";
    for (i = 0; i < num_bins; i++) {
      cout << this->field->elementToString(TRes[i]) << " "
           << this->field->elementToString(AddRes[i]) << ";";
    }
    cout << "\n";
  }
}

/*
 * Test reshare()
 */
template <class FieldType>
void CircuitPSI<FieldType>::testResharing() {
  vector<FieldType> shares(num_bins);
  vector<FieldType> opened(num_bins);
  cout << "Initialization of test variables done. " << add_a.size() << " " << shares.size() << " "
       << opened.size() << "\n";

  reshare(add_a, shares);

  cout << num_bins << " " << add_a.size() << " " << shares.size() << "\n";
  cout << "opening shares...\n";
  this->openShare(num_bins, shares, opened);
  for (uint64_t i = 0; i < num_bins; i++) {
    cout << this->field->elementToString(opened[i]) << " " << this->field->elementToString(add_a[i])
         << ";";
  }
}

/*
 * Test additive to threshold share conversion
 */
template <class FieldType>
void CircuitPSI<FieldType>::testConversion() {
  vector<FieldType> secrets(num_bins);
  vector<FieldType> orig(num_bins);

  addShareOpen(num_bins, add_a, orig);
  cout << "additive shares opened... ";

  additiveToThreshold();
  cout << "additiveToThreshold() done... ";

  this->openShare(num_bins, a_vals, secrets);
  for (uint64_t j = 0; j < num_bins; j++) {
    cout << "Opened: " << orig[j] << " " << secrets[j] << "\n";
  }
}
