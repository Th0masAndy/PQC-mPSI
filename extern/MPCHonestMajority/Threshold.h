#include "ProtocolParty2.h"

template <class FieldType>
class Threshold : public ProtocolParty<FieldType>{
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

		uint64_t num_bins; // number of bins
		uint64_t num_triples;//number of multiplication triples
		uint64_t num_outs; //number of outputs
		uint64_t sent_bytes; //total number of bytes sent
		uint64_t recv_bytes; //total number of bytes received
		int K; //threshold for intersection
		int p; //prime that the field is over
		int J;
		vector<FieldType> masks; //the shares of the masks s_j for each value to be multiplied with
		vector<FieldType> add_a; //additive shares of a_j
		vector<FieldType> a_vals; //threshold shares of a_j
		vector<FieldType> mult_outs; //threshold shares of s_j*a_j
		vector<FieldType> outputs; //the shares of s_j*a_j
		vector<FieldType> randomTAndAddShares; //shares of r_j for conversion of inputs to T-sharings
		vector<FieldType> poly_outs; //shares of multiplication output of polynomial for threshold

		Threshold(int argc, char* argv[]);

		//read num_bins MPSI inputs
		void readMPSIInputs(vector<vector<uint8_t>>& bins, uint64_t nbins);

		//convert shares to field type for testing
		void convertSharestoFieldType(vector<uint8_t>& bins, vector<FieldType>& shares, uint64_t nbins);

		//perform MPSI
		void runMPSI();

		//prepare additive and T-threshold sharings of secret random value r_j using DN07's protocol
		void modDoubleRandom(uint64_t no_random, vector<FieldType>& randomElementsToFill);

		//make and distribute T-threshold sharings of values
		void reshare(vector<FieldType>& vals, vector<FieldType>& shares);

		//evaluate the circuit
		void evaluateCircuit();

		//Step 1: convert additive shares to T-threshold
		void additiveToThreshold();

		//Step 2: Evaluate the polynomial
		void threshPoly();

		//Step 3: Send to leader to open
		void leaderOpen();

		//open an additive sharing
		//code similar to DNHonestMultiplication() as only P0 opens
		void addShareOpen(uint64_t numShares, vector<FieldType> &Shares, vector<FieldType> &Secrets);

		//print output results to file
		void outputPrint();

		~Threshold() {}

	private:
		//test the functions
		void testOpenAdd();
		void testShareGenNoComm(vector<FieldType>& y1, vector<FieldType>& y2);
		void testShareGenWithComm();
		void testResharing();
		void testConversion();
};

template <class FieldType> Threshold<FieldType>::Threshold(int argc, char* argv[]) : ProtocolParty<FieldType>(argc, argv) {
        //The call to ProtocolParty constructor initializes inherited variables
        // N, T, m_partyID, as well as the VDM matrix and related vectors.

        //Initialize global variables that have not been inherited.

	//cout << this->m_partyId << ": Entered constructor." << endl;
        CmdParser parser = this->getParser();

	K = stoi(parser.getValueByKey(this->arguments, "threshold"));
	p = stoi(parser.getValueByKey(this->arguments, "primemod"));

	sent_bytes = 0;
	recv_bytes = 0;

	//cout << this->m_partyId << ": Element size is " << this->field->getElementSizeInBytes() << "." << endl;

        //cout << this->m_partyId << ": Constructor done." << endl;

        //Generation of shared values, such as triples, must be done later.
}

/*
 * read num_bins MPSI inputs from parameters
 */
template <class FieldType> void Threshold<FieldType>::readMPSIInputs(vector<vector<uint8_t>>& bins, uint64_t nbins) {
  	uint8_t input;
    	uint64_t i = 0;
	uint64_t j = 0;
        //cout<<"Check point 4"<<endl;
	for(int i=0; i<nbins; i++) {
		add_a.push_back(this->field->GetElement(bins[0][i]));
	}
	//cout<<"Check point 5"<<endl;
	if (this->m_partyId == 0) {
		for(int j=1; j< this->N-1; j++) {
			for(int i =0; i< nbins; i++) {
				add_a[i] = add_a[i] + this->field->GetElement(bins[j][i]);
			}
		}
		/*cout<<"Check point 6"<<endl;
		for(int i=0; i< nbins; i++) {
			add_a[i] = *(this->field->GetZero()) - add_a[i];
		}*/
	}

	num_bins = add_a.size();
	//cout<<"Num Bins"<<num_bins<<endl;

        if (mpsi_print == true) {
                cout << this->m_partyId << ": " << num_bins << " values read." << endl;
        }
	//cout<<"Num Bins"<< num_bins<<endl;
	//cout<<"Reading Completed!"<<endl;
}

/*
 * convert shares to field type
 */
template <class FieldType> void Threshold<FieldType>::convertSharestoFieldType(vector<uint8_t>& bins, vector<FieldType>& shares, uint64_t nbins) {
  	uint8_t input;
	uint64_t j = 0;
	for(int i=0; i<nbins; i++) {
		input = bins[j++];
		if(input > 0) {
			shares.push_back(this->field->GetElement(input));
		}
		else {
			shares.push_back(*(this->field->GetZero()));
		}
		if (this->m_partyId == 0) {
			shares[i] = *(this->field->GetZero()) - shares[i];
		}
	}
}

/*
 * Generate shared randomness (preprocessing) and execute the protocol
 */
template <class FieldType> void Threshold<FieldType>::runMPSI() {
	J = 2 * ceil((40 + log2(num_bins) + 3) / ceil(log2(p))) + 1; //number of times to repeat the final step to reduce false positive rate
	num_outs = num_bins * J;
        masks.resize(num_outs);
        a_vals.resize(num_bins);
        mult_outs.resize(num_outs);
        outputs.resize(num_outs);
	poly_outs.resize(num_bins);//The polynomial itself is only evaluated once per element

	//cout << this->m_partyId << ": J = " << J << endl;

	int half = this->N / 2;
	if(K < half) {
		num_triples = (K + J) * num_bins;
	}
	else {
		num_triples = (this->N - K + 1 + J) * num_bins;
	}

	auto t1 = high_resolution_clock::now();
        this->honestMult->invokeOffline();
	auto t2 = high_resolution_clock::now();
	auto dur1 = duration_cast<milliseconds>(t2-t1).count();
	//cout << this->m_partyId << ": Time to initialise matrices is: " << dur1 << " milliseconds." << endl;

	//Generate random T-sharings
        auto t3 = high_resolution_clock::now();
        this->generateRandomShares(num_outs, masks);
        auto t4 = high_resolution_clock::now();
        auto dur2 = duration_cast<milliseconds>(t4-t3).count();
        //cout << this->m_partyId << ": T-sharings generated in " << dur3 << "milliseconds." << endl;

        //Generate random additive and T-sharings
	auto t5 = high_resolution_clock::now();
        modDoubleRandom(num_bins, randomTAndAddShares);
	auto t6 = high_resolution_clock::now();
	auto dur3 = duration_cast<milliseconds>(t6-t5).count();
	//cout << this->m_partyId << ": T- and additive sharings generated in " << dur2 << " milliseconds." << endl;

        //Generate random T and 2T sharings for multiplication
	auto t7 = high_resolution_clock::now();
        this->generateRandom2TAndTShares(num_triples, this->randomTAnd2TShares);
	auto t8 = high_resolution_clock::now();
	auto dur4 = duration_cast<milliseconds>(t8-t7).count();
	//cout << this->m_partyId << ": T- and 2T-sharings generated in " << dur4 << " milliseconds." << endl;

        //Evaluate the circuit
        evaluateCircuit();
}

/*
 * prepare additive and T-threshold sharings of secret random value r_j using DN07's protocol
 */
template <class FieldType> void Threshold<FieldType>::modDoubleRandom(uint64_t no_random, vector<FieldType>& randomElementsToFill) {
	//cout << this->m_partyId <<  ": Generating double sharings..." << endl;
        int index = 0;
        int N = this->N;
        int T = this->T;

        vector<FieldType> x1(N), y1(N), y2(N), t1(N), r1(N), t2(N), r2(N);

        vector<vector<FieldType>> sendBufsElements(N);

        vector<vector<byte>> sendBufsBytes(N);
        vector<vector<byte>> recBufsBytes(N);
        // the number of buckets (each bucket requires one double-sharing
        // from each party and gives N-2T random double-sharings)
        uint64_t no_buckets = (no_random / (N-T))+1;

	int fieldByteSize = this->field->getElementSizeInBytes();

        //maybe add some elements if a partial bucket is needed
        randomElementsToFill.resize(no_buckets*(N-T)*2);

        for(int i=0; i < N; i++) {
                sendBufsElements[i].resize(no_buckets*2);
                sendBufsBytes[i].resize(no_buckets*fieldByteSize*2);
                recBufsBytes[i].resize(no_buckets*fieldByteSize*2);
        }

	//cout << this->m_partyId << ": no_random: " << no_random << " no_buckets: " << no_buckets << " N: " << N << " T: " << T << endl;

        /**
         *  generate random sharings.
         *  first degree T, then additive
         *
         */
        for(uint64_t k=0; k < no_buckets; k++) {
                // generate random degree-T polynomial
                for(int i = 0; i < T+1; i++) {
                        // A random field element, uniform distribution,
                        // note that x1[0] is the secret which is also random
                        x1[i] = this->field->Random();
                }

                this->matrix_vand.MatrixMult(x1, y1,T+1); // eval poly at alpha-positions

                y2[0] = x1[0];
                // generate N-1 random elements
                for(int i = 1; i < N; i++) {
                        // A random field element, uniform distribution
                        y2[i] = this->field->Random();
                        //all y2[i] generated so far are additive shares of the secret x1[0]
                        y2[0] = y2[0] - y2[i];
                }
		//testShareGenNoComm(y1, y2);

                // prepare shares to be sent
                for(int i=0; i < N; i++) {
                        //cout << "y1[ " <<i<< "]" <<y1[i] << " y2[ " << i << "]" << y2[i] << endl;
                        sendBufsElements[i][2*k] = y1[i];
                        sendBufsElements[i][2*k + 1] = y2[i];
                }

        }

        for(int i=0; i < N; i++) {
                for(uint64_t j=0; j<sendBufsElements[i].size();j++) {
                        this->field->elementToBytes(sendBufsBytes[i].data() + (j * fieldByteSize), sendBufsElements[i][j]);
                }
        }

        this->roundFunctionSync(sendBufsBytes, recBufsBytes, 1);

        for(uint64_t k=0; k < no_buckets; k++) {
                for (int i = 0; i < N; i++) {
                        t1[i] = this->field->bytesToElement(recBufsBytes[i].data() + (2*k * fieldByteSize));
                        t2[i] = this->field->bytesToElement(recBufsBytes[i].data() + ((2*k +1) * fieldByteSize));
                }
                this->matrix_vand_transpose.MatrixMult(t1, r1,N-T);
                this->matrix_vand_transpose.MatrixMult(t2, r2,N-T);

                //copy the resulting vector to the array of randoms
                for (int i = 0; i < (N - T); i++) {
                        randomElementsToFill[index*2] = r1[i];
                        randomElementsToFill[index*2 +1] = r2[i];
                        index++;
                }
        }

        if (mpsi_print == true) {
                cout << this->m_partyId << ": First pair of shares is " << randomElementsToFill[0] << " " << randomElementsToFill[1] << endl;
        }

}

/*
 * Leader receives additive shares from everyone else,
 * reconstructs, and saves in secrets
 * DOES NOT SEND reconstructions
 * Code similar to ::DNHonestMultiplication
*/
template <class FieldType> void Threshold<FieldType>::addShareOpen(uint64_t num_vals, vector<FieldType>& shares, vector<FieldType>& secrets) {
	//cout << this->m_partyId << ": Reconstructing additive shares..." << endl;

	int fieldByteSize = this->field->getElementSizeInBytes();
	vector<vector<byte>> recBufsBytes;
	vector<byte> sendBufsBytes;
	vector<byte> aPlusRSharesBytes(num_vals*fieldByteSize);
	int i;
	uint64_t j;
	int N = this->N;

	secrets.resize(num_vals);

	for(j=0; j<num_vals; j++) {
		this->field->elementToBytes(aPlusRSharesBytes.data() + (j * fieldByteSize), shares[j]);
	}

	if(this->m_partyId == 0) {
		recBufsBytes.resize(N);

        	for (i = 0; i < N; i++) {
                	recBufsBytes[i].resize(num_vals*fieldByteSize);
        	}

		//uint64_t recSize = N * num_vals * fieldByteSize;
		//cout << "In addShareOpen(), P0 receives: " << recSize << " in total." << endl;

		//receive the shares from all the other parties
		this->roundFunctionSyncForP1(aPlusRSharesBytes, recBufsBytes);
	}
	else {//since I am not party 1 parties[0]->getID()=1
		//send the shares to p1
		this->parties[0]->getChannel()->write(aPlusRSharesBytes.data(), aPlusRSharesBytes.size());
    	}

	//reconstruct the shares recieved from the other parties
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
template <class FieldType> void Threshold<FieldType>::reshare(vector<FieldType>& vals, vector<FieldType>& shares) {
        int N = this->N;
        int T = this->T;
        uint64_t no_vals = vals.size();

        vector<FieldType> x1(N), y1(N);

        vector<vector<FieldType>> sendBufsElements(N);
        vector<vector<byte>> sendBufsBytes(N);
	vector<vector<byte>> recBufsBytes(N);
	vector<vector<FieldType>> recBufsElements(N);

        int fieldByteSize = this->field->getElementSizeInBytes();

        if(this->m_partyId == 0) {
                //generate T-sharings of the values in vals
                for(uint64_t k = 0; k < no_vals; k++) {
                        //set x1[0] as the secret to be shared
                        x1[0] = vals[k];
                        // generate random degree-T polynomial
                        for(int i = 1; i < T+1; i++) {
                                // A random field element, uniform distribution
                                x1[i] = this->field->Random();
                        }

                        this->matrix_vand.MatrixMult(x1, y1,T+1); // eval poly at alpha-positions

                        // prepare shares to be sent
                        for(int i=0; i < N; i++) {
                                //cout << "y1[ " <<i<< "]" <<y1[i] << endl;
                                sendBufsElements[i].push_back(y1[i]);
                        }

                        shares[k] = y1[0];
                }

		//cout << "Sharings generated " << endl;

		for (int i=0; i<N; i++) {
			sendBufsBytes[i].resize(sendBufsElements[i].size() * fieldByteSize);
			recBufsBytes[i].resize(num_bins * fieldByteSize);
			for(uint64_t j=0; j<sendBufsElements[i].size(); j++) {
				this->field->elementToBytes(sendBufsBytes[i].data() + (j * fieldByteSize), sendBufsElements[i][j]);
			}
			//cout << sendBufsElements[i].size() << " " << sendBufsBytes[i].size() << " " << recBufsBytes[i].size();
		}
	}
	else {
		for (int i=0; i<N; i++) {
			sendBufsBytes[i].resize(num_bins * fieldByteSize);
			recBufsBytes[i].resize(num_bins * fieldByteSize);
			for (uint64_t j=0; j<num_bins; j++) {
				this->field->elementToBytes(sendBufsBytes[i].data(), *(this->field->GetZero()));
			}
		}
	}

	//cout << "byte conversion done " << endl;

        this->roundFunctionSync(sendBufsBytes, recBufsBytes, 2);

	//cout << "roundFunctionSync() done ";

	if (this->m_partyId != 0) {
		for(uint64_t k=0; k < no_vals; k++) {
                	shares[k] = this->field->bytesToElement(recBufsBytes[0].data() + (k * fieldByteSize));
        	}
	}
	//cout << "converted back to field elements..." << endl;

        if (mpsi_print == true) {
                cout << this->m_partyId << ": First t-sharing received is: " << shares[0] << endl;
        }
}

/*
 * Step 1 of the online phase:
 * The parties convert their additive shares to T-threshold shares
 * They do this by first adding additive shares of a shared random value to their shares,
 * then the leader opens this masked value,
 * and reshares as a T-threshold sharing,
 * from which all parties subtract their T-threshold shares of the above randomness
 * to get the T-threshold sharing of the original shared secret
 */
template <class FieldType> void Threshold<FieldType>::additiveToThreshold() {
	uint64_t j;
        vector<FieldType> reconar; // reconstructed aj+rj
        reconar.resize(num_bins);

        //add additive share of rj to corresponding share of aj
        for(j=0; j<num_bins; j++) {
                add_a[j] = add_a[j] + randomTAndAddShares[j*2+1];
        }

        //reconstruct additive shares, store in reconar
        addShareOpen(num_bins, add_a, reconar);

        //reshare and save in a_vals;
        reshare(reconar, a_vals);

	//Subtract rj from the T-threshold sharings
	for(j=0; j<num_bins; j++) {
		a_vals[j] = a_vals[j] - randomTAndAddShares[j*2];
	}
}

/*
 * Step 2 of the online phase:
 * if K < N / 2:
 * Evaluate the polynomial s * p(x) = s * x * (x - 1) * ... * (x - (K - 1))
 * Else:
 * Evaluate the polynomial s * p(x) = s * (x - K) * (x - (K + 1)) * ... (x - N)
 */
template <class FieldType> void Threshold<FieldType>::threshPoly() {
	int fieldByteSize = this->field->getElementSizeInBytes();
	vector<FieldType> left(num_bins);
	vector<FieldType> right(num_bins);
	vector<FieldType> psi(num_outs);
	uint64_t i, j;
	int offset, half;

	half = this->N / 2;

	if(K < half) {
		for(j = 0; j < num_bins; j++) {
			poly_outs[j] = a_vals[j];
		}

		for(i = 1; i < K; i++) {
			offset = (i - 1) * num_bins * 2;
			for(j = 0; j < num_bins; j++) {
				left[j] = poly_outs[j];
				right[j] = a_vals[j] - this->field->GetElement(i);
			}
			this->DNHonestMultiplication(left, right, poly_outs, num_bins, offset);
		}
		offset = (K - 1) * num_bins * 2;
	}

	else {
		for(j = 0; j < num_bins; j++) {
			poly_outs[j] = a_vals[j] - this->field->GetElement(K);
		}

		for(i = K + 1; i <= this->N; i++) {
			offset = (i - K - 1) * num_bins * 2;
			for(j = 0; j < num_bins; j++) {
				left[j] = poly_outs[j];
				right[j] = a_vals[j] - this->field->GetElement(i);
			}
			this->DNHonestMultiplication(left, right, poly_outs, num_bins, offset);
		}
		offset = (this->N - K) * num_bins * 2;
	}

	for(j = 0; j < num_bins; j++) {
		int pos = (j * J);
		for(i = 0; i < J; i++) {
			psi[pos + i] = poly_outs[j];
		}
	}
	this->DNHonestMultiplication(masks, psi, mult_outs, num_outs, offset);
}

/*
 * Step 3 of the online phase:
 * The parties send shares to the leader to open
 */
template <class FieldType> void Threshold<FieldType>::leaderOpen() {
	int fieldByteSize = this->field->getElementSizeInBytes();
	vector<byte> multbytes(num_outs * fieldByteSize);
	vector<vector<byte>> recBufsBytes;
	int i;
	uint64_t j;

	for(j=0; j < num_outs; j++) {
		this->field->elementToBytes(multbytes.data() + (j*fieldByteSize), mult_outs[j]);
	}

	if(this->m_partyId == 0) {
		recBufsBytes.resize(this->N);
		for(i=0; i<this->N; i++) {
			recBufsBytes[i].resize(num_outs * fieldByteSize);
		}
		this->roundFunctionSyncForP1(multbytes, recBufsBytes);
	}
	else {
		this->parties[0]->getChannel()->write(multbytes.data(), multbytes.size());
	}

	if(this->m_partyId == 0) {
		vector<FieldType> x1(this->N);
		for(j=0; j<num_outs; j++) {
			for(i=0; i<this->N; i++) {
				x1[i] = this->field->bytesToElement(recBufsBytes[i].data() + (j*fieldByteSize));
			}
			outputs[j] = this->interpolate(x1);
		}
	}
}

/*
 * Call the 3 steps of the online phase.
 */
template <class FieldType> void Threshold<FieldType>::evaluateCircuit() {
	auto t9 = high_resolution_clock::now();
	additiveToThreshold();
	threshPoly();
	leaderOpen();
	auto t10 = high_resolution_clock::now();
	auto dur5 = duration_cast<milliseconds>(t10-t9).count();
	cout << this->m_partyId << ": Circuit evaluated in " << dur5 << " milliseconds." << endl;
	if(this->m_partyId == 0) {
		outputPrint();
	}

	for(int i = 0; i < this->parties.size(); i++) {
		sent_bytes += this->parties[i].get()->getChannel().get()->bytesOut;
		recv_bytes += this->parties[i].get()->getChannel().get()->bytesIn;
	}
	//cout << this->m_partyId << ": " << sent_bytes << " bytes sent." << endl;
	//cout << this->m_partyId << ": " << recv_bytes << " bytes received." << endl;
}

/*
 * print output results
 */
template <class FieldType> void Threshold<FieldType>::outputPrint() {
        vector<int> matches;
        uint64_t counter=0;
        uint64_t i, j, pos;
	bool allZero;
	int half = this->N / 2;

        for(i=0; i < num_bins; i++) {
		pos = i * J;
		if(K >= half) {
			allZero = true;
			for(j = 0; j < J; j++) {
				if(outputs[pos + j] != *(this->field->GetZero())) {
					allZero = false;
					break;
				}
			}
			if(allZero == true) {
				matches.push_back(i);
				counter++;
			}
		}

		else {
			allZero = true;
			for(j = 0; j < J; j++) {
				if(outputs[pos + j] != *(this->field->GetZero())) {
					allZero = false;
					break;
				}
			}
			if(allZero == false) {
				matches.push_back(i);
				counter++;
			}
		}
        }
	cout << this->m_partyId << ": 0 found at " << matches.size() << " positions. " << endl;
/*
        for(i=0; i < counter; i++) {
                cout << matches[i] << " " << outputs[i] << endl;
        }
*/
}

/*
 * Test additive shares
 */
template <class FieldType> void Threshold<FieldType>::testOpenAdd() {
	vector<FieldType> sum(1);
	sum[0] = *(this->field->GetZero());
	for(uint64_t i=0; i<num_bins; i++) {
		sum[0] = sum[0] + add_a[i];
	}
	cout << "Sum: " << sum[0] << "for Party " << this->m_partyId << endl;
}

/*
 * Compare two sets of T-threshold shares (or one set of T-threshold and one set of additive shares)
 */
template <class FieldType> void Threshold<FieldType>::testShareGenNoComm(vector<FieldType>& share_t, vector<FieldType>& share_add) {
	FieldType x1 = this->interpolate(share_t);
	FieldType x2 = this->interpolate(share_add);
/*	FieldType x2 = *(this->field->GetZero());
	for(int i=0; i<this->N; i++) {
		x2 = x2 + share_add[i];
	}
*/
	cout << "Reconstructed: " << (this->field->elementToString(x1)) << " " << (this->field->elementToString(x2)) << endl;

}

/*
 * Test modDoubleRandom()
 */
template <class FieldType> void Threshold<FieldType>::testShareGenWithComm() {
	uint64_t no_random = num_bins;
	vector<FieldType> shares;
	vector<FieldType> share_t, share_add;
	vector<FieldType> TRes, AddRes;
	int i;

	cout << "testing " << this->m_partyId << endl;

	modDoubleRandom(no_random, shares);

	cout << "modDoubleRandom done";

	for(i=0; i<num_bins; i++) {
		share_t.push_back(shares[i*2]);
		share_add.push_back(shares[i*2 + 1]);
	}

	TRes.resize(num_bins);

	cout << "opening T sharings..." << endl;
	this->openShare(num_bins, share_t, TRes);
	cout << "opening additive sharings... " << endl;
	addShareOpen(num_bins, share_add, AddRes);

	if(this->m_partyId == 0){
		cout << "Leader has recovered shares ";
		for(i=0; i<num_bins; i++) {
			cout << this->field->elementToString(TRes[i]) << " " << this->field->elementToString(AddRes[i]) << ";";
		}
		cout << endl;
	}
}

/*
 * Test reshare()
 */
template <class FieldType> void Threshold<FieldType>::testResharing() {
	vector<FieldType> shares(num_bins);
	vector<FieldType> opened(num_bins);
	cout << "Initialization of test variables done. " << add_a.size() << " " << shares.size() << " " << opened.size() << endl;

	reshare(add_a, shares);

	cout << num_bins << " " << add_a.size() << " " << shares.size() << endl;
	cout << "opening shares..." << endl;
	this->openShare(num_bins, shares, opened);
	for (uint64_t i = 0; i<num_bins; i++) {
		cout << this->field->elementToString(opened[i]) << " " << this->field->elementToString(add_a[i]) << ";";
	}
}

/*
 * Test additive to T-threshold conversion
 */
template <class FieldType> void Threshold<FieldType>::testConversion() {
	vector<FieldType> secrets(num_bins);
	vector<FieldType> orig(num_bins);

	addShareOpen(num_bins, add_a, orig);
	cout << "additive shares opened... ";

	additiveToThreshold();
	cout << "additiveToThreshold() done... ";

	this->openShare(num_bins, a_vals, secrets);
	for(uint64_t j=0; j<num_bins; j++) {
		cout << "Opened: " << orig[j] << " " << secrets[j] << endl;
	}
}
