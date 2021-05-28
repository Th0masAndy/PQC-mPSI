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

#include "relaxed_opprf.h"
#include "psi_analytics.h"
//#include "constants.h"
#include "connection.h"
#include "socket.h"
//#include "abycore/sharing/boolsharing.h"
//#include "abycore/sharing/sharing.h"
#include "equality.h"
//#include "ots/ots.h"
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
#include <unordered_set>
#include <thread>

namespace RELAXEDNS {
	struct hashlocmap {
		int bin;
		int index;
	};

//using share_ptr = std::shared_ptr<share>;

	using milliseconds_ratio = std::ratio<1, 1000>;
	using duration_millis = std::chrono::duration<double, milliseconds_ratio>;

	/*
	 * Reset communication for new execution
	 */
	void ResetCommunicationThreshold(std::vector<sci::NetIO*> &ioArr, ENCRYPTO::PsiAnalyticsContext &context){
		if(context.role == P_0) {
			context.sci_io_start.resize(2*(context.np-1));
			for(std::uint64_t i=0; i<2*(context.np-1); i++) {
				context.sci_io_start[i] = ioArr[i]->counter;
			}
		} else {
			context.sci_io_start.resize(2);
			for(int i=0; i<2; i++) {
				context.sci_io_start[i] = ioArr[i]->counter;
			}
		}
	}

	/*
	 * Measure communication
	 */
	void AccumulateCommunicationThreshold(std::vector<sci::NetIO*> &ioArr, ENCRYPTO::PsiAnalyticsContext &context){
		if(context.role == P_0) { //Accumulate from all parties
			for(std::uint64_t i=0; i<2*(context.np-1); i++) {
				context.sentBytesSCI += ioArr[i]->counter - context.sci_io_start[i];
			}
		} else {
			for(int i=0; i<2; i++) {
				context.sentBytesSCI += ioArr[i]->counter - context.sci_io_start[i];
			}
		}

		//Holds due to symmetricity
		context.recvBytesSCI = context.sentBytesSCI;
	}

	/*
	 * Parallelise leader's execution of OPRF for relaxed batch OPPRF subprotocols with other parties
	 */
	void multi_oprf_thread(int tid, std::vector<std::vector<osuCrypto::block>> &masks_with_dummies, std::vector<std::uint64_t> table,
				ENCRYPTO::PsiAnalyticsContext &context, std::vector<osuCrypto::Channel> &chl) {
		for(std::uint64_t i=tid; i<context.np-1; i=i+context.nthreads) {
			masks_with_dummies[i] = RELAXEDNS::ot_receiver(table, chl[i], context);
		}
	}

	/*
	 * OPPRF for other (non-leader) parties
	 */
	void OpprgPsiNonLeader(std::vector<std::uint64_t> &actual_contents_of_bins, std::vector<std::vector<std::uint64_t>> &simple_table_v, 
			       std::vector<std::vector<osuCrypto::block>> &masks, ENCRYPTO::PsiAnalyticsContext & context, 
			       std::unique_ptr<CSocket> &sock, osuCrypto::Channel &chl) {
		std::vector<std::uint64_t> content_of_bins;
		std::uint64_t bufferlength = (std::uint64_t)ceil(context.nbins/2.0);
		osuCrypto::PRNG prng(osuCrypto::sysRandomSeed(), bufferlength);

		for(std::uint64_t i=0; i<context.nbins; i++) {
			content_of_bins.push_back(prng.get<std::uint64_t>());
		}

		std::unordered_map<std::uint64_t,hashlocmap> tloc;
		std::vector<std::uint64_t> filterinputs;
		for(std::uint64_t i=0; i<context.nbins; i++) {
			int binsize = simple_table_v[i].size();
			for(int j=0; j<binsize; j++) {
				tloc[simple_table_v[i][j]].bin = i;
				tloc[simple_table_v[i][j]].index = j;
				filterinputs.push_back(simple_table_v[i][j]);
			}
		}

		ENCRYPTO::CuckooTable cuckoo_table(static_cast<std::size_t>(context.fbins));
		cuckoo_table.SetNumOfHashFunctions(context.ffuns);
		cuckoo_table.Insert(filterinputs);
		cuckoo_table.MapElements();
		//cuckoo_table.Print();
		
		if (cuckoo_table.GetStashSize() > 0u) {
			std::cerr << "[Error] Stash of size " << cuckoo_table.GetStashSize() << " occured\n";
		}

		std::vector<std::uint64_t> garbled_cuckoo_filter;
		garbled_cuckoo_filter.reserve(context.fbins);

		bufferlength = (std::uint64_t)ceil(context.fbins - 3*context.nbins);
		osuCrypto::PRNG prngo(osuCrypto::sysRandomSeed(), bufferlength);

		for(std::uint64_t i=0; i<context.fbins; i++){
			if(!cuckoo_table.hash_table_.at(i).IsEmpty()) {
				std::uint64_t element = cuckoo_table.hash_table_.at(i).GetElement();
				std::uint64_t function_id = cuckoo_table.hash_table_.at(i).GetCurrentFunctinId();
				hashlocmap hlm = tloc[element];
				osuCrypto::PRNG prng(masks[hlm.bin][hlm.index], 2);
				std::uint64_t pad = 0u;
				for(std::uint64_t j=0;j<=function_id;j++) {
					pad = prng.get<std::uint64_t>();
				}
				garbled_cuckoo_filter[i] = content_of_bins[hlm.bin] ^ pad;
			} else {
				garbled_cuckoo_filter[i] = prngo.get<std::uint64_t>();
			}
		}

		sock->Send(garbled_cuckoo_filter.data(), context.fbins * sizeof(std::uint64_t));

		const int ts=4;
		auto masks_with_dummies = RELAXEDNS::ot_receiver(content_of_bins, chl, context);

		std::vector<osuCrypto::block> padding_vals;
		padding_vals.reserve(context.nbins);
		std::vector<std::uint64_t> table_opprf;
		table_opprf.reserve(ts*context.nbins);

		//Receive nonces
		sock->Receive(padding_vals.data(), context.nbins * sizeof(osuCrypto::block));
		//Receive table
		sock->Receive(table_opprf.data(), context.nbins * ts* sizeof(std::uint64_t));

		//context.timings.table_transmission = ttrans_duration.count();
		
		std::uint64_t addresses1;
		std::uint8_t bitaddress;
		std::uint64_t mask_ad = (1ULL << 2) - 1;

		//actual_contents_of_bins.reserve(context.nbins);

		for(std::uint64_t i=0; i<context.nbins; i++) {
			addresses1 = hashToPosition(reinterpret_cast<std::uint64_t *>(&masks_with_dummies[i])[0], padding_vals[i]);
			bitaddress = addresses1 & mask_ad;
			actual_contents_of_bins[i] = reinterpret_cast<std::uint64_t *>(&masks_with_dummies[i])[0] ^ table_opprf[ts*i+bitaddress];
		}
	}

	/*
	 * Relaxed batch OPPRF for leader party
	 */
	void OpprgPsiLeader(std::vector<std::uint64_t> &content_of_bins, std::vector<std::uint64_t> &cuckoo_table_v, 
			    std::vector<osuCrypto::block> &masks_with_dummies, ENCRYPTO::PsiAnalyticsContext &context, 
			    std::unique_ptr<CSocket> &sock, osuCrypto::Channel &chl) {
		std::vector<std::uint64_t> garbled_cuckoo_filter;
		garbled_cuckoo_filter.reserve(context.fbins);

		sock->Receive(garbled_cuckoo_filter.data(), context.fbins * sizeof(std::uint64_t));

		ENCRYPTO::CuckooTable garbled_cuckoo_table(static_cast<std::size_t>(context.fbins));
		garbled_cuckoo_table.SetNumOfHashFunctions(context.ffuns);
		garbled_cuckoo_table.Insert(cuckoo_table_v);
		auto addresses = garbled_cuckoo_table.GetElementAddresses();

		std::vector<std::vector<std::uint64_t>> opprf_values(context.nbins, std::vector<std::uint64_t>(context.ffuns));

		for(std::uint64_t i=0; i<context.nbins; i++) {
			osuCrypto::PRNG prngo(masks_with_dummies[i], 2);
			for(std::uint64_t j=0; j< context.ffuns; j++) {
				opprf_values[i][j]=garbled_cuckoo_filter[addresses[i*context.ffuns+j]] ^ prngo.get<std::uint64_t>();
			}
		}

		const int ts=4;
		auto table_masks = RELAXEDNS::ot_sender(opprf_values, chl, context);

		std::uint64_t bufferlength = (std::uint64_t)ceil(context.nbins/2.0);
		osuCrypto::PRNG tab_prng(osuCrypto::sysRandomSeed(), bufferlength);

		for(std::uint64_t i=0; i<context.nbins; i++) {
			content_of_bins[i] = tab_prng.get<std::uint64_t>();
		}

		/* std::cout<<"***********************************"<<std::endl;
		 * std::cout<<"The actual contents are: ["<<std::endl;
		 * for(int i=0;i<context.nbins;i++) {
		 *	std::cout<<"( "<<i<<", "<<content_of_bins[i]<<"), ";
		 * }
		 * std::cout<<"]"<<std::endl;
		 * std::cout<<"***********************************"<<std::endl;*/

		std::vector<osuCrypto::block> padding_vals;
		padding_vals.reserve(context.nbins);
		std::vector<std::uint64_t> table_opprf;
		table_opprf.reserve(ts*context.nbins);
		osuCrypto::PRNG padding_prng(osuCrypto::sysRandomSeed(), 2*context.nbins);

		bufferlength = (std::uint64_t)ceil(context.nbins/2.0);
		osuCrypto::PRNG dummy_prng(osuCrypto::sysRandomSeed(), bufferlength);

		//Get addresses
		std::uint64_t addresses1[context.ffuns];
		std::uint8_t bitaddress[context.ffuns];
		std::uint8_t bitindex[ts];
		std::uint64_t mask_ad = (1ULL << 2) - 1;

		double ave_ctr=0.0;

		for(std::uint64_t i=0; i<context.nbins; i++) {
			bool uniqueMap = false;
			int ctr=0;
			while (!uniqueMap) {
				auto nonce = padding_prng.get<osuCrypto::block>();
				
				for(std::uint64_t j=0; j< context.ffuns; j++) {
					addresses1[j] = hashToPosition(reinterpret_cast<std::uint64_t *>(&table_masks[i][j])[0], nonce);
					bitaddress[j] = addresses1[j] & mask_ad;
				}

				uniqueMap = true;
				for(int j=0; j<ts; j++)
					bitindex[j]=ts;
				for(std::uint8_t j=0; j< context.ffuns; j++) {
					if(bitindex[bitaddress[j]] != ts) {
						uniqueMap = false;
						break;
					} else {
						bitindex[bitaddress[j]] = j;
					}
				}
				if(uniqueMap) {
					padding_vals.push_back(nonce);
					for(int j=0; j<ts; j++) {
						if(bitindex[j]!=-1) {
							table_opprf[i*ts+j] = reinterpret_cast<std::uint64_t *>(&table_masks[i][bitindex[j]])[0] ^ content_of_bins[i];
						} else {
							table_opprf[i*ts+j] = dummy_prng.get<std::uint64_t>();
						}
					}
					ave_ctr += ctr;
				}
				ctr++;
			}
		}

		ave_ctr = ave_ctr/context.nbins;
		
		//Send nonces
		sock->Send(padding_vals.data(), context.nbins * sizeof(osuCrypto::block));
		//Send table
		sock->Send(table_opprf.data(), context.nbins * ts* sizeof(std::uint64_t));
		//std::cout<<"Checkpoint 1"<<std::endl;
	}

	/*
	 * Parallelise hint transmission between leader and all parties
	 */
	void multi_hint_thread(int tid, std::vector<std::vector<std::uint64_t>> &sub_bins, std::vector<std::uint64_t> &cuckoo_table_v, 
			       std::vector<std::vector<osuCrypto::block>> &masks_with_dummies, ENCRYPTO::PsiAnalyticsContext &context, 
			       std::vector<std::unique_ptr<CSocket>> &allsocks, std::vector<osuCrypto::Channel> &chls) {
		for(std::uint64_t i=tid; i<context.np-1; i=i+context.nthreads) {
			OpprgPsiLeader(sub_bins[i], cuckoo_table_v, masks_with_dummies[i], context, allsocks[i], chls[i]);
		}
	}

	/*
	 * Parallelise setting up connections for equality phase
	 */
	void multi_boolean_conn(int tid, std::vector<sci::NetIO*> &ioArr, ENCRYPTO::PsiAnalyticsContext &context) {
		for(std::uint64_t i=tid; i<context.np-1; i=i+context.nthreads) {
			for(int j=0; j<2; j++) {
				ioArr[2*i+j] = new sci::NetIO(context.address[i].c_str(), REF_SCI_PORT + 2*i +j);
			}
		}
	}

	/*
	 * Parallelise setup of OT connections
	 */
	void multi_otpack_setup(int tid, std::vector<sci::NetIO*> &ioArr, std::vector<sci::OTPack<sci::NetIO>*> &otpackArr, 
				ENCRYPTO::PsiAnalyticsContext &context) {
		//std::cout<<"Cp 3"<<context.radixparam<<": "<< context.bitlen<< std::endl;
		for(std::uint64_t i=tid; i<context.np-1; i=i+context.nthreads) {
			for(int j=0; j<2; j++) {
				if (j == 0) {
					otpackArr[2*i+j] = new OTPack<NetIO>(ioArr[2*i+j], 2, context.radixparam, context.bitlen);
				} else if (j == 1) {
					otpackArr[2*i+j] = new OTPack<NetIO>(ioArr[2*i+j], 1, context.radixparam, context.bitlen);
				}
			}
		}
		//std::cout<<"Cp 2"<<std::endl;
	}

	/*
	 * Parallelise equality phase
	 */
	void multi_equality_thread(int tid, std::vector<std::vector<std::uint64_t>> &x, int party, int num_cmps, std::vector<std::vector<std::uint8_t>> &z, 
				   std::vector<std::vector<std::uint8_t>> &a_shares_bins, std::vector<std::vector<std::uint64_t>> &aux_bins, 
				   std::vector<sci::NetIO*> &ioArr, std::vector<sci::OTPack<sci::NetIO>*> &otpackArr, ENCRYPTO::PsiAnalyticsContext &context, 
				   std::vector<std::unique_ptr<CSocket>> &allsocks) {
		//std::cout<<"X Value: "<<x[0][5]<<std::endl;
		for(std::uint64_t i=tid; i<context.np-1; i=i+context.nthreads) {
			sci::NetIO* ioThreadArr[2];
			sci::OTPack<sci::NetIO> *otThreadpackArr[2];
			for(int j=0; j<2; j++) {
				ioThreadArr[j] = ioArr[2*i+j];
				otThreadpackArr[j] = otpackArr[2*i+j];
			}
			perform_equality(x[i].data(), party, context.bitlen, context.radixparam, num_cmps, z[i].data(), 
					 a_shares_bins[i].data(), ioThreadArr, otThreadpackArr, context.smallmod);
			//allsocks[i]->Receive(aux_bins[i].data(), num_cmps * sizeof(uint64_t));
		}
	}

	/*
	 * Run relaxed batch OPPRF for all parties
	 */
	void run_relaxed_opprf(std::vector<std::vector<std::uint64_t>> &sub_bins, ENCRYPTO::PsiAnalyticsContext &context, const std::vector<std::uint64_t> &inputs,
					std::vector<std::unique_ptr<CSocket>> &allsocks, std::vector<osuCrypto::Channel> &chls) {
		if (context.role == P_0) {//Protocol for leader party
			sub_bins.resize(context.np-1, std::vector<std::uint64_t>(context.nbins, 0));
			
			//Hashing
			std::vector<std::uint64_t> table;
			std::vector<std::vector<osuCrypto::block>> masks_with_dummies(context.np-1);
			table = ENCRYPTO::cuckoo_hash(context, inputs);

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

			//Hints
			const auto phase_ts_time = std::chrono::system_clock::now();
			std::thread hint_threads[context.nthreads];
			for(std::uint64_t i=0; i<context.nthreads; i++) {
				hint_threads[i] = std::thread(multi_hint_thread, i, std::ref(sub_bins), std::ref(table), std::ref(masks_with_dummies), 
							      std::ref(context), std::ref(allsocks), std::ref(chls));
			}
			for(std::uint64_t i=0; i<context.nthreads; i++) {
				hint_threads[i].join();
			}
			const auto phase_te_time = std::chrono::system_clock::now();
			const duration_millis phase_two_duration = phase_te_time - phase_ts_time;
			context.timings.polynomials = phase_two_duration.count();

		} else { //For non leader parties
			//Hashing
			auto simple_table_v = ENCRYPTO::simple_hash(context, inputs);
			//OPRF
			auto masks = RELAXEDNS::ot_sender(simple_table_v, chls[0], context);
			sub_bins.resize(1, std::vector<std::uint64_t>(context.nbins, 0));
			//Protocol for non-leader 
			OpprgPsiNonLeader(sub_bins[0], simple_table_v, masks, context, allsocks[0], chls[0]);
		}

	}

	/*
	 * Run relaxed batch OPPRF and equality check for all parties
	 */
	void run_threshold_relaxed_opprf(std::vector<std::vector<std::uint8_t>> &a_shares_bins, ENCRYPTO::PsiAnalyticsContext &context, 
					 const std::vector<std::uint64_t> &inputs, std::vector<std::unique_ptr<CSocket>> &allsocks, 
					 std::vector<osuCrypto::Channel> &chls, std::vector<sci::NetIO*> &ioArr) {
		int padded_size = ((context.nbins+7)/8)*8;
		
		if (context.role == P_0) {//Protocol for leader party
			a_shares_bins.resize(context.np-1, std::vector<std::uint8_t>(padded_size, 0));
			
			std::vector<std::vector<std::uint64_t>> sub_bins(context.np-1);
			for(std::uint64_t i=0; i<context.np-1; i++) {
				sub_bins[i].reserve(padded_size);
			}

			//Hashing
			std::vector<std::uint64_t> table;
			std::vector<std::vector<osuCrypto::block>> masks_with_dummies(context.np-1);
			table = ENCRYPTO::cuckoo_hash(context, inputs);

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

			//Hints
			const auto phase_ts_time = std::chrono::system_clock::now();
			std::thread hint_threads[context.nthreads];
			for(std::uint64_t i=0; i<context.nthreads; i++) {
				hint_threads[i] = std::thread(multi_hint_thread, i, std::ref(sub_bins), std::ref(table), std::ref(masks_with_dummies), 
							      std::ref(context), std::ref(allsocks), std::ref(chls));
			}
			for(std::uint64_t i=0; i<context.nthreads; i++) {
				hint_threads[i].join();
			}

			/* std::cout<<"Checkpoint 1: X Value: "<< sub_bins[0][5]<<std::endl;
			 allsocks[0]->Send(sub_bins[0].data(), padded_size * sizeof(std::uint64_t));*/

			std::vector<sci::OTPack<sci::NetIO>*> otpackArr(2*(context.np-1));
			std::thread ot_pack_threads[context.nthreads];
			for(std::uint64_t i=0; i<context.nthreads; i++) {
				ot_pack_threads[i] = std::thread(multi_otpack_setup, i, std::ref(ioArr), std::ref(otpackArr), std::ref(context));
			}

			for(std::uint64_t i=0; i<context.nthreads; i++) {
				ot_pack_threads[i].join();
			}

			for(std::uint64_t i=0; i<context.np-1; i++){
				for(int j=context.nbins; j<padded_size; j++)
					sub_bins[i][j] = S_CONST;
			}

			//std::cout<<"Checkpoint 1: X Value: "<< sub_bins[0][5]<<std::endl;

			std::vector<std::vector<std::uint8_t>> res_bins(context.np-1);
			for(std::uint64_t i=0;i<context.np-1; i++)
				res_bins[i].resize(padded_size);

			/*std::vector<std::vector<uint64_t>> a_shares_bins(context.np-1);
			 for(int i=0;i<context.np-1; i++)
			 a_shares_bins[i].resize(padded_size);*/

			std::vector<std::vector<std::uint64_t>> aux_bins(context.np-1);
			/*for(int i=0;i<context.np-1; i++)
			 aux_bins[i].reserve(padded_size);*/

			//Equality
			std::thread equality_threads[context.nthreads];
			for(std::uint64_t i=0; i<context.nthreads; i++) {
				equality_threads[i] = std::thread(multi_equality_thread, i, std::ref(sub_bins), 2, padded_size, std::ref(res_bins), 
								  std::ref(a_shares_bins), std::ref(aux_bins), std::ref(ioArr), std::ref(otpackArr), 
								  std::ref(context), std::ref(allsocks));
			}
			for(std::uint64_t i=0; i<context.nthreads; i++) {
				equality_threads[i].join();
			}
			const auto phase_te_time = std::chrono::system_clock::now();
			const duration_millis phase_two_duration = phase_te_time - phase_ts_time;
			context.timings.polynomials = phase_two_duration.count();

			//const auto agg_start_time = std::chrono::system_clock::now();

			/*std::cout<<"##########################"<<std::endl;
			 for(int i=0; i<5; i++) {
				std::cout<<a_shares_bins[0][i]<<std::endl;
			}
			std::cout<<"##########################"<<std::endl;

			allsocks[0]->Send(a_shares_bins[0].data(), padded_size * sizeof(std::uint64_t));*/
			//TemplateField<ZpMersenneLongElement1> *field;
			//std::vector<ZpMersenneLongElement1> field_bins;
			/*for(std::uint64_t j=0; j< context.nbins; j++) {
				field_bins.push_back(field->GetElement(a_shares_bins[0][j]));
			}
			for(std::uint64_t i=1; i< context.np-1; i++) {
				for(std::uint64_t j=0; j< context.nbins; j++) {
					field_bins[j] = field_bins[j]+field->GetElement(a_shares_bins[i][j]);
				}
			}
			*/

			//const auto agg_end_time = std::chrono::system_clock::now();
			//const duration_millis agg_duration = agg_end_time - agg_start_time;
			//context.timings.aggregation += agg_duration.count();

		} else {//Protocol for non-leader parties
			a_shares_bins.resize(1, std::vector<std::uint8_t>(padded_size, 0));
			
			//Hashing
			auto simple_table_v = ENCRYPTO::simple_hash(context, inputs);
			
			//OPRF
			auto masks = RELAXEDNS::ot_sender(simple_table_v, chls[0], context);
			std::vector<std::uint64_t> actual_contents_of_bins;
			actual_contents_of_bins.reserve(padded_size);
			
			//Relaxed batch OPPRF protocol for non-leader
			OpprgPsiNonLeader(actual_contents_of_bins, simple_table_v, masks, context, allsocks[0], chls[0]);
			
			//Equality
			std::vector<sci::OTPack<sci::NetIO>*> otpackArr(2);
			for(int j=0; j<2; j++) {
				if (j == 0) {
					otpackArr[j] = new OTPack<NetIO>(ioArr[j], 1, context.radixparam, context.bitlen);
				} else if (j == 1) {
					otpackArr[j] = new OTPack<NetIO>(ioArr[j], 2, context.radixparam, context.bitlen);
				}
			}

			for(int j=context.nbins; j<padded_size; j++)
				actual_contents_of_bins[j] = C_CONST;
			std::vector<std::uint8_t> res_bins;
			res_bins.resize(padded_size);

			sci::NetIO* ioThreadArr[2];
			sci::OTPack<sci::NetIO> * otThreadpackArr[2];
			for(int j=0; j<2; j++) {
				ioThreadArr[j] = ioArr[j];
				otThreadpackArr[j] = otpackArr[j];
			}
			//std::cout<<"Checkpoint 1: X Value: "<< actual_contents_of_bins[5]<<std::endl;
			perform_equality(actual_contents_of_bins.data(), 1, context.bitlen, context.radixparam, padded_size, res_bins.data(), 
					 a_shares_bins[0].data(), ioThreadArr, otThreadpackArr, context.smallmod);
		}
	}

}
