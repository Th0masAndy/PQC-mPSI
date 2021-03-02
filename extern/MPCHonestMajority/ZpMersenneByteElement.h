#include <libscapi/include/primitives/Prg.hpp>
#include <libscapi/include/primitives/Mersenne.hpp>

#include "stdint.h"
#include <iostream>

using namespace std;

//static uint8_t p = 31;

class ZpMersenneByteElement{

	public:
		uint8_t elem;
		ZpMersenneByteElement();
		ZpMersenneByteElement(uint8_t elem);
		//init(uint8_t prime);
};
