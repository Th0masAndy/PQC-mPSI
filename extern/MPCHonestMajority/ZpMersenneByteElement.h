#include <libscapi/include/primitives/Prg.hpp>
#include <libscapi/include/primitives/Mersenne.hpp>

#include "stdint.h"
#include <iostream>

using namespace std;

//Performs field operations modulo a Mersenne prime of a byte or less in length
//E.g 127, 31
//The exact prime is defined in the .cpp file

class ZpMersenneByteElement{

	public:
		uint8_t elem; //The field element
		ZpMersenneByteElement(); //Default constructor, sets elem = 0
		ZpMersenneByteElement(uint8_t elem); //Constructor to set elem to a field element
		
		//Basic arithmetic operators
		ZpMersenneByteElement& operator=(const ZpMersenneByteElement& other);
		bool operator!=(const ZpMersenneByteElement& other);
		bool operator==(const ZpMersenneByteElement& other);
		
		ZpMersenneByteElement operator+(const ZpMersenneByteElement& other);
		ZpMersenneByteElement& operator+=(const ZpMersenneByteElement& other);
		
		ZpMersenneByteElement operator-(const ZpMersenneByteElement& other);
		ZpMersenneByteElement& operator-=(const ZpMersenneByteElement& other);
		
		ZpMersenneByteElement operator*(const ZpMersenneByteElement& other);
		ZpMersenneByteElement& operator*=(const ZpMersenneByteElement& other);
		
		ZpMersenneByteElement operator/(const ZpMersenneByteElement& other);
		ZpMersenneByteElement& operator/=(const ZpMersenneByteElement& other);
		
		//Field inverse of an element; not implemented
		//ZpMersenneByteElement inv();
};

inline ::ostream& operator<<(::ostream& s, const ZpMersenneByteElement& a){ return s << a.elem; };
