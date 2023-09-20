/*
 * \author Nishka Dasgupta
 * \email nishka.dasgupta@yahoo.com
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
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT 
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR LIABILITY, WHETHER IN AN ACTION 
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
 * OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

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
