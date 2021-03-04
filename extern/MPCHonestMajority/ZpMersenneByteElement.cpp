#include "ZpMersenneByteElement.h"
#include "gmp.h"

static uint8_t p = 31; // Mersenne Prime only; multiplication protocol does not work with non-Mersenne primes
static uint8_t p_size = 5; // size of bit representation of p

ZpMersenneByteElement::ZpMersenneByteElement() {
	this->elem = 0;
}

ZpMersenneByteElement::ZpMersenneByteElement(uint8_t elem) {
	if (elem >=0 && elem < p) {
		this->elem = elem;
	}
	else if (elem >= p) {
		while (elem >= p) {
			elem = elem - p;
		}
		this->elem = elem;
	}
}

ZpMersenneByteElement& ZpMersenneByteElement::operator=(const ZpMersenneByteElement& other) {
	this->elem = other.elem;
	return *this;
}

bool ZpMersenneByteElement::operator!=(const ZpMersenneByteElement& other) {
	return !(other.elem == this->elem);
}

bool ZpMersenneByteElement::operator==(const ZpMersenneByteElement& other) {
	return (other.elem == this->elem);
}

ZpMersenneByteElement ZpMersenneByteElement::operator+(const ZpMersenneByteElement& other) {
	ZpMersenneByteElement answer;
	answer.elem = this->elem + other.elem;
	if(answer.elem >= p) {
		answer.elem = answer.elem - p;
	}
	return answer;
}

ZpMersenneByteElement& ZpMersenneByteElement::operator+=(const ZpMersenneByteElement& other) {
	uint8_t ans = this->elem + other.elem;
	if(ans >= p) {
		ans = ans - p;
	}
	this->elem = ans;
	return *this;
}

ZpMersenneByteElement ZpMersenneByteElement::operator-(const ZpMersenneByteElement& other) {
	ZpMersenneByteElement answer;
	int ans = (int) (this->elem - other.elem);
	if (ans < 0) {
		ans = ans + p;
	}
	answer.elem = (uint8_t) ans;
	return answer;
}

ZpMersenneByteElement& ZpMersenneByteElement::operator-=(const ZpMersenneByteElement& other) {
	int ans = (int) (this->elem - other.elem);
	if (ans < 0) {
		ans = ans + p;
	}
	this->elem = (uint8_t) ans;
	return *this;
}

ZpMersenneByteElement ZpMersenneByteElement::operator*(const ZpMersenneByteElement& other) {
	ZpMersenneByteElement answer;
	
	uint16_t prod = (uint16_t)this->elem * (uint16_t)other.elem;
	uint8_t bottom = prod & p;
	uint8_t top = (prod >> p_size);
	uint8_t ans = top + bottom;
	if(ans >= p) {
		ans = ans - p;
	}
	answer.elem = ans;
	return answer;
}

ZpMersenneByteElement& ZpMersenneByteElement::operator*=(const ZpMersenneByteElement& other) {
	uint16_t prod = (uint16_t)this->elem * (uint16_t)other.elem;
	uint8_t bottom = prod & p;
	uint8_t top = (prod >> p_size);
	uint8_t ans = top + bottom;
	if(ans >= p) {
		ans = ans - p;
	}
	this->elem = ans;
	return *this;
}
