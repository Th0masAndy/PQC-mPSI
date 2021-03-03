#include "ZpMersenneByteElement.h"
#include "gmp.h"

static uint8_t p = 31;

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
