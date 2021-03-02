#include "ZpMersenneByteElement.h"
#include "gmp.h"

static uint8_t p = 11;

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
