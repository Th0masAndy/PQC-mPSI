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

template <>
TemplateField<ZpMersenneByteElement>::TemplateField(long fieldParam) {

    this->fieldParam = p;
    this->elementSizeInBytes = 1;//round up to the next byte
    this->elementSizeInBits = p_size;

    auto randomKey = prg.generateKey(128);
    prg.setKey(randomKey);

    m_ZERO = new ZpMersenneByteElement(0);
    m_ONE = new ZpMersenneByteElement(1);
}

template <>
ZpMersenneByteElement TemplateField<ZpMersenneByteElement>::GetElement(long b) {


    if(b == 1)
    {
        return *m_ONE;
    }
    if(b == 0)
    {
        return *m_ZERO;
    }
    else{
        ZpMersenneByteElement element(b);
        return element;
    }
}

template <>
void TemplateField<ZpMersenneByteElement>::elementToBytes(unsigned char* elementInBytes, ZpMersenneByteElement& element){

    memcpy(elementInBytes, (byte*)(&element.elem), 1);
}

template <>
void TemplateField<ZpMersenneByteElement>::elementVectorToByteVector(vector<ZpMersenneByteElement> &elementVector, vector<byte> &byteVector){

    copy_byte_array_to_byte_vector((byte *)elementVector.data(), elementVector.size()*elementSizeInBytes, byteVector,0);
}

template <>
ZpMersenneByteElement TemplateField<ZpMersenneByteElement>::bytesToElement(uint8_t* elemenetInBytes){

    return ZpMersenneByteElement((unsigned int)(*(unsigned int *)elemenetInBytes));
}

