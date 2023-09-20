#include <fstream>
using namespace std;
#define DEF_ADDRESS "0.0.0.0"
#define REF_PORT 32000

int main(int argc, char **argv) {
  string filename = string(argv[1]);

  int isLeader = atoi(argv[2]);

  string address_1, address_2;

  if(isLeader) {
    address_1 = DEF_ADDRESS;
    address_2 = string(argv[3]);
  } else {
    address_1 = string(argv[3]);
    address_2 = DEF_ADDRESS;
  }

  fstream f(filename, fstream::out);

  f << "party_" + to_string(0) + "_ip = " + address_1 << "\n";
  for(int i=1; i< 100; i++) {
    f << "party_" + to_string(i) + "_ip = " + address_2<< "\n";
  }

  for(int i=0; i< 100; i++) {
    f << "party_" + to_string(i) + "_port = " + to_string(REF_PORT+20*i)<< "\n";
  }
  f.close();

  return 0;
}
