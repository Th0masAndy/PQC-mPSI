#include <fstream>
using namespace std;

int main(int argc, char **argv) {
  string filename = string(argv[1]);
  string address = string(argv[2]);

  fstream f(filename, fstream::out);

  for(int i=0; i< 100; i++) {
    f << address<< "\n";
  }
  f.close();

  return 0;
}
