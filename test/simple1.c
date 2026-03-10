#include "example.h"

int main() {
  int x = 0;
  source(&x);
  sink(x); // bug
  return 0;
}
