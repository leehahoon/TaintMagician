#include "example.h"

void foo(int x) {
    int y = x+1;
    sink(y);
}

int main() {
  int x = 0;
  source(&x);
  foo(x);
  return 0;
}
