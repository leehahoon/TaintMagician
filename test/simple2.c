#include "example.h"

int main() {
  int x = 0;
  source(&x);
  int y;
  if (x > 0) {
    y = sanitizer(x);
    sink(y); // safe
  }
  y = x;
  sink(y); // bug
  return 0;
}
