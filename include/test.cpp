#include <iostream>
#include "progressBar.h"

using namespace std;

int main() {
	ProgressBar p(cout);
	p.displayProgress(0.5);
	return 0;
}
