#include "lamu.h"

namespace thread {
    using namespace std::chrono;
    void sleep(double seconds)
    {
        high_resolution_clock::time_point start = high_resolution_clock::now();
        int sleep_length = (int)std::round(seconds * CLOCKS_PER_SEC);
        while (duration_cast<milliseconds>(high_resolution_clock::now() - start).count() < sleep_length);
    }
}