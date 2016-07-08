#include <ostream>
#include <string>
#include <iomanip>

class ProgressBar
{
private:
    std::ostream& out;
    int width;

public:
    ProgressBar(std::ostream& _out, int _width = 80):out(_out) {
        width = _width - 9;
    }

    void displayProgress(double percentage) {
        out << "\r[" << std::fixed << std::setprecision(2) << percentage * 100 << "%]";
        for (int i = 0; i < width * percentage; ++i) out << "=";
        if (percentage != 1) out << ">";
        else out << "O";
    }
};