#ifndef PROGRESSBAR_H
#define PROGRESSBAR_H

#include <ostream>
#include <string>
#include <iomanip>

class ProgressBar
{
private:
    double progress = 0.0;
    ProgressBar() {};

public:
    static ProgressBar &getInstance()
    {
        static ProgressBar progressBar;
        return progressBar;
    }
    void incrementProgress(double increment, std::ostream& out, int width = 71);
    void displayProgress(double percentage, std::ostream& out, int width = 71);
};

// ProgressBar ProgressBar::progressBar;

void ProgressBar::incrementProgress(double increment, std::ostream& out, int width)
{
    progress += increment;
    ProgressBar::displayProgress(progress, out, width);
}

void ProgressBar::displayProgress(double percentage, std::ostream& out, int width)
{
    progress = percentage;
    out << "\r[" << std::fixed << std::setprecision(2) << percentage * 100 << "%]";
    for (int i = 0; i < width * percentage; ++i) out << "=";
    if (percentage != 1) out << ">";
    else out << "O" << std::endl;
}


#endif // !PROGRESSBAR_H