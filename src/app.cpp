#include "app.h"

using std::string; // usage too often
using std::cout;
using std::cerr;
using std::endl;

void cveBackend::regenerateTable()
{
    ProgressBar::getInstance().displayProgress(0.0, cout);
    auto filenames = loadJsonFiles();
}

void cveBackend::regenerateCWETables()
{

}

void cveBackend::regenerateCAPECTables()
{

}

void cveBackend::regenerateCPETables()
{

}

void cveBackend::regenerateCWETree()
{

}

void cveBackend::printToFiles()
{

}

std::vector<string> cveBackend::loadJsonFiles()
{
    std::vector<string> filenames;
    std::ifstream ifs;
    ifs.open("filelist.txt");
    while (ifs.good())
    {
        string str;
        ifs >> str;
        if (str.length() > 4)
        {
            str = "rawdata/" + str;
            filenames.push_back(str);
        }
        ProgressBar::getInstance().incrementProgress()
    }
    return filenames;
}
