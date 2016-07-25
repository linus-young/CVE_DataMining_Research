#ifndef APP_H
#define APP_H

#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <cstdio>
#include <algorithm>
#include "JsonHelper.h"
#include "ProgressBar.h"


class cveBackend
{
    using std::string;
public:
    void regenerateTable();
    void regenerateCWETables();
    void regenerateCAPECTables();
    void regenerateCPETables();
    void regenerateCWETree();
    void printToFiles();

private:
    std::map<int, string> CWEName;
    std::map<int, string> CAPECName;
    std::vector<item> completeTable;

    void loadJsonFiles();
}

#endif