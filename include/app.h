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
public:
    void regenerateTable();
    void regenerateCWETables();
    void regenerateCAPECTables();
    void regenerateCPETables();

private:
    map<int, string> CWEName;
    map<int, string> CAPECName;
    vector<item> completeTable;
}

#endif