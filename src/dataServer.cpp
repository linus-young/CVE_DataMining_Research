#include "JsonHelper.h"
#include "progressBar.h"
#include <cstdio>
#include <fstream>
#include <iostream>
#include <vector>

using namespace std;
using namespace rapidjson;

vector<string> readfilenames()
{
    vector<string> filenames;
    ifstream ifs;
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
    }
    return filenames;
}

int main()
{
    
}