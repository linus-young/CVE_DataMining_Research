#include "JsonHelper.h"
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
    auto filenames = readfilenames();
    JsonHelper jsonHelper;
    std::ofstream ofs ("statistics/completeTable.csv", std::ofstream::out);

    ofs << "CVE_ID, Published_Time, Lastest_Modification_Time, " 
        << "CAPEC_IDs, CWE_IDs, CPE_IDs, Risk_Severity\n";

    for (auto &filename : filenames)
    {
        cout << filename << endl;
        auto d = jsonHelper.parseComplete(fopen(filename.c_str(), "r"));

        Value & Information = d["Information"];

        if (!(Information["CVE"].IsNull()))
        {
            Value & CVEId = Information["CVE"][0]["id"];
            ofs << CVEId.GetString();
            ofs << ",";
            if (!(Information["CVE"][0]["published"].IsNull()))
            {
                Value & PublishedTime = Information["CVE"][0]["published"];
                ofs << PublishedTime.GetString();
            }
            else ofs << "null";

            ofs << ",";
            if (!(Information["CVE"][0]["modified"].IsNull()))
            {
                Value & LatestModTime= Information["CVE"][0]["modified"];
                ofs << LatestModTime.GetString();
            }
            else ofs << "null";
        }
        else
        {
            ofs << "null, null, null" ;
        }

        ofs << ",";
        if (!(Information["CAPEC"].IsNull()))
        {
            Value & CAPEC = Information["CAPEC"];
            for (SizeType i = 0; i < CAPEC.Size(); ++i) ofs << CAPEC[i]["id"].GetInt() << "|";
        }

        ofs << ",";
        if (!(Information["CWE"].IsNull()))
        {
            Value & CWE = Information["CWE"];
            ofs << CWE[0]["id"].GetString() << " : " << CWE[0]["title"].GetString();
        }

        ofs << ",";
        if (!(Information["CPE"].IsNull()))
        {
            Value & CPE = Information["CPE"];
            for (SizeType i = 0; i < CPE.Size(); ++i) ofs << jsonHelper.CPEStringSimplify(CPE[i]["id"].GetString()) << "|";
        }
        
        ofs << ",";
        if (!(d["Risk"][0]["severity"].IsNull()))
        {
            Value & RiskSeverity= d["Risk"][0]["severity"];
            ofs << RiskSeverity.GetString();
        }
        ofs << "\n";
    }

    ofs.close();
    return 0;
}