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
    ProgressBar progressBar(cout);
    progressBar.displayProgress(0.01);
    auto filenames = readfilenames();
    JsonHelper jsonHelper;
    std::ofstream ofs ("statistics/completeTable.csv", std::ofstream::out);

    ofs << "CVE_ID, Published_Time, Lastest_Modification_Time, "
        << "CAPEC_IDs, CWE_IDs, CPE_IDs, Risk_Severity\n";
    double progress = 0.01;
    for (auto &filename : filenames)
    {
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
            set<int> capecs;
            for (SizeType i = 0; i < CAPEC.Size(); ++i) capecs.insert(CAPEC[i]["id"].GetInt());
            for (auto c : capecs) ofs << c << "|";
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
            set<string> cpes;
            for (SizeType i = 0; i < CPE.Size(); ++i) cpes.insert(jsonHelper.CPEStringSimplify(CPE[i]["id"].GetString()));
            for (auto s : cpes) ofs << s << "|";
        }

        ofs << ",";
        if (!(d["Risk"][0]["severity"].IsNull()))
        {
            Value & RiskSeverity= d["Risk"][0]["severity"];
            ofs << RiskSeverity.GetString();
        }
        ofs << "\n";
        progress += 1.0 / filenames.size();
        progressBar.displayProgress(progress);
    }

    progressBar.displayProgress(1.0);
    cout << endl;

    ofs.close();
    return 0;
}