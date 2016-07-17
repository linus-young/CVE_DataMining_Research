#include <vector>
#include <string>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <algorithm>
#include "rapidjson/document.h"
#include "rapidjson/filereadstream.h"
#include "progressBar.h"

using namespace rapidjson;
using namespace std;

string emptyString = "";

struct CPEwithTime
{
public:
    int year;
    string cpe;

    CPEwithTime(int _year = 0, string _cpe = emptyString) : year(_year), cpe(_cpe) {}

    bool operator < (CPEwithTime second) { return year < second.year; }
    bool operator == (CPEwithTime second ) { return cpe == second.cpe; }
};

struct CPEwithFrequency
{
    string cpe;
    int frequency = 0;

    bool operator < (CPEwithFrequency second) { return frequency < second.frequency; }
    bool operator > (CPEwithFrequency second) { return frequency > second.frequency; }
    bool operator == (CPEwithFrequency second ) { return cpe == second.cpe; }
    bool operator != (CPEwithFrequency second ) { return cpe != second.cpe; }
};

vector<CPEwithTime> getCPE(FILE* file)
{
    char readBuffer[65536];
    FileReadStream is(file, readBuffer, sizeof(readBuffer));

    Document d;
    d.ParseStream(is);

    vector<CPEwithTime> cpes;

    string timestr = d["Information"]["CVE"][0]["published"].GetString();
    string yearstr = timestr.substr(0, 4);
    int year = stoi(yearstr);

    if (!d["Information"].IsNull() && !d["Information"]["CPE"].IsNull())
    {
        Value& jsonCPE = d["Information"]["CPE"];
        for (SizeType i = 0; i < jsonCPE.Size(); ++i)
        {
            string id = jsonCPE[i]["id"].GetString();
            string conciseId = id.substr(7);
            cpes.push_back(CPEwithTime(year, conciseId));
        }
    }

    return cpes;
}

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

vector< CPEwithFrequency > countFrequencies(vector< CPEwithTime >::iterator begin, vector< CPEwithTime >::iterator end)
{
    vector <CPEwithFrequency > frequencies;
    for (auto it = begin; it != end; )
    {
        auto id = (*it).cpe;
        auto start = it;
        while (it != end && (*it).cpe == id) ++it;
        CPEwithFrequency w;
        w.cpe = id;
        w.frequency = (it - start);
        frequencies.push_back(w);
    }
    return frequencies;
}

vector< int > divideBins(int lo, int hi, int nbins)
{
    vector< int > bins;
    for (int i = 1; i < nbins; ++i)
        bins.push_back(lo + i * (hi - lo) / nbins);
    bins.push_back(hi);
    return bins;
}

int frequencyOf(string id, vector< CPEwithFrequency > & vec)
{
    for (auto v : vec)
        if (v.cpe == id) return v.frequency;
    return 0;
}

bool comByTime (CPEwithTime first, CPEwithTime second) { return first.year  < second.year;  }
bool comByID   (CPEwithTime first, CPEwithTime second) { return first.cpe < second.cpe; }
bool comByFreq (CPEwithFrequency first, CPEwithFrequency second) { return first.frequency > second.frequency; }

void printStatsinTable(vector< CPEwithTime > &cpesTimeTable, string directory)
{
    ofstream ofs;

    // frequency of all times
    std::sort(cpesTimeTable.begin(), cpesTimeTable.end(), comByID);
    auto frequencyTableOfAlltime = countFrequencies(cpesTimeTable.begin(), cpesTimeTable.end());
    std::sort(frequencyTableOfAlltime.begin(), frequencyTableOfAlltime.end(), comByFreq);

    ofs.open(directory + "/alltimes.csv");
    ofs << "ID, frequency\n";
    for (auto f : frequencyTableOfAlltime) {
        ofs << f.cpe << "," << f.frequency <<"\n";
    }
    ofs.close();

    // frequency of bins
    std::sort(cpesTimeTable.begin(), cpesTimeTable.end(), comByTime);

    int minYear = cpesTimeTable[0].year;
    int maxYear = cpesTimeTable[cpesTimeTable.size() - 1].year;

    vector < vector < CPEwithFrequency > > groupedFrequencies;
    auto bins = divideBins(minYear, maxYear, 4);
    std::sort(cpesTimeTable.begin(), cpesTimeTable.end(), comByTime);

    ofs.open(directory + "4_Bin.csv");
    ofs << "ID, frequency\n";
    auto it = cpesTimeTable.begin();
    for (auto hi : bins)
    {
        auto lo = it;
        ofs << "From " << lo->year << " to "  << hi << '\n';
        while (it != cpesTimeTable.end() && it->year <= hi) ++it;

        // count frequencies
        std::sort(lo, it, comByID);
        auto thisBin = countFrequencies(lo, it);
        std::sort(thisBin.begin(), thisBin.end(), comByFreq);
        groupedFrequencies.push_back(thisBin);

        for (int i = 0; i < 10; ++i)
            ofs << thisBin[i].cpe << "," << thisBin[i].frequency << '\n';

        ofs << "Least 10\n";
        for (auto itt = thisBin.end() - 10; itt != thisBin.end(); itt++)
            ofs << itt->cpe << "," << itt->frequency << '\n';
    }
    ofs.close();

    // Persistant
    ofs.open(directory + "overtimeconsistent.csv");
    ofs << "Until Year,";
    for (auto h : bins) ofs << h << ",";
    ofs << '\n'  ;

    vector <string> overLappingIds;
    for (auto g : groupedFrequencies[0])
        overLappingIds.push_back(g.cpe);
    groupedFrequencies.erase(groupedFrequencies.begin());

    for (auto group : groupedFrequencies)
    {
        vector <string> vec;
        for (auto g : group)
            vec.push_back(g.cpe);
        vector <string> o(1000);
        auto qit = std::set_intersection(vec.begin(), vec.end(),
                                overLappingIds.begin(), overLappingIds.end(), o.begin());
        o.resize(qit - o.begin());
        overLappingIds = o;
    }

    for (auto id : overLappingIds)
    {
        ofs << id;
        for (auto v : groupedFrequencies)
            ofs << ',' << frequencyOf(id, v);
        ofs << '\n';
    }
    ofs.close();

    cout << endl;
}

int main()
{
    cout << "Reading files: " << endl;
    ProgressBar::getInstance().displayProgress(0.0, cout);
    auto filenames = readfilenames();
    vector<CPEwithTime> cpesTimeTable;
    // parse all files
    for (auto &filename : filenames)
    {
        FILE* file = fopen(filename.c_str(), "r");
        auto thisline = getCPE(file);
        fclose(file);
        for (auto cpe : thisline)
            cpesTimeTable.push_back(cpe);
        ProgressBar::getInstance().incrementProgress(1.0 / filenames.size(), cout);
    }
    ProgressBar::getInstance().displayProgress(1.0, cout);

    cout << "With Version" << endl;
    printStatsinTable(cpesTimeTable, "statistics/CPEwithTime/withVersion/");

    for (auto &c : cpesTimeTable)
    {
        auto secondColon = c.cpe.find(":", c.cpe.find(":") + 1);
        if (secondColon != std::string::npos)
            c.cpe = c.cpe.substr(0, secondColon);
    }

    auto it = std::unique(cpesTimeTable.begin(), cpesTimeTable.end(),
                            [] (const CPEwithTime &a, const CPEwithTime &b)
                            {
                                return a.cpe == b.cpe;
                            });
    cpesTimeTable.resize(it - cpesTimeTable.begin());

    cout << "Merged Version" << endl;
    printStatsinTable(cpesTimeTable, "statistics/CPEwithTime/mergedVersion/");

    return 0;
}