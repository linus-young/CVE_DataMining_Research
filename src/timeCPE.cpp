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

struct CPEwithTime
{
public:
    int year;
    string cpe;

    CPEwithTime(int _year, string _cpe) : year(_year), cpe(_cpe) {}

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
        cerr << "1";
        auto id = (*it).cpe;
        cerr << "2";        
        auto start = it;
        cerr << "3";
        while (it != end && (*it).cpe == id) ++it;
        cerr << "4";
        CPEwithFrequency w;
        cerr << "5";
        w.cpe = id;
        cerr << "6";
        w.frequency = (it - start);
        cerr << "7";
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

int main()
{
    ProgressBar bar(cout, 80);
    double progress = 0.0;
    auto filenames = readfilenames();
    ofstream ofs;
    vector<CPEwithTime> cpesTimeTable;

    // parse all files
    for (auto filename : filenames)
    {
        bar.displayProgress(progress);
        FILE* file = fopen(filename.c_str(), "r");
        auto thisline = getCPE(file);
        fclose(file);
        for (auto cpe : thisline)
            cpesTimeTable.push_back(cpe);
        progress += 1.0 / filenames.size() * 0.3;
    }
    // frequency of all times
    std::sort(cpesTimeTable.begin(), cpesTimeTable.end(), comByID);
    auto frequencyTableOfAlltime = countFrequencies(cpesTimeTable.begin(), cpesTimeTable.end());
    cerr << "can I sort?" << endl;
    std::sort(frequencyTableOfAlltime.begin(), frequencyTableOfAlltime.end(), comByFreq);
    cerr << "can I sort?" << endl;

    ofs.open("statistics/CPEwithTime/alltimes.csv");
    ofs << "ID, frequency\n";
    for (auto f : frequencyTableOfAlltime) {
        bar.displayProgress(progress);
        ofs << f.cpe << "," << f.frequency <<"\n";
        progress += 1.0 / frequencyTableOfAlltime.size() * 0.2;
    }
    ofs.close();

    // frequency of bins
    std::sort(cpesTimeTable.begin(), cpesTimeTable.end(), comByTime);

    int minYear = cpesTimeTable[0].year;
    int maxYear = cpesTimeTable[cpesTimeTable.size() - 1].year;

    vector < vector < CPEwithFrequency > > groupedFrequencies;
    auto bins = divideBins(minYear, maxYear, 4);
    std::sort(cpesTimeTable.begin(), cpesTimeTable.end(), comByTime);

    ofs.open("statistics/CPEwithTime/4_Bin.csv");
    ofs << "ID, frequency\n";
    auto it = cpesTimeTable.begin();
    for (auto hi : bins)
    {
        bar.displayProgress(progress);
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
        progress += 1.0 / 4 * 0.4;
    }
    ofs.close();

    // Persistant
    ofs.open("statistics/CPEwithTime/overtimeconsistent.csv");
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

    bar.displayProgress(1.0);
    cout << endl;

    return 0;
}