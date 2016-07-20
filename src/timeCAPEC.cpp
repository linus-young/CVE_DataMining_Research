#include <vector>
#include <string>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <map>
#include <algorithm>
#include "rapidxml/rapidxml.hpp"
#include "rapidxml/rapidxml_utils.hpp"
#include "rapidjson/document.h"
#include "rapidjson/filereadstream.h"
#include "progressBar.h"

using namespace rapidjson;
using namespace std;
using namespace rapidxml;



struct CAPECwithTime
{
public:
    int year;
    int capecID;

    CAPECwithTime(int _year, int _capecID) : year(_year), capecID(_capecID) {}

    bool operator < (CAPECwithTime second) { return year < second.year; }
    bool operator == (CAPECwithTime second ) { return capecID == second.capecID; }
};

struct CAPECwithFrequency
{
    int capecID = 0;
    int frequency = 0;

    bool operator < (CAPECwithFrequency second) { return frequency < second.frequency; }
    bool operator > (CAPECwithFrequency second) { return frequency > second.frequency; }
    bool operator == (CAPECwithFrequency second ) { return capecID == second.capecID; }
    bool operator != (CAPECwithFrequency second ) { return capecID != second.capecID; }
};

map<int, string> getCAPECNames()
{
    map<int, string> dictionary;
    rapidxml::file<char> f("rawdata/capec_v2_8.xml");
    rapidxml::xml_document<> doc;
    doc.parse<0>(f.data());
    xml_node<> *node = doc.first_node()->first_node()->next_sibling()->next_sibling();
    for (auto capecNode = node->first_node(); capecNode; capecNode = capecNode->next_sibling())
    {
        auto attrName = capecNode->first_attribute()->next_attribute();
        auto attrID = capecNode->first_attribute();
        dictionary[atoi(attrID->value())] = attrName->value();
    }
    return dictionary;
}

vector<CAPECwithTime> getCAPEC(FILE* file)
{
    char readBuffer[65536];
    FileReadStream is(file, readBuffer, sizeof(readBuffer));

    Document d;
    d.ParseStream(is);

    vector<CAPECwithTime> capecs;

    string timestr = d["Information"]["CVE"][0]["published"].GetString();
    string yearstr = timestr.substr(0, 4);
    int year = stoi(yearstr);

    if (!d["Information"].IsNull() && !d["Information"]["CAPEC"].IsNull())
    {
        Value& jsonCAPEC = d["Information"]["CAPEC"];
        for (SizeType i = 0; i < jsonCAPEC.Size(); ++i)
            capecs.push_back(CAPECwithTime(year, jsonCAPEC[i]["id"].GetInt()));
    }

    return capecs;
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

vector< CAPECwithFrequency > countFrequencies(vector< CAPECwithTime >::iterator begin, vector< CAPECwithTime >::iterator end)
{
    vector <CAPECwithFrequency > frequencies;
    for (auto it = begin; it != end; )
    {
        int id = (*it).capecID;
        auto start = it;
        while (it != end && (*it).capecID == id) ++it;
        CAPECwithFrequency w;
        w.capecID = id;
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

int frequencyOf(int id, vector< CAPECwithFrequency > & vec)
{
    for (auto v : vec)
        if (v.capecID == id) return v.frequency;
    return 0;
}

bool comByTime (CAPECwithTime first, CAPECwithTime second) { return first.year  < second.year;  }
bool comByID   (CAPECwithTime first, CAPECwithTime second) { return first.capecID < second.capecID; }
bool comByFreq (CAPECwithFrequency first, CAPECwithFrequency second) { return first.frequency > second.frequency; }

int main()
{
    double progress = 0.0;
    auto filenames = readfilenames();
    ofstream ofs;
    vector<CAPECwithTime> CAPECsTimeTable;
    map<int, string> capecNameDictionary = getCAPECNames();

    // parse all files
    for (auto filename : filenames)
    {
        ProgressBar::getInstance().displayProgress(progress, cout);
        FILE* file = fopen(filename.c_str(), "r");
        auto thisline = getCAPEC(file);
        fclose(file);
        for (auto capec : thisline)
            CAPECsTimeTable.push_back(capec);
        progress += 1.0 / filenames.size() * 0.3;
    }

    // frequency of all times
    std::sort(CAPECsTimeTable.begin(), CAPECsTimeTable.end(), comByID);
    auto frequencyTableOfAlltime = countFrequencies(CAPECsTimeTable.begin(), CAPECsTimeTable.end());
    std::sort(frequencyTableOfAlltime.begin(), frequencyTableOfAlltime.end(), comByFreq);

    ofs.open("statistics/CAPECwithTime/alltimes.csv");
    ofs << "ID, frequency\n";
    for (auto f : frequencyTableOfAlltime) {
        ProgressBar::getInstance().displayProgress(progress, cout);
        ofs << f.capecID << ",\"" << capecNameDictionary[f.capecID] << "\","<< f.frequency <<"\n";
        progress += 1.0 / frequencyTableOfAlltime.size() * 0.2;
    }
    ofs.close();

    // frequency of bins
    std::sort(CAPECsTimeTable.begin(), CAPECsTimeTable.end(), comByTime);

    int minYear = CAPECsTimeTable[0].year;
    int maxYear = CAPECsTimeTable[CAPECsTimeTable.size() - 1].year;

    vector < vector < CAPECwithFrequency > > groupedFrequencies;
    auto bins = divideBins(minYear, maxYear, 4);
    std::sort(CAPECsTimeTable.begin(), CAPECsTimeTable.end(), comByTime);

    ofs.open("statistics/CAPECwithTime/4_Bin.csv");
    ofs << "ID, frequency\n";
    auto it = CAPECsTimeTable.begin();
    for (auto hi : bins)
    {
        auto lo = it;
        ofs << "From " << lo->year << " to "  << hi << '\n';
        while (it != CAPECsTimeTable.end() && it->year <= hi) ++it;

        // count frequencies
        std::sort(lo, it, comByID);
        auto thisBin = countFrequencies(lo, it);
        std::sort(thisBin.begin(), thisBin.end(), comByFreq);
        groupedFrequencies.push_back(thisBin);

        for (int i = 0; i < 10; ++i)
            ofs << "\"" << thisBin[i].capecID << "\"" << ",\"" << capecNameDictionary[thisBin[i].capecID] << "\"," << "," << thisBin[i].frequency << '\n';
    }
    ofs.close();

    // Persistant
    ofs.open("statistics/CAPECwithTime/overtimeconsistent.csv");
    ofs << "ID, \"Name\" ";
    for (auto h : bins) ofs << h << ",";
    ofs << '\n'  ;

    vector <int> overLappingIds;
    for (auto g : groupedFrequencies[0])
        overLappingIds.push_back(g.capecID);

    for (auto group : groupedFrequencies)
    {
        vector <int> vec;
        for (auto g : group)
            vec.push_back(g.capecID);
        vector <int> o(1000);
        std::sort(vec.begin(), vec.end());
        std::sort(overLappingIds.begin(), overLappingIds.end());
        auto qit = std::set_intersection(vec.begin(), vec.end(),
                                overLappingIds.begin(), overLappingIds.end(), o.begin());
        o.resize(qit - o.begin());
        overLappingIds = o;
    }

    for (auto id : overLappingIds)
    {
        ofs << id << ",\"" << capecNameDictionary[id] << "\",";
        for (auto v : groupedFrequencies)
            ofs << ',' << frequencyOf(id, v);
        ofs << '\n';
    }
    ofs.close();

    ProgressBar::getInstance().displayProgress(1.0, cout);
    cout << endl;

    return 0;
}