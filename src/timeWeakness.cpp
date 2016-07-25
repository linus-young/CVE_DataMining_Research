#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>
#include <string>



using namespace std;

string nullString = "";

vector<string> dict (2000, nullString);

struct WeaknessWithTime
{
    int year = 1999;
    int cweID = 0;

    WeaknessWithTime(int _year, int _cweID)
    {
        year = _year;
        cweID = _cweID;
    }

    bool operator < (WeaknessWithTime second) { return year < second.year; }
    bool operator == (WeaknessWithTime second ) { return cweID == second.cweID; }
};

struct WeaknessWithFrequency
{
    int cweID = 0;
    int frequency = 0;

    bool operator < (WeaknessWithFrequency second) { return frequency < second.frequency; }
    bool operator > (WeaknessWithFrequency second) { return frequency > second.frequency; }
    bool operator == (WeaknessWithFrequency second ) { return cweID == second.cweID; }
    bool operator != (WeaknessWithFrequency second ) { return cweID != second.cweID; }
    
};

bool comByTime (WeaknessWithTime first, WeaknessWithTime second) { return first.year  < second.year;  }
bool comByID   (WeaknessWithTime first, WeaknessWithTime second) { return first.cweID < second.cweID; }
bool comByFreq (WeaknessWithFrequency first, WeaknessWithFrequency second) { return first.frequency > second.frequency; }

int parseYear(string str)
{
    int retVal = stoi(str);
    return retVal;
}

int parseID(string str)
{
    int start = str.find(" : ");
    string number = str.substr(4, start - 4);
    string s = (str.substr(start + 3    , str.length() - start));
    int id = stoi(number);
    if (dict[id] == nullString) dict[id] = s;
    return id;
}

vector< WeaknessWithFrequency > countFrequencies(vector< WeaknessWithTime >::iterator begin, vector< WeaknessWithTime >::iterator end)
{
    vector <WeaknessWithFrequency > frequencies;
    for (auto it = begin; it != end; )
    {
        int id = (*it).cweID;
        auto start = it;
        while (it != end && (*it).cweID == id) ++it;
        WeaknessWithFrequency w; 
        w.cweID = id;
        w.frequency = (it - start);
        frequencies.push_back(w);
    }
    return frequencies;
}

vector< int > divideBins(int lo, int hi, int nbins)
{
    vector< int > bins;
    for (int i = 1; i < nbins; ++i)
    {
        bins.push_back(lo + i * (hi - lo) / nbins);
    }
    bins.push_back(hi);
    return bins;
}

int frequencyOf(int id, vector< WeaknessWithFrequency > & vec)
{
    for (auto v : vec)
    {
        if (v.cweID == id) return v.frequency;
    }
    return 0;
}


int main()
{
    // Setting up filestreams
    ifstream ifs("./statistics/completeTable.csv");
    ofstream ofs;
    if (!ifs.is_open()) return -1;

    vector< WeaknessWithTime > weaknesses;

    // Reading the completeTable.csv file and extract information
    string str;
    getline(ifs, str); // remove the first line (header)
    while (getline(ifs, str))
    {
        int commas[6];
        commas[0] = str.find(",");
        for (int i = 1; i < 6; ++i) commas[i] = str.find(",", commas[i - 1] + 1);
        if (commas[1] - commas[0] < 3 || commas[4] - commas[3] < 3) continue; // no year or no CWE

        int year  = parseYear(str.substr(commas[0] + 1, 4));
        int cweID = parseID  (str.substr(commas[3] + 1, commas[4] - commas[3] - 1));
        if (year > 1900 && year <= 2016)
        {
            WeaknessWithTime element (year, cweID);
            weaknesses.push_back(element);
        }
    }
    ifs.close();

    std::sort(weaknesses.begin(), weaknesses.end(), comByID);

    auto alltime = countFrequencies(weaknesses.begin(), weaknesses.end());
    std::sort(alltime.begin(), alltime.end(), comByFreq);

    ofs.open("statistics/CWEwithTime/allTime.csv");
    for (int i = 0; i < alltime.size(); ++i)
    {
        ofs << alltime[i].cweID << "," << alltime[i].frequency << '\n';
        // ofs << "\"" << alltime[i].cweID << '-' << dict[alltime[i].cweID] << "\"" << "," << alltime[i].frequency << '\n';
    }

    ofs.close();


    std::sort(weaknesses.begin(), weaknesses.end(), comByTime);
    vector < vector < WeaknessWithFrequency > > groupedFrequencies;
    int bins[] = {2001, 2006, 2011, 2016}; // upper bounds of time bins
    std::sort(weaknesses.begin(), weaknesses.end(), comByTime);
    auto it = weaknesses.begin();
    for (auto hi : bins)
    {
        ofs.open("statistics/CWEwithTime/" + to_string(hi) + ".csv");
        auto lo = it;
        while (it != weaknesses.end() && it->year <= hi) ++it;
        std::sort(lo, it, comByID);
        auto thisBin = countFrequencies(lo, it);
        std::sort(thisBin.begin(), thisBin.end(), comByFreq);
        groupedFrequencies.push_back(thisBin);
        for (auto &w : thisBin)
        {
            ofs << "\"" << w.cweID << '-' << dict[w.cweID] << "\"" << "," << w.frequency << '\n';
        }

        ofs.close();
    }

    // find consistently present IDs
    ofs.open("statistics/CWEwithTime/overtimeconsistent.csv");
    ofs << "ID" << ",";
    for (auto h : bins) ofs << "\"" << h << "\"" << ",";
    ofs << '\n'  ;

    vector <int> overLappingIds;
    for (auto g : groupedFrequencies[0])
        overLappingIds.push_back(g.cweID);

    for (auto group : groupedFrequencies)
    {
        vector <int> vec;
        for (auto g : group)
            vec.push_back(g.cweID);
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
        ofs << "\"" << id << '-' << dict[id] << "\"";
        for (auto v : groupedFrequencies)
        {
            ofs << ',' << frequencyOf(id, v);
        }
        ofs << '\n';
    }
    ofs.close();

    return 0;
}