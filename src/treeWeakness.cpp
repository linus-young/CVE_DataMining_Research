#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>
#include <set>
#include <map>
#include <string>
#include "JsonHelper.h"
#include "rapidjson/filereadstream.h"
#include "rapidjson/document.h"

using namespace rapidjson;

using namespace std;

class CWE
{
public:
    int id;
    string name;
    vector<int> children;
    vector<int> parents;
    int frequency = 0;
};

void removeDuplicates(vector<int> &vec)
{
    std::vector<int>::iterator it;
    std::sort(vec.begin(), vec.end());
    it = std::unique (vec.begin(), vec.end());
    vec.resize(it - vec.begin());
}

map<int, CWE> loadCWETree()
{
    ifstream ifs ("rawdata/cwe/filelist.txt");
    map<int, CWE> CWEpointers;
    string line;
    char readBuffer[65536];
    while (getline(ifs, line))
    {
        line = "rawdata/cwe/" + line;
        FILE* file = fopen(line.c_str(), "r");
        FileReadStream is(file, readBuffer, sizeof(readBuffer));
        Document d;
        d.ParseStream(is);
        CWE cwe;
        cwe.id = d["id"].GetInt();
        cwe.name = d["name"].GetString();
        Value &parentList = d["parents"];
        for (SizeType i = 0; i < parentList.Size(); ++i)
            cwe.parents.push_back(parentList[i].GetInt());
        Value &childrenList = d["children"];
        for (SizeType i = 0; i < childrenList.Size(); ++i)
            cwe.children.push_back(childrenList[i].GetInt());
        removeDuplicates(cwe.parents);
        removeDuplicates(cwe.children);
        CWEpointers[cwe.id] = cwe;
        fclose(file);
    }
    return CWEpointers;
}

map<int, int> loadFrequencies()
{
    ifstream ifs ("statistics/allTimeWeaknesses.csv");
    map<int, int> frequencies;
    string line;
    getline(ifs, line);
    while (getline(ifs, line))
    {
        if (line.length() < 1) break;
        int number    = stoi(line.substr(0, line.find('-')));
        int frequency = stoi(line.substr(line.find(',') + 1));
        frequencies[number] = frequency;
    }
    return frequencies;
}

vector< int > allAffected(int id, map<int, CWE>& dict)
{
    vector < int > s;
    s.push_back(id);
    for (auto p : dict[id].parents)
    {
        vector<int> sp = allAffected(p, dict);
        for (auto i : sp) s.push_back(i);
    }
    removeDuplicates(s);
    return s;
}


int main()
{
    auto cwes = loadCWETree();
    auto freq = loadFrequencies();
    map<int, int> treeiedfreq;

    for (auto &p : freq)
    {
        auto s = allAffected(p.first, cwes);
        for (auto i : s)
        {
            if (treeiedfreq.find(i) == treeiedfreq.end()) treeiedfreq[i] = 0;
            treeiedfreq[i] += p.second;
        }
    }

    for (auto &v : treeiedfreq)
    {
        // auto &id = 
    }


    return 0;
}

