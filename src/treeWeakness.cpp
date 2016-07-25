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
    bool discovered = false;
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
    ifstream ifs ("statistics/CWEwithTime/allTime.csv");
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

int updateFrequency(int id, map<int, CWE> & cwes)
{
    if (cwes[id].discovered) return cwes[id].frequency;
    for (auto &c : cwes[id].children)
    {
        cwes[id].frequency += updateFrequency(c, cwes);
    }
    cwes[id].discovered = true;
    return cwes[id].frequency;
}


int main()
{
    auto cwes = loadCWETree();
    auto freq = loadFrequencies();

    for (auto &f : freq) cwes[f.first].frequency = f.second;
    updateFrequency(1, cwes);

    ofstream ofs;
    ofs.open("statistics/CWEwithTree.csv");
    for (auto &v : cwes)
    {
        auto &id = v.first;
        auto &freq = v.second.frequency;
        ofs << id << "," << freq << ",\"";
        for (auto &c : v.second.children)
            ofs << c << ",";
        ofs << "\"" << endl;
    }
    ofs.close();

    return 0;
}

