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

map<int, CWE> loadCWETree()
{
    ifstream ifs ("rawdata/cwe/filelist.txt");
    map<int, CWE> CWEpointers;
    string line;
    char readBuffer[65536];
    while (getline(ifs, line))
    {
        cout << line << endl;
        line = "rawdata/" + line;
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
        int number =    stoi(line.substr(0, line.find('-')));
        int frequency = stoi(line.substr(line.find(',') + 1));
        frequencies[number] = frequency;
    }
    return frequencies;
}

set< int > allAffected(int id, map<int, CWE>& dict) 
{
    set < int > s;
    s.insert(id);
    for (auto p : dict[id].parents) 
    {
        set<int> sp = allAffected(p, dict);
        for (auto i : sp) s.insert(i);
    }
    return s;
}

int main()
{
    auto cwes = loadCWETree();
    for (auto &q : cwes) {
        cout << q.first << " " << q.second.name << endl;
    }
    auto freq = loadFrequencies();
    for (auto &p : freq) 
    {
        set<int> s = allAffected(p.first, cwes);
        for (auto i : s) 
        {
            if (freq.find(i) == freq.end()) freq[i] = 0;
            freq[i] += p.second;
        }
    }
    ofstream ofs;
    ofs.open("statistics/tree_fiedCWE.csv");
    ofs << "id, name, frequency\n";
    for (auto &f : freq)
    {
        ofs << f.first << "," << cwes[f.first].name << "," << f.second << "\n";
    }
    return 0;
}