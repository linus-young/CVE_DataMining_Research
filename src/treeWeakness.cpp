#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>
#include <string>

using namespace std;

class CWE
{
public:
    int id;
    string name;
    int[] children;
    int[] parents;
}

map<int, CWE> loadCWETree()
{
    ifstream ifs ("/rawdata/cwe/filelist.txt");
    map<int, CWE> CWEpointers;
    string line;
    char readBuffer[65536];
    while (getline(ifs, line))
    {
        FileReadStream is(line, readBuffer, sizeof(readBuffer));
        Document d;
        d.ParseStream(is);
        CWE cwe = new CWE()
        cwe.id = d["id"].GetInt();
        cwe.name = d["name"].GetString();
        Value &parentList = d["parents"] 
        for (SizeType i = 0; i < parentList.Size(); ++i)
            cwe.parents.insert(parentList[i]);
        Value &childrenList = d["children"] 
        for (SizeType i = 0; i < childrenList.Size(); ++i)
            cwe.children.insert(childrenList[i]);
    }

    
}

int main()
{




    return 0;
}