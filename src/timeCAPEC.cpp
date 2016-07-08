#include <set>
#include <string>
#include <cstdio>
#include <map>
#include "rapidjson/document.h"

using namespace rapidjson;
using namespace std;


Item* JsonHelper::parse(FILE* file)
{
    char readBuffer[65536];
    FileReadStream is(file, readBuffer, sizeof(readBuffer));
    
    Document d;
    d.ParseStream(is);
    
    Value& info  = d["Information"];
    Value& CWE   = info["CWE"];
    Value& CAPEC = info["CAPEC"];
    Value& CPE   = info["CPE"];
    Value& Risk  = d["Risk"];

    Item* item = new Item;
    getCWE(item->CWE, CWE);
    getCAPEC(item->CAPEC, CAPEC);
    getRisk(item->Risk, Risk);
    getCPE(item->CPE, CPE);
    fclose (file);
    return item;
}


int main()
{

}