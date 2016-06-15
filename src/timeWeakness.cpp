#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>
#include <string>


using namespace std;

struct WeaknessWithTime
{
    int year = 1999;
    int cweID = 0;

    WeaknessWithTime(int _year, int _cweID)
    {
        year = _year;
        cweID = _cweID;
    }
};

bool comByTime (WeaknessWithTime that) { year  < that.year;  }
bool comByID   (WeaknessWithTime that) { cweID < that.cweID; }

int parseYear(string str)
{
    int retVal = stoi(str);
    return retVal;
}

int parseID(string str)
{
    int start = 4;
    int q = str.find(" :");
    string s = str.substr(start, (q - 4));
    return stoi(s);
}


int main()
{
    ifstream ifs("./statistics/completeTable.csv");
    if (!ifs.is_open()) return -1;

    vector< WeaknessWithTime > weaknesses;

    string str;
    getline(ifs, str); // remove the first line (header)
    while (getline(ifs, str))
    {
        int commas[] = new int[6];
        int id = 0;
        for (int i = 0; i < 6; ++i)
        {
            commas[i] = str.find(",", id + 1);
            id = commas[i];
        }
        
        int year  = parseYear(str.substr(commas[0], 4));
        int cweID = parseID(str.substr(commas[3], commas[4]));
        WeaknessWithTime element (year, cweID);
        weaknesses.push_back(element);
    }

    std::sort(weaknesses.begin(), weaknesses.end(), comByTime);

    `



    ifs.close();

    return 0;
}