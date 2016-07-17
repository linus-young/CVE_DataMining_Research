#include <fstream>
#include <string>
#include <vector>

class CSVWriter
{
private:
    ofstream ofs;
    string buffer = "";
public:
    CSVWriter(ofstream& ofs) : ofs(ofs) {}
    CSVWriter(string filename)
    {
        ofs.open(filename);
    }

    ~CSVWriter() 
    {
        ofs.close();
    }

    void writeCell()
}