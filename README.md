# CVE_DataMining_Research
Programs and Data used in CVE Data Mining Research (University of Virginia)

# Version

`completeTable.cpp` now outputs a CSV file that contain every entry with the following attributes:

- CVE_ID
- Published_Time
- Lastest_Modification_Time
- CAPEC_IDs
- CWE_IDs
- CPE_IDs
- Risk_Severity

# TODO

To answer the following research questions:

1. Overall what type of bugs are predominant?
2. If you divide the time period of reporting bugs in 4 bins, whether the bug trends change over time?
3. What are some bugs that are consistently present over time, but might not be dominant?


# Build

Run `cmake .` and `make` in the current directory. The executable file will be named "Stats".

So far, the compilation and execution have been tested on Fedora 23 and Ubuntu 14.04 (subsystem of Windows 10).
It will not run on Windows without modification, because the directories are coded in Unix convention.  

You need cmake of at least version 2.6 to deploy the project. 

# License 

No license is appropriate for current progress. The research is still ongoing. Do not distribute any code or data from this repository.