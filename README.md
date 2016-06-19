# CVE_DataMining_Research
Programs and Data used in CVE Data Mining Research (University of Virginia)

# Versions

## Lastest Progress [2016-06-19]:

 - Dominant CWE over all time (1996 - 2016)
 - Dominant CWE over each period of a 4 bins division
 - CWE that has persistently appear over the 4 bins
 - results see:
    - `allTimeWeaknesses.csv`
    - `4_bin_Weaknesses.csv`
    - `overtimeconsistent.csv`
 - The codes responsible for this production include :
    - `timeWeakness.cpp`
    - `JsonHelper.cpp`
    - `RapidJson library`
    - The above files produce the executable: `Time`

## Old Versions:

`completeTable.cpp` now outputs a CSV file that contain every entry with the following attributes:

- CVE_ID
- Published_Time
- Lastest_Modification_Time
- CAPEC_IDs
- CWE_IDs
- CPE_IDs
- Risk_Severity

# TODO



# Build

Run `cmake .` and `make` in the current directory. The executable file will be named "Stats".

So far, the compilation and execution have been tested on Fedora 23 and Ubuntu 14.04 (subsystem of Windows 10).
It will not run on Windows without modification, because the directories are coded in Unix convention.  

You need cmake of at least version 2.6 to deploy the project. 

# License 

No license is appropriate for current progress. The research is still ongoing. Do not distribute any code or data from this repository.