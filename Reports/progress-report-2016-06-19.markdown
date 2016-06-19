# Weakness over time

## RQ1: Overall what type of weaknesses are predominant?

### Results

The following CWE IDs top the list of all weaknesses overall:

> 119, 79, 264, 89, 20, 399, 200, 310, 94, 22

See `allTimeWeaknesses.csv`

### Methods

Extract CWE-ID, pushlished_time from `completeTable.csv`
Count the times of appearance of each CWE-ID

## RQ2: If you divide the time period of reporting weaknesses in 4 bins, whether the weaknesses trends change over time?

### Results

There are four bins: 1996 - 2001, 2002 - 2006, 2007 - 2011, 2012 - 2016

The most frequent ids for each bin is listed in the following table:

1996 - 2001 | 2002 -2006 | 2007 -2011 | 2012 -2016
--- | --- | -- | --
119 |119  |119 |119
20  |94   |79  |79
264 |79   |264 |264
16  |89   |20  |20
94  |264  |310 |310
200 |20   |200 |200
310 |399  |399 |399
59  |200  |89  |89
255 |22   |352 |352
287 |189  |22  |22

See `4_Bin_Weaknesses.csv`

### Methods

Extract CWE-ID, pushlished_time from `completeTable.csv`
Sort the list by time, divide the list into four sub-list according to the bins
Count the times of appearance of each CWE-ID in each list

## RQ3: What are some weaknesses that are consistently present over time, but might not be dominant?

### Results

Surprisingly there are only three IDs that appear in all time periods:

Frequencies in | 1996 - 2001 | 2002 -2006 | 2007 -2011 | 2012 -2016
--- | --- | --- | --- | ---
119 | 15 | 334 | 2757 | 3487
264 | 10 | 151 | 1735 | 2581
399 | 1 | 121 | 1266 | 1260

See `overtimeconsistent.csv`

### Methods

Use the four lists from RQ2, find the intersection (in terms of id) of all lists, and the remains are the CWEs that appear in all periods