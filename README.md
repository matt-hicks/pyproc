A learning exercise for python. Would probably do some things differently now such as not use the 'mode' design for functions and implement the print status messages as optional.
-----------
PyProc.py, a JSON controlled data summariser in python

Description:
Process a data file and write metadata information to a data summary file.

Usage (in windows):
>python PyProc.py {Parameter file}

Edit the parameter file to reflect the correct location for the input file (infile)
and output file (metafile).

The parameter file should contain a single JSON object of the form:

{‘infile’:’C:/data/data.csv’, 
 ‘metafile’:’C:/data/metadata.json’, 
 ‘format’:’tabular’, 
 ‘hasheader’:0, 
 ‘separator’:’,’ }

Optional parameters:
format - "JSON" or "tabular"
hasheader - 0 or 1
separator - Any punctuation mark, "tab" ,"	", "\t" or "space", " ".

Only tab, space and comma have been extensively tested.

Recognised file extensions: .json .csv and .txt
