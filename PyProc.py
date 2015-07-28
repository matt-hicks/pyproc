#!/usr/bin/env python

# PyProc, a JSON controlled data summariser
# v1.0
# Usage: PyProc.py {Parameter File in JSON format}

import csv
import io
import json
import operator
import os.path
import re
import sys

# Some variables which can be altered to adjust program behaviour:

# The regular expression used to decide if a field value is a number.
# Explanation:
# (\+|-)? match 0 or 1 +- signs
# ([0-9]+\.?[0-9]* match 1 or more digits followed by 0 or 1 decimal points followed by 0 or more digits
# | OR
# \.[0-9]+) match a decimal point followed by 1 or more digits
# ([eE](\+|-)?[0-9]+)? match e or E followed by 0 or 1 +- signs followed by 1 or more digits, this whole sequence occuring 0 or 1 times
# $ this must be the end of the string
number_regex = re.compile(r'(\+|-)?([0-9]+\.?[0-9]*|\.[0-9]+)([eE](\+|-)?[0-9]+)?$')

# The expected file extension for JSON formatted data files.
json_format = 'JSON'

# Tabular format as used by the parameter and output files.
generic_tabular_format = 'tabular'

# A dictionary which gives allowable tabular file extensions and the field separator whch will be assigned to them if necessary.
tabular_exts_and_seps = {'CSV': ',' , 'TXT': '\t'}

# A dictionary specifying how tabs and spaces should appear externally in messages to users and internally to the code.
int_ext_sep_chrs = {'tab': '\t', 'space':' '}

# Some tuples holding information about the program parameters.
# Explanation: internal name, external name, optionality in the parameter file.
f_info = 'format', 'File Format', 'optional'
df_info = 'infile', 'Data File', 'mandatory'
h_info = 'hasheader', 'Header Row', 'optional'
mf_info = 'metafile', 'Metadata Output File', 'mandatory'
pf_info = 'pfile', 'Parameter File', None
s_info = 'separator', 'Separator Character', 'optional'

# The names of the fields to include in the output report.
out_format = 'format'
out_fields = 'fields'
out_hasheader = 'header'
out_infile = 'infile'
out_missing_values = 'num_missing_values'
out_numfields = 'numfields'
out_numrows = 'numrows'
out_separator = 'separator'

# Some text strings, for information or error handling.
cfi_info_str = "{0} \"{1}\" detected by inspecting {2}."
csv_info_str = "{0} found in {1} by python's csv module."
fa_info_str = "{0} classed as {1}."
fae_error_str = "ERROR: Could not access {0}. Please check file exists with correct name and/or info in {1} is correct. Exiting."
fsa_info_str = "{0} assigned to default value: \"{1}\" for {2} file extension."
fer_error_str = "ERROR: Please supply a {0} with a name that includes a file extension. Exiting."
fer_info_str = "{0} extension detected from file extension of {1}."
hh0_info_str = "No {0} found in {1}. Proceeding by using column headings var1, var2 etc.\nIf there really is a {0} please specify {2}:1 in the {3}."
hh1_info_str = "{0} found in {1} by comparing the first two rows."
hpv_error_str = "ERROR: {0}: \"{1}\" read from {2}. Accepted values for {0} are 0 and 1. Please edit {2}. Exiting."
pfv_error_str = "ERROR: {0} not specified in {1}. Please edit the {1} to supply it. Exiting."
pfv_info_str1 = "{0}: \"{1}\" successfully identified from {2}."
pfv_info_str2 = "{0} not specified in {1}. Attempting to guess value."
pmr_info_str = "\nMetadata collection complete. Results below are also written to {0}, {1}\n"
sc_error_str = "Usage: {0} {1}"
sfv_error_str = "ERROR: Detected {0}: {1}. Supported {0}s are {2} Please adjust file extension of {3} and/or edit {4}.\nFile extensions recognised as {5} are {6}. Exiting."

# Initializing some variables and collections to use later when processing the lines from the file.
numrows = 0
num_missing = 0
line_fields = set()
total_fields = set()
field_metadata = []

#==================================
# An alphabetical list of functions

def condense_uniquevals():
	"""
	Returning to the nested dictionaries to condense the sets of distinct values for string type keys down to a number,
	i.e. take the cardinality of the set.
	"""
	for md_dict in field_metadata:
		for md_key in md_dict:
			if md_key == 'uniquevals':
				md_dict[md_key] = len(md_dict[md_key])


def csv_format_investigator(mode):
	"""
	Accepts one argument, mode (sep|head).
	'sep' mode: Reads the data file and calls csv.Sniffer().sniff() to identify the separator character which it returns if found.
	'head' mode: Reads the data file and calls csv.Sniffer().has_header() to determine if a header row is present. Returns 1 for present, 0 for absent.
	"""
	try:
		with open(infile, 'rU') as source_file:
			sniffer = csv.Sniffer()
			if mode == 'sep':
				dialect = sniffer.sniff(source_file.readline().rstrip())
				if dialect:
					# Replace tab and space characters with words for reporting.
					print cfi_info_str.format(s_info[1], sep_chr_swapper(dialect.delimiter, 'external'), df_info[1])
				return dialect.delimiter
			elif mode == 'head':
				if sniffer.has_header(source_file.read()):
					hasheader = 1
					print csv_info_str.format(h_info[1], df_info[1])
				else:
					hasheader = 0
					print hh0_info_str.format(h_info[1], df_info[1], h_info[0], pf_info[1])
				return hasheader
	except EnvironmentError:
		file_access_error(df_info[1])
	

def field_separator_assigner():
	"""
	Return a value for the field separator from the tabular_exts_and_seps dictionary defined at the beginning of the program.
	"""
	file_extension = file_extension_reader()
	# Replace tab and space characters with words for reporting.
	print fsa_info_str.format(s_info[1], sep_chr_swapper(tabular_exts_and_seps[file_extension], 'external'), file_extension)
	return tabular_exts_and_seps[file_extension]


def file_access_error(file_name):
	"""
	Prints an error message when a file cannot be accessed and exits.
	"""
	print fae_error_str.format(file_name, pf_info[1])
	raise SystemExit


def file_extension_reader():
	"""
	Reads the file extension and converts it to a single upper case word which can be returned and compared with expected file formats.
	Raises a failure if no file extension is found.
	"""
	parsed_extension = os.path.splitext(infile)[1].lstrip('.').upper()
	if (parsed_extension is None) or (parsed_extension == ''):
		print fer_error_str.format(df_info[1])
		raise SystemExit
	else:
		print fer_info_str.format(parsed_extension, df_info[1])
	return parsed_extension


def format_assigner():
	"""
	Returns format based on file extension.
	"""
	file_extension = file_extension_reader()
	# If the file extension is .csv or .txt, keep a distinction between the extension and the format (tabular).
	if file_extension in tabular_exts_and_seps.viewkeys():
		format = generic_tabular_format
	else:
		format = file_extension
	print fa_info_str.format(f_info[1], format)
	return format


def header_investigator(mode):
	"""
	Accepts one argument, mode (guess|count).
	'guess' mode: Compares the first 2 rows of a tabular file and returns 1 for a formatting difference or 0 if the rows are identically formatted.
	'count' mode: Returns the number of columns in the file.
	"""
	try:
		with open(infile, 'rU') as source_file:
			source_data = csv.reader(source_file, delimiter = separator)
			# Use nested generator expressions to make a new tuple which is composed of tuples which contain all the fields in each row interpreted
			# as just 'string' or 'numeric' format.
			# Note that this sacrifices overall program efficiency for some concise syntax here because all the rows in the file are read
			# and processed into the tuple even though only the first 2 are of interest at this point. For tabular files of a few hundred lines,
			# this is acceptable, but it will scale poorly.
			tabular_row_formats = tuple(tuple(type_detector(str(element)) for element in row) for row in source_data)
			if mode == 'guess':
				if tabular_row_formats[0] == tabular_row_formats[1]:
					hasheader = 0
				else:
					hasheader = 1
					print hh1_info_str.format(h_info[1], df_info[1])
				return hasheader
			elif mode == 'count':
				return len(tabular_row_formats[0])
	except EnvironmentError:
		file_access_error(df_info[1])
		

def header_param_validator(hpv_input):
	"""
	Check the value of hasheader is 0 or 1 and return if so, raise an error if not.
	"""
	if hpv_input in (0, 1, '0', '1'):
		# Return as an int, string would cause problems in equality checks later.
		return int(hpv_input)
	else:
		print hpv_error_str.format(h_info[0], hpv_input, pf_info[1])
		raise SystemExit


def missing_value_detector(mvd_key, mvd_dict):
	"""
	Accepts two arguments, a key and a dictionary and tests whether the key's value is missing. Returns 0 for present, 1 for missing.
	"""
	if mvd_dict.get(mvd_key):
		return 0
	else:
		return 1


def new_field_metadata_initializer():
	"""
	Makes a dictionary to hold metadata about a field in the data file, populates it with relevant initial values, adds it to the list
	[field_metadata] and returns the list.
	"""
	# Make a temporary dictionary to hold metadata about the field with this name.
	new_field_dict = {'Name': field }

	new_field_dict['Type'] = type_detector(source_line[field])
			
	if new_field_dict['Type'] == 'numeric':
		# Add max and min keys into the temporary dictionary.
		# These can be set to the first value encountered and will be modified up or down as more lines are read.			
		new_field_dict['max'] = source_line[field]
		new_field_dict['min'] = source_line[field]

	elif new_field_dict['Type'] == 'string':
		# Add a 'uniquevals' key whose value is an empty set.
		new_field_dict['uniquevals'] = set()
			
	# Copy the temporary dictionary to the list field_metadata as a list element.
	field_metadata.append(new_field_dict)
	return field_metadata


def numeric_metadata_collector(operator):
	"""
	Updates numeric metadata dictionary fields, takes the argument operator to specify > or < comparison. Returns an updated value for md_dict[md_key].
	"""
	if operator(md_dict[md_key], source_line[md_dict['Name']] ):
		md_dict[md_key] = source_line[md_dict['Name']]
	return md_dict[md_key]
	

def output_dict_generator():
	"""
	Brings together information to return a new dictionary.
	"""
	# It would be nice to return a platform specific name for infile using os.path.normpath(), but the escape characters show up when backslashes
	# are printed in a dictionary and no way to hide them was found (e.g. c:\\somefolder\\infile.csv).
	output_dict = {out_infile: infile, out_format: format, out_fields: field_metadata, out_numrows: numrows, out_numfields: len(field_metadata)}
	if format == generic_tabular_format:
		# Replace tab and space characters with words for reporting.
		output_dict.update({out_hasheader: hasheader, out_separator: sep_chr_swapper(separator, 'external')})
	# Only report the number of missing values if there actually were any.
	if num_missing > 0:
		output_dict[out_missing_values] = num_missing
	return output_dict


def	param_file_opener():
	"""
	Loads the parameter file , rebuilds the contents to replace backslashes with forward slashes in the filepaths and returns its contents as a
	dictionary, {params}. Calls file_access_error() if there is a problem.
	"""
	# A function specific regex to search for infile and metafile.
	pfo_regex = re.compile(re.escape(df_info[0]) + r'|' + re.escape(mf_info[0]))

	try:
		with open(pfile, 'rU') as param_file:
			for line in param_file:
				# Make the line string into a list.
				line_list = line.split(',')
				rebuilt_line = ""
				for element in line_list:
					# Remove the JSON specific formatting from the strings in the list.
					element = element.strip('{},')
					# If the string corresponds to a filepath, replace windows style backslashes with forward slashes.
					if pfo_regex.search(element):
						element = element.replace('\\','/')
					# Concatenate the processed strings together
					rebuilt_line = rebuilt_line + element + ','
				# Format the completed string back into valid JSON.
				rebuilt_line = '{' + rebuilt_line.rstrip(',') + '}'
				# Now the string with corrected filenames can be passed to json.loads()
		
				# 'strict = False' will allow whitespace characters like literal tabs to be read as the separator character,
				# even though technically that means the JSON document in the param file is invalid JSON.
				# .encode('string-escape') allows json.loads() to process a JSON object with backslashes in it (windows filepaths).
				# It was decided not to go with the string escape option because this would prevent characters like \t from being
				# parsed. The rebuilding code above was used instead.
				#params = json.loads(line.encode('string-escape'), strict = False)
				params = json.loads(rebuilt_line, strict = False)

	except EnvironmentError:
		file_access_error(pf_info[1])
	return params


def param_file_validator(param_name, verbose_param_name, mode):
	"""
	Allows variables to be set from information in the dictionary {params}. Takes param_name (the name of the variable being set),
	a version of that name in english, and the mode out of mandatory|optional. If the information is mandatory, raises a failure
	if it does not exist in {params}. If a key called param_name is found in the dictionary, the value of that key is returned,
	after some processing/cleanup operations.
	"""
	if param_name in params:
		
		if param_name == f_info[0]:
			# Check value for format is allowed.
			validated_format = simple_format_validator(params[param_name])
			print pfv_info_str1.format(verbose_param_name, validated_format, pf_info[1])
			return validated_format
		
		elif param_name == h_info[0]:
			# Check value given for hasheader is allowed.
			validated_header_value = header_param_validator(params[param_name])
			print pfv_info_str1.format(verbose_param_name, validated_header_value, pf_info[1])
			return validated_header_value
		
		elif param_name in (df_info[0], mf_info[0]):
			# use os.path.normpath to report platform specific filepaths.
			print pfv_info_str1.format(verbose_param_name, os.path.normpath(params[param_name]), pf_info[1])
			return params[param_name]

		elif param_name == s_info[0]:
			# Perform word case validation on value for separator.
			validated_sep_value = sep_param_validator(params[param_name])
			# Internally, tab should read '\t', externally 'tab'
			# Externally, space should read ' ', externally 'space'
			# Use sep_chr_swapper() to accomplish this
			print pfv_info_str1.format(verbose_param_name, sep_chr_swapper(validated_sep_value, 'external'), pf_info[1])
			# Return a string type to be extra sure not to pass some weird character to the csv.reader() later.
			return str(sep_chr_swapper(validated_sep_value, 'internal'))
			
	else:
		if mode == 'mandatory':
			print pfv_error_str.format(verbose_param_name, pf_info[1])
			raise SystemExit
		elif mode == 'optional':
			print pfv_info_str2.format(verbose_param_name, pf_info[1])
			return


def publish_metadata_report():
	"""
	Outputs the report to terminal and as a file.
	"""
	# Use os.path.normpath() to make the file name platform corrected (e.g c:\somefolder\sweetdeliciousmetadata.json).
	print pmr_info_str.format(mf_info[1], os.path.normpath(metafile))
	print json.dumps(output_dict, sort_keys = True)

	try:
		with open(metafile, 'w') as outfile:
			json.dump(output_dict, outfile, sort_keys = True, indent = 4)
	except EnvironmentError:
		file_access_error(mf_info[1])


def sep_chr_swapper(scs_text, mode):
	"""
	Makes some replacements as defined in {int_ext_sep_chrs}. Accepts string to operate on and mode (external|internal), which indicates in which direction the
	replacement should occur. Returns the edited string.
	"""
	for k, v in int_ext_sep_chrs.iteritems():
		if mode == 'internal':
			scs_text = scs_text.replace(k, v)
		elif mode == 'external':
			scs_text = scs_text.replace(v, k)
	return scs_text


def sep_param_validator(spv_input):
	"""
	Does some limited casing correction on possible values for separator read from the parameter file.
	"""
	for sk in int_ext_sep_chrs.viewkeys():
		if spv_input.lower() == sk:
			spv_input = sk
	return spv_input


def simple_format_validator(sfv_format):
	"""
	Accepts the format as an argument, cleans up the case for consistency and reporting purposes and then checks it is valid before returning it.
	If the format is not valid, raises a failure and exits.
	"""
	if sfv_format.upper() == json_format:
		sfv_format = json_format
	elif sfv_format.lower() == generic_tabular_format:
		sfv_format = generic_tabular_format

	if sfv_format in allowed_formats:
		return sfv_format
	else:
		print sfv_error_str.format(f_info[1], sfv_format, allowed_formats, df_info[1], pf_info[1], generic_tabular_format, tabular_exts_and_seps.keys())
		raise SystemExit


def startup_check():
	"""
	Checks that the program was invoked with an argument and fails the program if it was not.
	"""
	if len(sys.argv) < 2:
		print sc_error_str.format(sys.argv[0], pf_info[0])
		raise SystemExit


def type_detector(value):
	"""
	Takes the value of a field passed from a source data file and applies the regex in number_regex to classify it
	as numeric or string type.
	"""
	if number_regex.match(str(value)):
		type = 'numeric'
	else:
		type = 'string'	# As per the project spec, if a value cannot be recognised as a number, just call it a string.
	return type

# End of function list
#=====================

# Check program was invoked correctly
startup_check()

# Get identity of the parameter file from the argument supplied when the program was run.
pfile = sys.argv[1]

# For convenience, construct a tuple of all allowed formats
allowed_formats = json_format, generic_tabular_format

# Read the parameter file and convert the JSON object it contains into a python dictionary: {params}.
params = param_file_opener()

# Take the values inside {params} and, where they exist, use them to set variables. This step is not strictly necessary since the info could be
# referenced directly by params[variable_name], but will make for code that reads more naturally and consistently later, if there are missing values
# that need to be guessed.
metafile = param_file_validator(mf_info[0], mf_info[1], mf_info[2])
infile = param_file_validator(df_info[0], df_info[1], df_info[2])
format = param_file_validator(f_info[0], f_info[1], f_info[2])

# If format was not supplied in the parameter file, assign it from the file extension of the data file.
if format is None:
	format = format_assigner()
	
# Now that some value for format has been picked up, check it is valid:
format = simple_format_validator(format)

# If the format is tabular, try to read values for separator and header from parameter file.
if format == generic_tabular_format:


	separator = param_file_validator(s_info[0], s_info[1], s_info[2])
	# If separator was not in params, guess a value using csv.Sniffer() - see function docstring.
	if separator is None:
		separator = csv_format_investigator('sep')

	# If the csv.Sniffer() did not work, assign a default value based on file extension.
	if separator is None:
		separator = field_separator_assigner()
	

	hasheader = param_file_validator(h_info[0], h_info[1], h_info[2])
	# If header was not in params, determine the hasheader variable - see function docstring.
	if hasheader is None:
		hasheader = header_investigator('guess')

		# If the guess did not identify a header row, call csv.Sniffer() as a backup.
		if hasheader == 0:
			hasheader = csv_format_investigator('head')

	# If a header row was still not found, or the parameter file indicated it was absent, construct a virtual one,
	# where the column headings default to var1, var2, etc.
	if hasheader == 0:
		virtual_header = tuple(('var' + str(col_num)) for col_num in range(1, header_investigator('count') + 1))


# Open the data file to actually read it and collect metadata.
try:
	# Open using io.open with encoding='utf-8-sig' to work around a problem encountered with the Byte Order Mark \ufeff
	# The U option enables universal newlines support, which works around an issue opening csv files saved in windows excel.
	with io.open(infile, 'rU', encoding = 'utf-8-sig') as source_file:

		# csv.DictReader transforms the csv file into a object which can be read line by line to yield dictionaries.
		if format == generic_tabular_format:
			if hasheader == 0:
				# If no header is present the dictionary keys will come from the virtual header var1, var2 etc.
				source_data = csv.DictReader(source_file, delimiter = separator, fieldnames = virtual_header)
			elif hasheader == 1:
				# If a header is present, csv.DictReader will use the column headings as its dictionary keys.
				source_data = csv.DictReader(source_file, delimiter = separator)

		# The preceding step is unnecessary for JSON documents so just rename to keep things consistent.
		elif format == json_format:
			source_data = source_file

#=======================
# Start of the main loop

		# Now examine the data object line by line
		for source_line in source_data:

			# The json.loads function will turn a JSON object (one line from the file in this case) into a python dictionary.
			if format == json_format:
				source_line = json.loads(source_line)

			# After these pre-processing steps the loop is now processing one dictionary at a time, whether the source was JSON or tabular.

			# Increment the row counter each time a row is processed so this information can be included in the final metadata report.
			numrows += 1	
			
			# Investigate the values in this line to see if there are any missing (empty cells in other words). If so increment the
			# missing values counter.
			for slk in source_line.viewkeys():
				num_missing += missing_value_detector(slk, source_line)

			# Add all the keys from the dictionary to line_fields, the set of fields which exist in this line.
			line_fields.update(source_line.viewkeys())

			# Take the difference of the set of fields in this line with the set of all fields seen before, so any new fields can be identified.
			new_fields = line_fields.difference(total_fields)

			# Now that new fields have been identified, add any new fields into the set total_fields, which keeps track of all fields seen in all lines
			# read so far.
			total_fields.update(source_line.viewkeys())

			# Remove fields in this line from line_fields so it will be empty again when the next line is tested.
			line_fields.difference_update(source_line.viewkeys())

			# Although it is fine (and indeed obligatory) to pass strings to the regex in type_detector() for number detection, now it is important
			# to make the number values which have come through as strings into real ints or floats to stop bad things happening like doing a numerical
			# operation on a str with a float or another str.
			# Use a dictionary comprehension to skip over values that are already ints or floats and then turn numerical strings into ints and floats.
			source_line = {k: v if isinstance(v, int) else v if isinstance(v, float) else int(v) if v.isdigit()
			else float(v) if type_detector(v) == 'numeric' else v for k, v in source_line.iteritems()}
			
			# Deal with new fields: While the number of fields per line is not expected to vary in a tabular file, it could vary between JSON objects.
			# In the case of a tabular file, this still works for learning about all the fields when line #1 is processed.
			for field in new_fields:
				# If new fields were discovered in this line, investigate their value types.
				field_metadata = new_field_metadata_initializer()

			# Now that field_metadata is populated with a dictionary for every field discovered so far in the source lines,
			# collect the metadata of interest by comparing the values held in the meta dictionaries with the values in this line of the source data.
			for md_dict in field_metadata:

				# Check that the field the dictionary is concerned with actually exists in this line - if it is absent skip updating this dictionary.
				# This is not expected to happen in a csv file but could happen in a collection of JSON objects.
				if md_dict['Name'] in source_line:
			
					# Work with each metadata field in the nested dictionaries. The basic idea here is that md_dict[md_key] can be compared to
					# source_line[md_dict['Name'], because the values in md_dict['Name'] were taken from the names of the keys (fields) in source_line.
					# For example, if md_dict['Name'] is 'Price', comparing md_dict['min'] with source_line['Price'] will be comparing two Price values,
					# which is the desired result.
					for md_key in md_dict:

						# If a 'min' key holds a value greater than the value of that key in the source line, set it to the source value.
						if md_key == 'min':
		 					md_dict[md_key] = numeric_metadata_collector(operator.gt)
		 					 			
		 				# If a 'max' key holds a value less than the value of that key in the source line, set it to the source value.
		 				elif md_key == 'max':
		 					md_dict[md_key] = numeric_metadata_collector(operator.lt)
		 			
		 				# For 'uniquevals' keys, add whatever value is found in the source line to the set. There is no need to check
		 				# for duplicate values, the set collection type takes care of that.
		 				elif md_key == 'uniquevals':
		 					md_dict[md_key].add(source_line[md_dict['Name']])

# End of the main loop, once every line in the source file has been processed, all required metadata has been gathered.
# =====================================================================================================================

except EnvironmentError:
	file_access_error(df_info[1])

# Do some post-processing
condense_uniquevals()

# Bring all the the information gathered so far into one python dictionary, so that it can be exported as a JSON object.
output_dict = output_dict_generator()

# Finally, report the results
publish_metadata_report()