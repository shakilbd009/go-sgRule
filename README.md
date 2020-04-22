# go-sgRule

this application would be able to:
    Read the csv data passed in as an argument using -source flag.
    show error messages if right path for csv file is not given.
    Find a security group based on the given ip, which is the first column of csv file.
    Add /32 if no cidr is given, skip, if an cidr range is given.
    Trip spaces where spaces are not allowed.
    Parse the inbound and outbound data, and be able send request concurrently to the right security group based on the given ip, which is The first column of csv file.
    Catch any error that occurs, and print it. However, execution flow continues.


