burp2xml
========

Tool to convert a burp session file to xml.


This is a fork of the repo found at
https://github.com/SecurityInnovation/burp2xml.git

Changes from SecuityInnovation/burp2xml
---------------------------------------

* Added setup.py
* Use OptionParser to get args
* Added option -n to keep non-printable characters
* Added option -v for verbose output
* Avoid failure on bad dates
* Avoid failure on reporting use of stdout

jnw@cise.ufl.edu
