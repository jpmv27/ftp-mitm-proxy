This python code is a work-around for the firmware issue present in some Bambu Labs 3D printers,
as described here: https://github.com/jneilliii/OctoPrint-BambuPrinter/issues/18

It is a MITM FTPS proxy/application gateway that applies a fix to the PASV response from the
3D printer to replace the 0.0.0.0 IP address with the server's (printer's) IP address.

The code was composed by ChatGPT after an extensive process of prompting and iterating. It seems
to work, based on light testing. In the end, I would have come out ahead if I had written it myself.

*** INCOMPLETE *** Limited to retrieving the remote directory from the printer
