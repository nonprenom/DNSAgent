#!/usr/bin/bash

# tests can be done with a browser and entering various url.
# the browser and linux use local cache so sometimes no query is made, so no answer is received.
# dig don't use any local cache so it's safe to use for testing
dig www.google.com ANY
dig securingsam.com  ANY
dig drive.erwan.my.to  ANY
dig yahoo.com  ANY
