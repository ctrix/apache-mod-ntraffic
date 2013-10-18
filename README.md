Mod-Ntraffic
===================

mod_ntraffic is an Apache module to record traffic statistics for each Apache virtual host or a grand total for the whole server.

The module collects the hits, the inbound bytes and the outbound bytes.

The data are made available through HTTP GET requests to a configurable handler which can return data in XML, Json or Plain Text formats.

The data are also stored eventually on the file system for persistence or easier collection if necessary.


Installation
------------

To build mod_ntraffic you need apxs2.
This is usually shipped with the sources of your Apache server. If you are using a package manager, this utility is usually shipped
with the development files and headers.
If you are a Debian addict, for example, this utility is usually shipped with the package *apache2-threaded-dev* or *apache2-prefork-dev*
If you are using a RPM based distribution, the package is usually called *apache-devel* or *httpd-devel*.

To build the module simply run:

    make

To install the module simply run (as root):

    make install

Eventually Use sudo if needed.

Configuration
-------------

The distribution contains a file called *ntraffic.conf* which contains all the following **global** configuration directives.

```ruby

<IfModule mod_ntraffic.c>
    NTrafficEnabled             On
    NTrafficRefreshInterval     120

    NTrafficDataDir             /var/spool/apache2/mod_ntraffic/

    NTrafficExcludeIP           127.0.0.1/8
    NTrafficExcludeIP           10.1.1.0/24
    NTrafficExcludeIP           192.168.1.2

    <Location /ntraffic-status>
        SetHandler ntraffic-status

        RewriteEngine Off
        Order allow,deny
        Allow from 127.0.0.1
        Allow from 10.0.0.0/16
    </Location>
</IfModule>

```

- **NTrafficEnabled** (On/Off)

    Disables or enables Ntraffic globally

- **NTrafficRefreshInterval** (seconds)

    Ntraffic stores the statistics on files (inside NTrafficDataDir). This values specify
    the minimum interval between two updates.
    Please note that the file is updated only after a request (no request implies no update)

- **NTrafficDataDir**

    This is where the statistic files are stored. If not specified, no files will be used.

- **NTrafficExcludeIP** (IP or Network sub-net)

    Ntraffic counts all requests from all hosts. This directive, which can be used several times,
    indicates which hosts or networks should not be logged.


The location part installs the ntraffic-status handler for every virtual hosts, enabling access restrictions.


Access the data
---------------

The ntraffic-status handler is the main way to access the traffic statistics.

If you have, for example, a virtual host called www.test.it then accessing the following URL:

    http://www.test.it/ntraffic-status

from an IP inside an allowed network (see the Allow directive in the example above) will show you the virtual host statistics in XML (default format):

```XML
<document type="ntraffic/xml">
    <ntraffic-data>
        <vhost name="guendalinux.navynet.it" hits="74" sent="17734" recvd="15019" />
    </ntraffic-data>
</document>

```

There are four URL parameters that you may pass to alter the output:

- **globals** allows you to see the collected statistics of all the visited virtual hosts. If no statistics have been collected for a single virtual host, it will not be included in the list.

- **plain** turns the output from XML to plain TEXT, tab separated

- **json** turns the output to JSON

- **flush** clears the virtual host statistics (or every statistic if 'globals' is used) to zero after displaying them.


The **plain** and the **json** options should not be used together.

As an example, the following URL will:

    http://www.test.it/ntraffic-status?globals&json&flush

display all the statistics collected for every virtual host in json format and will clear them after displaying.



Development
------------

- Source hosted at [GitHub](https://github.com/ctrix/apache-mod-ntraffic)
- Report issues, questions, feature requests on [GitHub Issues](https://github.com/ctrix/apache-mod-ntraffic/issues)


Authors
-------

[Massimo Cetra](http://www.ctrix.it/)

* * *
