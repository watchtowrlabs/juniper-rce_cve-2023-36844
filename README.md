# CVE-2023-36844 , CVE-2023-36845 , CVE-2023-36846 , CVE-2023-36847

A Proof of Concept for chaining the CVEs [CVE-2023-36844, CVE-2023-36845, CVE-2023-36846, CVE-2023-36847] developed by @watchTowr to achieve Remote Code Execution in Juniper JunOS within SRX and EX Series products.

# Follow the [watchTowr](http://watchTowr.com) Labs Team for our Security Research

- https://labs.watchtowr.com/
- https://twitter.com/watchtowrcyber
- https://twitter.com/alizthehax0r

# Technical Analysis

watchTowr performed a deep dive into reproducing, chaining and exploiting these vulnerabilities which can be found at: https://labs.watchtowr.com/cve-2023-36844-and-friends-rce-in-juniper-firewalls/

# Summary

1. A pre-authentication upload vulnerability can be used to upload an arbitrary PHP file to a restricted directory with a randomised file name.
2. Using the same vulnerable function, we upload a PHP configuration file (.ini) which points to and loads the PHP file from step 1 using the `auto_prepend_file` directive.
3. As all environment variables can be set via HTTP requests, we overwrite the environment variable `PHPRC` to load the PHP configuration file from step 2 and trigger the execution of the PHP function declared in step 1.

# Usage

The PHP function can be specified using the flag `—payload`, however `php_uname()` is set by default.

`python watchtowr-vs-junos_juniper_2023-08-25.py --url http://localhost`

`python watchtowr-vs-junos_juniper_2023-08-25.py --url http://localhost --payload "get_current_user()"`

# Mitigations

Update to the latest version of JunOS, and/or apply the patches provided by Juniper. If these actions are not possible, please leverage the provided Juniper workaround.

https://supportportal.juniper.net/s/article/2023-08-Out-of-Cycle-Security-Bulletin-Junos-OS-SRX-Series-and-EX-Series-Multiple-vulnerabilities-in-J-Web-can-be-combined-to-allow-a-preAuth-Remote-Code-Execution?language=en_US
