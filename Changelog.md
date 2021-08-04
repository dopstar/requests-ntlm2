#### [6.4.2](https://github.com/dopstar/requests-ntlm2/releases/tag/6.4.2) - 04 Aug 2021
 - fix regression issue introduced in https://github.com/dopstar/requests-ntlm2/pull/21
 - include `workstation` name (ie hostname) in the NTLM dance

#### [6.4.1](https://github.com/dopstar/requests-ntlm2/releases/tag/6.4.1) - 02 Aug 2021
 - fix python2 max-int bug introduced by version 6.4.0

#### [6.4.0](https://github.com/dopstar/requests-ntlm2/releases/tag/6.4.0) - 31 Jul 2021
 - added ability to switch from HTTP/1.0 to HTTP/1.1 when tunnelling to the proxy server (ie HTTP CONNECT)
 - added ability to send user-agent header to the proxy server during proxy tunnel creation 
 - log NTLM challenge negotiate flags
