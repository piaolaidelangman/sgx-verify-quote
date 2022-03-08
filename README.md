This is a project to verify SGX Quote refers to [intel/SGXDataCenterAttestationPrimitives](https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/5cca11f9ece7be2a55b2aec10deb4b1c016fde3a).
================================================

## Linux
Supported operating systems:
* Ubuntu* 18.04 LTS Desktop 64bits
* Ubuntu* 18.04 LTS Server 64bits
* Ubuntu* 20.04 LTS Server 64bits
* Red Hat Enterprise Linux Server release 8.2 64bits
* CentOS 8.2 64bits

Requirements:
* make
* gcc
* g++
* bash shell

Prerequisite:
* Intel(R) SGX DCAP Driver
* Intel(R) SGX SDK
* Intel(R) SGX DCAP Packages
* Intel(R) SGX DCAP PCCS (Provisioning Certificate Caching Service)

*Please refer to SGX DCAP Linux installation guide "https://download.01.org/intel-sgx/sgx-dcap/#version#/linux/docs/Intel_SGX_DCAP_Linux_SW_Installation_Guide.pdf" to install above dependencies*<br/>
*Note that you need to change **\#version\#** to actual version number in URL, such as 1.4.*

Build and run QuoteVerificationSample to verify a given quote
```
   Release build:
   $ make
   Or Debug build:
   $ make SGX_DEBUG=1
   $ ./app -quote </path/to/quote.dat [default=./App/quote.dat]>
```


## Windows
Supported operating systems:
   * Windows* Server 2016 (Long-Term Servicing Channel)
   * Windows* Server 2019 (Long-Term Servicing Channel)

Requirements:
* Microsoft Visual Studio 2019 or newer.

Prerequisite:
* Intel(R) SGX DCAP Driver
* Intel(R) SGX SDK
* Intel(R) SGX DCAP Packages
* Intel(R) SGX DCAP PCCS (Provisioning Certificate Caching Service)


*Please refer to [SGX DCAP Windows installation guide](https://software.intel.com/en-us/sgx/sdk) to install above dependencies*<br/>
*Note that you need to sign in IDZ first, then download & extract product "Intel(R) Software Guard Extensions Data Center Attestation Primitives"*

Build and run QuoteVerificationSample to verify a given quote
```
   a. Open VS solution QuoteVerificationSample.sln, butil with Debug/Release | x64 configuration
      Note that Release mode need to sign ISV enclave with your own key
   b. Run App.exe
      > App.exe -quote </path/to/quote.dat [default=App\quote.dat]>
```
