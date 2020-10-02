Helix C99 Wrappers
========================================================

## Synopsys
Helix C99 API exposes core Helix protocol capabilities to runtime environments capable of
executing C language instructions, using C99 language standard.

This package is build targeting for following environment configuration:

	Architecture: x64
	CPU: AMD
	OS: CentOS 7
	Compiler: GCC 7.3.1
	Build Type: Release
	Runtime: N/A
	Thread Model: mt
	Library Type: static
	Language: C
	Standard: C99


### Licensing and Use of IP during evaluation
This package is intended for evaluation purposes of API and data model. 
As such, it has been compiled without using licensable Helix algorithms. 
For evaluation purposes, non-IP protected stand-in algorithms are utilized.

Please contact BlakFx for a private release of similar package utilizing IP-protected algorithms.


## Layout of the package
```
    ./
        bin/ -> Holds all necessary runtime dependencies, and example executable utilizing Helix library
        include/ -> Contains Helix header necessary for integration of Helix with other applications
        lib/ -> Contains helix binary dependencies necessary for link-time integration to Helix with other applications
```


### Integration Componenets
* Helix C99 API header is contained in file `include/helix_crypto.h`
* Helix C99 API binary is contained in file `lib/helix_c99.lib`

