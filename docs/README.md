# PSAttck

## Introduction

`PSAttck` is a PowerShell Module to interact with the MITRE ATT&CK Framework.  This module extracts details about MITRE ATT&CK Tactics, Techniques, Actors/Groups, Tools, Malware, and Mitigations provided by MITRE.

Currently `PSAttck` supports the Enterprise MITRE ATT&CK Framework
with future plans to support additional frameworks.

By default, `PSAttck` downloads data about the Mitre ATT&CK framework from
an external source.  Additionally, additional externally generated data sets are downloaded as well.

You can set an alternate path to retrieve these data sets from by using 
the `Set-PSAttckConfiguration` function.

## Compatibility

PSAttck is compatible with Windows PowerShell 5 and PowerShell Core.

PSAttck utilizes PowerShell Classes to generate and create standard objects
across all ATT&CK data categories.


## Features

* Retrieve all Tactics, Techniques, Actors, Malware, Tools, and Mitigations from the MITRE ATT&CK Enterprise framework independently 
* Every data point has exposed properties that allow the user to retrieve additional data based on relationships:
* All techniques (if applicable) now have collected data from third-party resources that are accessible via properties on a technique.  These properties and values are:
	* CommandList = A list of commands from multiple open-source tools and repositories that contain potential commands used by a technique
	* Commands = A list of property objects that contain the `Name`, `Source, and `Command` dataset
	* Queries = A list of potential queries for different products to identify threats within your environment by technique
	* Datasets = A list of the datasets as it relates to a technique
	* PossibleDetections =  A list of potential detections for different products (e.g. NSM rules) as it relates to a technique
	* For more detailed information about these features, please view the following  [Generated Datasets](generateattcks/README.md)
* Each Actor object (if available) enables you to access the following properties on the object or access the entire dataset using the `ExternalDataset` property:
    * country
    * operations
    * attribution_links
    * known_tools
    * targets
    * additional_comments
    * external_description
* Each Tools object (if available) enables you to access the following properties on the object or access the entire dataset using the `ExternalDataset` property:
    * additional_names
    * attribution_links
    * additional_comments
    * family
* You can update/sync the external datasets by calling the `update()` method on an `Attck` object.  By default it will check for updates every 30 days.
* You can specify a local file path for the MITRE ATT&CK Enterprise Framework json, Generated Dataset, and/or a config.yml file.
* You can retrieve, if available, a image_logo of an actor or alternatively a ascii_logo will be generated.
* You can also search the external dataset for external commands that are similar using the `SearchCommands` method.

## Feedback

Please submit any feedback, including defects and enhancement requests at: 

[Issues](https://github.com/swimlane/PSAttck/issues)

## Credits

This is a list of people and/or groups who have directly or indirectly
helped by offering significant suggestions & code without which `PSAttck`
would be a lesser product. In no particular order:

Name: Mathias Jessen
Twitter: [@IISResetMe](https://twitter.com/IISResetMe)
Blog: [https://blog.iisreset.me/](https://blog.iisreset.me/)
    
PSAttck is a Swimlane open-source project; we believe in giving back to the open-source community by sharing some of the projects we build for our application. Swimlane is an automated cyber security operations and incident response platform that enables cyber security teams to leverage threat intelligence, speed up incident response and automate security operations.