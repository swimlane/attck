# Documentation

To see what functions are provided by PSAttck, execute the command:

```powershell
Get-Command -Module PSAttck 
```

## Functions

* [Function Documentation](public/functions.md)    
    * [Get-Attck](public/Get-Attck.md)    
    * [Get-AttckActor](public/Get-AttckActor.md)
    * [Get-AttckMalware](public/Get-AttckMalware.md)
    * [Get-AttckMitigation](public/Get-AttckMitigation.md)
    * [Get-AttckTactic](public/Get-AttckTactic.md)
    * [Get-AttckTechnique](public/Get-AttckTechnique.md)
    * [Get-AttckTool](public/Get-AttckTool.md)


## Classes

* [Class Documentation](class/classes.md)    
    * [PSAttck](class/PSAttck.md)    
    * [Enterprise](class/enterprise/Enterprise.md)    
    * [EnterpriseActor](class/enterprise/EnterpriseActor.md)  
    * [EnterpriseMalware](class/enterprise/EnterpriseMalware.md)  
    * [EnterpriseMitigation](class/enterprise/EnterpriseMitigation.md)  
    * [EnterpriseTactic](class/enterprise/EnterpriseTactic.md)  
    * [EnterpriseTechnique](class/enterprise/EnterpriseTechnique.md)  
    * [EnterpriseTool](class/enterprise/EnterpriseTool.md)  

## External Datasets

PSAttck also allows you to retrieve [external data sets](external-data/data.md) related to Techniques
For example, every Technique object has additional (non-standard) properties 
which allow you to access:

    - Commands
        - Source
        - Command
        - Name (if applicable)
    - CommandList
        - command from Commands['command']
    - RawDatasets
        - Raw dataset data
    - Queries
        - Product
        - Query
        - Name (if applicable)
    - RawDetections
        - Raw detection data source


## See Also
    
For more information, please visit https://swimlane.com 

Additionally, most of the functions have help associated with 
them e.g.:

```powershell
PS> Get-Help Get-Attck
```